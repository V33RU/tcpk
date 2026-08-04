function Test-TcpkPacker {
<#
.SYNOPSIS
    A22. Packer / obfuscator detection -- and the inverse: source-recoverable
    (not-obfuscated) first-party assemblies.

.DESCRIPTION
    Four real signals (three original + DIE-style additions):

      1. PACKER SECTION NAME -- known packer/protector section names
         (UPX/Themida/VMProtect/ASPack/Enigma/MPRESS/...) read from PE section table.

      2. OBFUSCATOR -- .NET obfuscator attribute/marker strings (ConfuserEx,
         Dotfuscator, SmartAssembly, Eazfuscator, Babel, .NET Reactor, Agile.NET,
         Crypto Obfuscator) found in the assembly.

      3. DIE-STYLE ENTROPY -- sections with Shannon entropy > 7.0 bits/byte on files
         where no packer section name was found; consistent with packing or encryption.
         Also flags OEP (AddressOfEntryPoint) pointing into a non-code section
         (.data, .rsrc, .rdata, writable-but-not-code) which is a common packer
         artifact.

      4. LEGACY COMPILER -- files importing msvbvm60.dll (VB6) or the Delphi/BPL
         runtime (borlndmm.dll, rtlNNN.bpl) flagged as legacy builds: often lack
         modern mitigations and carry known vuln classes specific to those runtimes.

      5. NOT-OBFUSCATED -- first-party managed (.NET) assemblies with no packer
         and no obfuscator -> source is fully recoverable in a decompiler.
         Reported once as a summary.

.PARAMETER Path
    File or directory.

.PARAMETER Unpack
    Opt-in: when a UPX-packed binary is found and upx.exe is on PATH, auto-unpack a
    COPY (upx -d) to %TEMP% and report the path so the static checks can run on the
    real code. Only UPX is auto-reversible; commercial protectors (Themida/VMProtect)
    require a dynamic unpacker and are never touched.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Unpack
    )

    # ---- Byte-level Shannon entropy helper (DIE-style section entropy) ----
    function _PeByteEntropy([byte[]]$bytes) {
        if (-not $bytes -or $bytes.Length -eq 0) { return 0.0 }
        $freq = New-Object 'int[]' 256
        foreach ($b in $bytes) { $freq[$b]++ }
        $len = $bytes.Length; $h = 0.0
        foreach ($c in $freq) {
            if ($c -eq 0) { continue }
            $p = $c / $len; $h -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($h, 3)
    }

    # ---- Read minimal PE fields needed for entropy + OEP checks ----
    # Returns $null if the file is not a valid PE.
    function _ReadPeForDie([string]$filePath) {
        $fs = $null; $br = $null
        try {
            $fs = [IO.File]::OpenRead($filePath)
            $br = [IO.BinaryReader]::new($fs)
            if ($fs.Length -lt 0x80) { return $null }
            $fs.Position = 0; if ($br.ReadUInt16() -ne 0x5A4D) { return $null }
            $fs.Position = 0x3C; $peOff = [long]$br.ReadInt32()
            if ($peOff -le 0 -or ($peOff + 24) -gt $fs.Length) { return $null }
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { return $null }

            $br.ReadUInt16() | Out-Null                 # Machine
            $numSec     = $br.ReadUInt16()
            $br.ReadUInt32() | Out-Null                 # TimeDateStamp
            $br.ReadUInt32() | Out-Null; $br.ReadUInt32() | Out-Null  # Symbol table
            $optHdrSize = $br.ReadUInt16()
            $br.ReadUInt16() | Out-Null                 # Characteristics

            $optStart = $peOff + 24
            if (($optStart + 4) -gt $fs.Length) { return $null }
            $fs.Position = $optStart
            $magic = $br.ReadUInt16()
            $isPE32Plus = ($magic -eq 0x20B)
            $br.ReadByte() | Out-Null; $br.ReadByte() | Out-Null  # Linker version
            $br.ReadUInt32() | Out-Null; $br.ReadUInt32() | Out-Null; $br.ReadUInt32() | Out-Null
            $oepRva = $br.ReadUInt32()

            $sections = [System.Collections.Generic.List[hashtable]]::new()
            for ($i = 0; $i -lt $numSec; $i++) {
                $secOff = $peOff + 4 + 20 + $optHdrSize + ($i * 40)
                if (($secOff + 40) -gt $fs.Length) { break }
                $fs.Position = $secOff
                $nb    = $br.ReadBytes(8)
                $sname = ([Text.Encoding]::ASCII.GetString($nb)).Trim([char]0).Trim()
                $vsize = $br.ReadUInt32()
                $va    = $br.ReadUInt32()
                $rSize = $br.ReadUInt32()
                $rPtr  = $br.ReadUInt32()
                $br.ReadUInt32() | Out-Null; $br.ReadUInt32() | Out-Null; $br.ReadUInt32() | Out-Null
                $schar = $br.ReadUInt32()
                $isCode = ($schar -band 0x20) -ne 0
                $isExec = ($schar -band 0x20000000) -ne 0
                $isWrite = ($schar -band 0x80000000) -ne 0

                # Per-section entropy (sample up to 64KB)
                $entropy = 0.0
                if ($rPtr -gt 0 -and $rSize -gt 0 -and ([long]$rPtr + $rSize) -le $fs.Length) {
                    $saved = $fs.Position
                    $fs.Position = $rPtr
                    $sb = $br.ReadBytes([Math]::Min([int]$rSize, 65536))
                    $fs.Position = $saved
                    $entropy = _PeByteEntropy $sb
                }

                $sections.Add(@{
                    Name    = $sname; VA=$va; VSize=$vsize
                    RawPtr  = $rPtr; RawSize=$rSize
                    Entropy = $entropy; IsCode=$isCode
                    IsExec  = $isExec; IsWrite=$isWrite
                })
            }
            return [pscustomobject]@{ OepRva=$oepRva; Sections=$sections.ToArray() }
        } catch { return $null }
        finally {
            if ($br) { try { $br.Dispose() } catch {} }
            if ($fs) { try { $fs.Dispose() } catch {} }
        }
    }

    $upxExe = if ($Unpack) { (Get-Command upx -ErrorAction SilentlyContinue).Source } else { $null }

    # Packer / protector section-name signatures
    $packerSecs = @{
        'UPX0'='UPX'; 'UPX1'='UPX'; 'UPX2'='UPX'; '.UPX0'='UPX'
        '.themida'='Themida/WinLicense'; '.winlice'='Themida/WinLicense'
        '.vmp0'='VMProtect'; '.vmp1'='VMProtect'; '.vmp2'='VMProtect'
        '.aspack'='ASPack'; '.adata'='ASPack'
        '.petite'='Petite'; '.nsp0'='NsPack'; '.nsp1'='NsPack'
        'FSG!'='FSG'; 'MEW'='MEW'; '.MPRESS1'='MPRESS'; '.MPRESS2'='MPRESS'
        '.enigma1'='Enigma'; '.enigma2'='Enigma'; '.boom'='Boomerang'
        '.y0da'='yoda'; '.yP'='yoda'; 'pebundle'='PEBundle'; '.perplex'='Perplex'
        '.svkp'='SVKP'; '.taz'='PESpin'; '.packed'='Generic packer'
    }
    # .NET obfuscator markers
    $obfMarkers = @{
        'ConfusedByAttribute'='ConfuserEx'; 'ConfuserEx'='ConfuserEx'
        'DotfuscatorAttribute'='Dotfuscator'; 'DotfuscatedByAttribute'='Dotfuscator'
        'SmartAssembly.Attributes'='SmartAssembly'; 'PoweredByAttribute'='SmartAssembly'
        'EazfuscatorAttribute'='Eazfuscator.NET'; 'Eazfuscator.NET'='Eazfuscator.NET'
        'BabelObfuscatorAttribute'='Babel'; 'BabelAttribute'='Babel'
        'NETReactor'='.NET Reactor'; 'NetReactorSlightlyImproved'='.NET Reactor'
        'Crypto Obfuscator'='Crypto Obfuscator'; 'CryptoObfuscator'='Crypto Obfuscator'
        'ObfuscatedByGoliath'='Goliath.NET'; 'Agile.NET'='Agile.NET / CliSecure'
        'ZYXDNGuarder'='DNGuard'
    }

    $managedNotObf = New-Object 'System.Collections.Generic.List[string]'
    $managedTotal = 0

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        # 1) Packer section name check
        $packerFound = $false
        foreach ($sn in $info.SectionNames) {
            $key = $packerSecs.Keys | Where-Object { $sn -ieq $_ -or $sn -like "$_*" } | Select-Object -First 1
            if ($key) {
                $packerName = $packerSecs[$key]
                New-TcpkFinding -Module 'static' -RuleId 'packer.detected' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) is packed/protected ($packerName)" `
                    -File $pe.FullName -Evidence "section '$sn'" -Cwe @('CWE-656') `
                    -Description "A packer/protector section was found. Packing hides code from static analysis and is sometimes used to evade AV; confirm it is intentional (commercial protector) and unpack to audit the real code." `
                    -Fix 'If this is your own product, ensure the protector is a known commercial one and document it; otherwise treat as suspicious.'

                if ($Unpack -and $packerName -eq 'UPX') {
                    if (-not $upxExe) {
                        New-TcpkFinding -Module 'static' -RuleId 'packer.unpack-skipped' `
                            -Severity 'INFO' -Confidence 'Skipped' `
                            -Title "Cannot auto-unpack $($pe.Name): upx.exe not on PATH" `
                            -File $pe.FullName -Evidence 'install UPX and re-run with -Unpack' `
                            -Description 'UPX was detected but the upx tool is not available to reverse it.'
                    } else {
                        $dest = Join-Path $env:TEMP ('tcpk-unpacked-' + [guid]::NewGuid().ToString('N') + '-' + $pe.Name)
                        try {
                            Copy-Item -LiteralPath $pe.FullName -Destination $dest -Force
                            & $upxExe -d -q $dest 2>$null | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                New-TcpkFinding -Module 'static' -RuleId 'packer.unpacked' `
                                    -Severity 'INFO' -Confidence 'Confirmed' `
                                    -Title "Unpacked $($pe.Name) (UPX) for analysis" `
                                    -File $dest -Evidence 'upx -d succeeded' `
                                    -Description 'A UPX-unpacked copy was written. Re-run the static checks (secrets/strings/callsites/PE) against this path to audit the real code.'
                            } else {
                                New-TcpkFinding -Module 'static' -RuleId 'packer.unpack-failed' `
                                    -Severity 'INFO' -Confidence 'Skipped' `
                                    -Title "UPX unpack failed for $($pe.Name)" `
                                    -File $pe.FullName -Evidence "upx exit $LASTEXITCODE (may be a modified/secondary-packed UPX)"
                                Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
                            }
                        } catch { }
                    }
                }
                $packerFound = $true
                break
            }
        }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $managed = $text.Contains('BSJB')   # .NET metadata root signature

        # 2) Obfuscator markers
        $hitObf = $null; $hitMk = ''
        foreach ($mk in $obfMarkers.Keys) { if ($text.Contains($mk)) { $hitObf = $obfMarkers[$mk]; $hitMk = $mk; break } }
        if ($hitObf) {
            New-TcpkFinding -Module 'static' -RuleId 'obfuscation.present' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "$($pe.Name) is obfuscated ($hitObf)" `
                -File $pe.FullName -Evidence "marker: $hitMk" -Cwe @('CWE-656') `
                -Description 'Defensive signal -- code is obfuscated, raising the bar for reverse engineering. Note: obfuscation is not a security control; confirm secrets are not merely hidden.'
            continue
        }

        # 3) DIE-style section entropy and OEP checks
        # Only for native PEs where no packer name was already found (avoids double-reporting).
        if (-not $managed) {
            $dieInfo = _ReadPeForDie $pe.FullName
            if ($dieInfo) {
                # 3a) High-entropy section heuristic: entropy > 7.0 without a known packer name
                if (-not $packerFound) {
                    foreach ($sec in $dieInfo.Sections) {
                        if ($sec.Entropy -gt 7.0 -and $sec.RawSize -gt 512) {
                            New-TcpkFinding -Module 'static' -RuleId 'packer.entropy' `
                                -Severity 'MEDIUM' -Confidence 'Inferred' `
                                -Title "$($pe.Name) section '$($sec.Name)' has high entropy ($($sec.Entropy)) -- possible packing/encryption" `
                                -File $pe.FullName `
                                -Evidence "section='$($sec.Name)', entropy=$($sec.Entropy), raw_size=$($sec.RawSize)" `
                                -Cwe @('CWE-656') `
                                -Description ('Section entropy > 7.0 bits/byte is consistent with packed, ' +
                                    'encrypted, or compressed code. This is a DIE/PEiD-style heuristic -- ' +
                                    'it does not uniquely identify a packer but indicates that static ' +
                                    'analysis of this section will not recover readable code. Common causes: ' +
                                    'UPX/MPRESS without their default section names, Themida/VMProtect with ' +
                                    'custom section names, RC4/AES-encrypted payload, or a self-extracting ' +
                                    'archive stub. Confirm by loading in x64dbg and checking what runs OEP.') `
                                -Fix ('Identify the packing/encryption mechanism (entropy scan + import ' +
                                    'pattern + string analysis). For audit purposes, obtain or generate an ' +
                                    'unpacked copy before running further static checks.')
                        }
                    }
                }

                # 3b) OEP in suspicious section (not .text or CODE-flagged)
                $oepRva = $dieInfo.OepRva
                if ($oepRva -ne 0) {
                    $oepSec = $null
                    foreach ($sec in $dieInfo.Sections) {
                        if ($oepRva -ge $sec.VA -and $oepRva -lt ($sec.VA + $sec.VSize)) {
                            $oepSec = $sec; break
                        }
                    }
                    if ($oepSec -and -not $oepSec.IsCode) {
                        $riskLevel = if ($oepSec.IsWrite) { 'HIGH' } else { 'MEDIUM' }
                        New-TcpkFinding -Module 'static' -RuleId 'packer.oep-not-in-code' `
                            -Severity $riskLevel -Confidence 'Inferred' `
                            -Title "$($pe.Name) OEP (0x$($oepRva.ToString('X8'))) is in '$($oepSec.Name)' (not a code section)" `
                            -File $pe.FullName `
                            -Evidence "OEP=0x$($oepRva.ToString('X8')), section='$($oepSec.Name)', CODE_flag=$($oepSec.IsCode), EXEC_flag=$($oepSec.IsExec), WRITE_flag=$($oepSec.IsWrite)" `
                            -Cwe @('CWE-656') `
                            -Description ('The AddressOfEntryPoint (OEP) of this PE points into a section ' +
                                "that is NOT flagged as a code section (section '$($oepSec.Name)'). " +
                                'This is a textbook packer artifact: the packer stub starts in a data ' +
                                'or otherwise non-code section, decrypts/decompresses the real code, ' +
                                'then transfers control to it. It also occurs in some legitimate tools ' +
                                '(custom loaders, some .NET native images). ' +
                                $(if ($oepSec.IsWrite) { 'The section is WRITABLE, which means self-modifying code or code injection is likely.' } else { '' })) `
                            -Fix ('Obtain an unpacked copy. If this is legitimate, document the loader ' +
                                'design. If it is third-party/unsigned, treat as suspicious and cross-check ' +
                                'with the vendor-supplied hash of the binary.')
                    }
                }
            }
        }

        # 4) DIE-style legacy compiler detection (VB6, Delphi) -- INFO findings
        if (-not $managed) {
            if ($text -match '(?i)\bmsvbvm60\.dll\b') {
                New-TcpkFinding -Module 'static' -RuleId 'compiler.vb6' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) is a Visual Basic 6 binary (msvbvm60.dll runtime)" `
                    -File $pe.FullName -Evidence 'import: msvbvm60.dll' `
                    -Cwe @('CWE-1104') `
                    -Description ('VB6 runtime (msvbvm60.dll) is no longer supported by Microsoft. ' +
                        'VB6 binaries commonly use unsafe P/Invoke patterns, have no ASLR/DEP by default ' +
                        'in older builds, and rely on COM-based automation that is vulnerable to DLL hijack ' +
                        'and type confusion. Check for: missing /DYNAMICBASE in COFF flags, missing NX/DEP, ' +
                        'and any user-controlled string passed to Shell(), CreateObject(), or Environ().') `
                    -Fix ('Rewrite in a supported language. If rewriting is not feasible, ensure the binary ' +
                        'is compiled with VB6 SP6 + ASLR patch, all input is validated before being passed ' +
                        'to Shell/CreateObject, and the application runs as a non-admin account.')
            } elseif ($text -match '(?i)\b(borlndmm\.dll|rtl\d+\.bpl|vcl\d+\.bpl)\b') {
                $borMatch = [regex]::Match($text, '(?i)\b(borlndmm\.dll|rtl\d+\.bpl|vcl\d+\.bpl)\b').Value
                New-TcpkFinding -Module 'static' -RuleId 'compiler.delphi' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) is a Delphi/C++Builder binary ($borMatch)" `
                    -File $pe.FullName -Evidence "import: $borMatch" `
                    -Cwe @('CWE-1104') `
                    -Description ('Delphi / Embarcadero C++Builder binaries use the Borland memory ' +
                        'manager (borlndmm.dll) or package runtime (RTL/VCL BPLs). These runtimes ' +
                        'have historically used GetMem/FreeMem without bounds checking in their ' +
                        'string implementations. Check: GetMem/ReallocMem calls with attacker-controlled ' +
                        'size, AnsiString/WideString operations on network data, and FreeAndNil vs nil ' +
                        'check after free (dangling pointer patterns common in older Delphi code).') `
                    -Fix ('Update to a current Embarcadero release. Enable FastMM4 with FullDebugMode ' +
                        'for development builds to surface heap corruption. Validate all external data ' +
                        'lengths before passing to string/buffer functions.')
            }
        }

        # 5) Not-obfuscated first-party managed assembly
        if ($managed -and -not (Test-TcpkIsFrameworkFile $pe.Name) -and -not (Test-TcpkIsNativeNoise $pe.Name)) {
            $managedTotal++
            $managedNotObf.Add($pe.Name)
        }
    }

    if ($managedNotObf.Count -gt 0) {
        $sample = (@($managedNotObf) | Select-Object -First 12) -join ', '
        New-TcpkFinding -Module 'static' -RuleId 'obfuscation.absent' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "$($managedNotObf.Count) first-party .NET assemblies are NOT obfuscated (source recoverable)" `
            -File $Path -Evidence $sample -Cwe @('CWE-656','CWE-1294') `
            -Description 'These managed assemblies have no packer and no obfuscator, so a decompiler (ILSpy/dnSpy) recovers near-original source: business logic, license checks, hardcoded values, and any embedded secrets are fully readable.' `
            -Fix 'If the logic/IP or any client-side check matters, apply an obfuscator AND move trust decisions server-side. Never rely on obfuscation to hide secrets.'
    }
}
