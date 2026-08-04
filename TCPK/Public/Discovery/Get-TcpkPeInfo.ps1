function Get-TcpkPeInfo {
<#
.SYNOPSIS
    Deep PE inspection -- CFF Explorer equivalent in PowerShell.

.DESCRIPTION
    Parses a PE file (or every PE under a directory) and returns a rich
    structured object covering all the fields a CFF Explorer session surfaces:

    Header fields:
      Machine, Arch, Subsystem, DllCharacteristics flags decoded
      TimeDateStamp (decoded to UTC datetime)
      MajorLinkerVersion / MinorLinkerVersion -> compiler toolchain hint
      ImageBase, SizeOfImage
      AddressOfEntryPoint, EntryPointSection (which section OEP is in)
      NumberOfSections

    Rich Header:
      Present flag, XOR key, decoded tool-entry list (ToolId, BuildNumber, Count)
      Inferred compiler/toolchain name from known VS build number ranges

    Sections:
      Name, VirtualAddress, VirtualSize, RawOffset, RawSize
      Entropy (Shannon bits/byte of raw section bytes -- > 7.0 suggests packing/encryption)
      Characteristics flags decoded (executable, readable, writable, discardable)

    Exports:
      Name, Ordinal, RVA, IsForwarded (forwarded exports show the target "DLL.Function")
      ForwardTarget string when IsForwarded = true

    VersionInfo resource strings (UTF-16LE wide-string scan):
      FileVersion, ProductVersion, CompanyName, ProductName,
      OriginalFilename, FileDescription, InternalName

    Manifest:
      ExecutionLevel extracted: asInvoker / requireAdministrator / highestAvailable

    PE Overlay:
      OverlayOffset and OverlaySize (bytes after the last section -- may be an
      installer payload, encrypted blob, or packer stub artifact)

    Compiler hint:
      .NET/CIL (BSJB magic), VB6 (msvbvm60), Delphi/C++Builder (borlndmm/BPL),
      or MSVC version decoded from Rich Header linker entry.

    This cmdlet does NOT emit TcpkFinding objects; it is a pure inspection/report
    cmdlet whose output is consumed interactively or piped to Format-List / Out-File.
    It is the data source for Get-TcpkPeHardening, but with ~10x more fields.

.PARAMETER Path
    Single PE file or directory (recurses for PE files).

.PARAMETER MaxFiles
    Cap on files when scanning a directory. Default 50.

.EXAMPLE
    Get-TcpkPeInfo -Path .\app.exe | Format-List *
    Get-TcpkPeInfo -Path .\app\ | Select-Object Name, Arch, Compiler, OverlaySize |
        Format-Table -AutoSize
    Get-TcpkPeInfo -Path .\app.exe | ForEach-Object { $_.Sections } | Format-Table -AutoSize

.OUTPUTS
    [pscustomobject]  -- one per PE file.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxFiles = 50
    )

    if (-not (Assert-TcpkWindows 'Get-TcpkPeInfo')) { return }

    # ---- Shannon entropy for a byte array ----
    function _ByteEntropy([byte[]]$bytes) {
        if (-not $bytes -or $bytes.Length -eq 0) { return 0.0 }
        $freq = New-Object 'int[]' 256
        foreach ($b in $bytes) { $freq[$b]++ }
        $len  = $bytes.Length
        $h    = 0.0
        foreach ($c in $freq) {
            if ($c -eq 0) { continue }
            $p = $c / $len
            $h -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($h, 3)
    }

    # ---- RVA -> file offset using raw section descriptor list ----
    # $secRaw is an array of hashtables with keys VA, VSize, RawPtr.
    function _RvaToOff([uint32]$rva, $secRaw) {
        foreach ($s in $secRaw) {
            if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) {
                return [long]($s.RawPtr + ($rva - $s.VA))
            }
        }
        return [long]-1
    }

    # ---- Read null-terminated ASCII string at file offset ----
    function _ReadAsciiZ([IO.BinaryReader]$br, [IO.Stream]$fs, [long]$off, [int]$max = 256) {
        if ($off -lt 0 -or $off -ge $fs.Length) { return '' }
        $saved = $fs.Position
        $fs.Position = $off
        $bs = [System.Collections.Generic.List[byte]]::new()
        while ($fs.Position -lt $fs.Length -and $bs.Count -lt $max) {
            $b = $br.ReadByte(); if ($b -eq 0) { break }
            $bs.Add($b)
        }
        $fs.Position = $saved
        return [Text.Encoding]::ASCII.GetString($bs.ToArray())
    }

    # ---- Scan a byte array for a UTF-16LE key and return its associated value ----
    function _FindWideString([byte[]]$data, [string]$key) {
        $keyBytes = [Text.Encoding]::Unicode.GetBytes($key)
        $kLen = $keyBytes.Length
        $dLen = $data.Length
        for ($i = 0; $i -le $dLen - $kLen - 4; $i++) {
            $match = $true
            for ($k = 0; $k -lt $kLen; $k++) {
                if ($data[$i + $k] -ne $keyBytes[$k]) { $match = $false; break }
            }
            if (-not $match) { continue }
            # Skip null words between key and value
            $p = $i + $kLen
            while ($p + 1 -lt $dLen -and $data[$p] -eq 0 -and $data[$p+1] -eq 0) { $p += 2 }
            # Read UTF-16LE value until double-null
            $chars = [System.Collections.Generic.List[char]]::new()
            while ($p + 1 -lt $dLen -and $chars.Count -lt 256) {
                $lo = $data[$p]; $hi = $data[$p+1]
                if ($lo -eq 0 -and $hi -eq 0) { break }
                $chars.Add([char](($hi -shl 8) -bor $lo))
                $p += 2
            }
            $val = ([string]::new($chars.ToArray())).Trim()
            if ($val.Length -ge 2) { return $val }
        }
        return ''
    }

    # ---- Known VS linker build number -> display name ----
    $vsNames = @{
        1300='VS2003 (VC7)'; 1310='VS2003 (VC7.1)'; 1400='VS2005 (VC8)'
        1500='VS2008 (VC9)'; 1600='VS2010 (VC10)'; 1700='VS2012 (VC11)'
        1800='VS2013 (VC12)'; 1900='VS2015 (VC14.0)'; 1910='VS2017 (VC14.1x)'
        1920='VS2019 (VC14.2x)'; 1930='VS2022 (VC14.3x)'
    }

    $subsysNames = @{
        0='Unknown'; 1='Native'; 2='Windows GUI'; 3='Windows Console'
        5='OS/2 CUI'; 7='POSIX CUI'; 9='Windows CE GUI'; 10='EFI Application'
        11='EFI Boot Driver'; 12='EFI Runtime Driver'; 14='Xbox'; 16='Windows Boot App'
    }

    $pes = if ((Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).PSIsContainer) {
        @(Get-TcpkPeFiles -Path $Path | Select-Object -First $MaxFiles)
    } else {
        @(Get-Item -LiteralPath $Path)
    }

    foreach ($peFile in $pes) {
        $fs = $null; $br = $null
        try {
            $fs = [IO.File]::OpenRead($peFile.FullName)
            $br = [IO.BinaryReader]::new($fs)
            if ($fs.Length -lt 0x80) { continue }

            # MZ check
            $fs.Position = 0; $mz = $br.ReadUInt16()
            if ($mz -ne 0x5A4D) { continue }

            # PE offset
            $fs.Position = 0x3C; $peOff = [long]$br.ReadInt32()
            if ($peOff -le 0 -or ($peOff + 24) -gt $fs.Length) { continue }

            # PE signature
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { continue }

            # COFF header (20 bytes after PE signature)
            $machine    = $br.ReadUInt16()
            $numSec     = $br.ReadUInt16()
            $timeDateSt = $br.ReadUInt32()
            $null = $br.ReadUInt32(); $null = $br.ReadUInt32()  # SymbolTable, NumSymbols
            $optHdrSize = $br.ReadUInt16()
            $coffChars  = $br.ReadUInt16()

            # Optional header
            $optStart   = $peOff + 24
            if (($optStart + 4) -gt $fs.Length) { continue }
            $fs.Position = $optStart
            $magic       = $br.ReadUInt16()
            $isPE32Plus  = ($magic -eq 0x20B)
            $majorLinker = $br.ReadByte()
            $minorLinker = $br.ReadByte()
            $null = $br.ReadUInt32()   # SizeOfCode
            $null = $br.ReadUInt32()   # SizeOfInitializedData
            $null = $br.ReadUInt32()   # SizeOfUninitializedData
            $oepRva      = $br.ReadUInt32()
            $null = $br.ReadUInt32()   # BaseOfCode
            if (-not $isPE32Plus) { $null = $br.ReadUInt32() }  # BaseOfData (PE32 only)
            $imageBase = if ($isPE32Plus) { $br.ReadUInt64() } else { [uint64]$br.ReadUInt32() }
            $null = $br.ReadUInt32(); $null = $br.ReadUInt32()   # SectionAlignment, FileAlignment
            $null = $br.ReadUInt16(); $null = $br.ReadUInt16()   # MajorOSVersion, MinorOSVersion
            $null = $br.ReadUInt32()   # MajorImageVersion + MinorImageVersion (packed)
            $null = $br.ReadUInt16(); $null = $br.ReadUInt16()   # MajorSubsystemVersion, MinorSubsystemVersion
            $null = $br.ReadUInt32()   # Win32VersionValue
            $sizeOfImage = $br.ReadUInt32()
            $null = $br.ReadUInt32()   # SizeOfHeaders
            $null = $br.ReadUInt32()   # CheckSum
            $subsystem   = $br.ReadUInt16()
            $dllChar     = $br.ReadUInt16()

            # Data directory base offset: PE32 = optStart+96, PE32+ = optStart+112
            $ddBase = if ($isPE32Plus) { $optStart + 112 } else { $optStart + 96 }

            $exportDirRva = [uint32]0; $exportDirSize = [uint32]0
            $resourceRva  = [uint32]0
            if (($ddBase + 24) -le $fs.Length) {
                $fs.Position = $ddBase
                $exportDirRva  = $br.ReadUInt32(); $exportDirSize = $br.ReadUInt32()
                $null = $br.ReadUInt32(); $null = $br.ReadUInt32()   # Import dir (skip)
                $resourceRva   = $br.ReadUInt32()
            }

            # Section table: one 40-byte entry per section.
            # Keep two parallel collections:
            #   $secRaw  = hashtable list for RVA math (raw uint32 integers)
            #   $sections = pscustomobject list for output (formatted strings)
            $secRaw      = [System.Collections.Generic.List[hashtable]]::new()
            $sections    = [System.Collections.Generic.List[pscustomobject]]::new()
            $lastSectionEnd = [long]0

            for ($i = 0; $i -lt $numSec; $i++) {
                $secOff2 = $peOff + 4 + 20 + $optHdrSize + ($i * 40)
                if (($secOff2 + 40) -gt $fs.Length) { break }
                $fs.Position = $secOff2
                $nameBytes = $br.ReadBytes(8)
                $sname     = ([Text.Encoding]::ASCII.GetString($nameBytes)).Trim([char]0).Trim()
                $vsize     = $br.ReadUInt32()
                $va        = $br.ReadUInt32()
                $rawSize   = $br.ReadUInt32()
                $rawPtr    = $br.ReadUInt32()
                $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
                $secChars  = $br.ReadUInt32()

                $secRaw.Add(@{ VA=$va; VSize=$vsize; RawPtr=$rawPtr })

                # Per-section Shannon entropy -- sample up to 64KB for performance
                $secEntropy = 0.0
                if ($rawPtr -gt 0 -and $rawSize -gt 0 -and ([long]$rawPtr + $rawSize) -le $fs.Length) {
                    $savedPos = $fs.Position
                    $fs.Position = $rawPtr
                    $readLen  = [Math]::Min([int]$rawSize, 65536)
                    $secBytes = $br.ReadBytes($readLen)
                    $fs.Position = $savedPos
                    $secEntropy = _ByteEntropy $secBytes
                }

                $cflags = [System.Collections.Generic.List[string]]::new()
                if ($secChars -band 0x20)       { $cflags.Add('CODE') }
                if ($secChars -band 0x40000000) { $cflags.Add('R') }
                if ($secChars -band 0x80000000) { $cflags.Add('W') }
                if ($secChars -band 0x20000000) { $cflags.Add('X') }
                if ($secChars -band 0x02000000) { $cflags.Add('DISCARDABLE') }
                if ($secChars -band 0x10000000) { $cflags.Add('SHARED') }

                $sections.Add([pscustomobject]@{
                    Name            = $sname
                    VirtualAddress  = '0x{0:X8}' -f $va
                    VirtualSize     = $vsize
                    RawOffset       = '0x{0:X8}' -f $rawPtr
                    RawSize         = $rawSize
                    Entropy         = $secEntropy
                    EntropyFlag     = if ($secEntropy -gt 7.0) { 'HIGH (packed/encrypted?)' }
                                      elseif ($secEntropy -gt 6.0) { 'MODERATE' }
                                      else { 'normal' }
                    Characteristics = $cflags -join ','
                })

                $sectionEnd = [long]$rawPtr + [long]$rawSize
                if ($sectionEnd -gt $lastSectionEnd) { $lastSectionEnd = $sectionEnd }
            }

            $secRawArr = $secRaw.ToArray()

            # PE Overlay: data after the last section
            $overlayOffset = [long]0; $overlaySize = [long]0
            if ($lastSectionEnd -gt 0 -and $lastSectionEnd -lt $fs.Length) {
                $overlayOffset = $lastSectionEnd
                $overlaySize   = $fs.Length - $lastSectionEnd
            }

            # Which section contains the OEP?
            $oepSection = '?'
            for ($oi = 0; $oi -lt $secRawArr.Length -and $oi -lt $sections.Count; $oi++) {
                $s = $secRawArr[$oi]
                if ($oepRva -ge $s.VA -and $oepRva -lt ($s.VA + $s.VSize)) {
                    $oepSection = $sections[$oi].Name; break
                }
            }

            # Exports including forwarded exports
            $exportList = [System.Collections.Generic.List[pscustomobject]]::new()
            if ($exportDirRva -ne 0) {
                $eOff = _RvaToOff $exportDirRva $secRawArr
                if ($eOff -ge 0 -and ($eOff + 40) -le $fs.Length) {
                    $fs.Position = $eOff + 16; $exportBase   = $br.ReadUInt32()
                    $fs.Position = $eOff + 20; $numFunctions = $br.ReadUInt32()
                    $fs.Position = $eOff + 24; $numNames     = $br.ReadUInt32()
                    $fs.Position = $eOff + 28; $addrOfFuncs  = $br.ReadUInt32()
                    $fs.Position = $eOff + 32; $addrOfNames  = $br.ReadUInt32()
                    $fs.Position = $eOff + 36; $addrOfOrds   = $br.ReadUInt32()

                    $cap      = [Math]::Min([int]$numNames, 256)
                    $namesOff = _RvaToOff $addrOfNames $secRawArr
                    $ordsOff  = _RvaToOff $addrOfOrds  $secRawArr
                    $funcsOff = _RvaToOff $addrOfFuncs $secRawArr

                    for ($k = 0; $k -lt $cap; $k++) {
                        $expName = ''; $ord = [uint32]0; $funcRva = [uint32]0
                        try {
                            if ($namesOff -ge 0) {
                                $fs.Position = $namesOff + ($k * 4)
                                $nameRva2 = $br.ReadUInt32()
                                $expName  = _ReadAsciiZ $br $fs (_RvaToOff $nameRva2 $secRawArr)
                            }
                            if ($ordsOff -ge 0) {
                                $fs.Position = $ordsOff + ($k * 2)
                                $ord = [uint32]($br.ReadUInt16()) + $exportBase
                            }
                            if ($funcsOff -ge 0 -and $ord -ge $exportBase) {
                                $funcIdx = $ord - $exportBase
                                $fs.Position = $funcsOff + ([long]$funcIdx * 4)
                                $funcRva = $br.ReadUInt32()
                            }
                        } catch {}

                        # Forwarded: RVA falls within the export directory range
                        $isForward = ($funcRva -ge $exportDirRva -and
                                      $funcRva -lt ($exportDirRva + $exportDirSize))
                        $fwdTarget = ''
                        if ($isForward) {
                            $fwdTarget = _ReadAsciiZ $br $fs (_RvaToOff $funcRva $secRawArr)
                        }
                        if ($expName -or $ord) {
                            $exportList.Add([pscustomobject]@{
                                Name          = $expName
                                Ordinal       = $ord
                                RVA           = '0x{0:X}' -f $funcRva
                                IsForwarded   = $isForward
                                ForwardTarget = $fwdTarget
                            })
                        }
                    }
                }
            }

            # Rich Header: scan DOS stub (0x80..peOff) for 'Rich' magic (0x68636952).
            # The 4-byte XOR key follows 'Rich'; DanS (0x536E6144) at stub[0] when XOR'd.
            $richHeader = $null
            if ($peOff -gt 0x88) {
                $stubLen = [Math]::Min($peOff - 0x80, 0x200)
                $fs.Position = 0x80
                $stub = $br.ReadBytes($stubLen)
                for ($ri = $stub.Length - 8; $ri -ge 0; $ri--) {
                    if ($stub[$ri] -eq 0x52 -and $stub[$ri+1] -eq 0x69 -and
                        $stub[$ri+2] -eq 0x63 -and $stub[$ri+3] -eq 0x68) {
                        $xorKey = [uint32](
                            $stub[$ri+4] -bor ($stub[$ri+5] -shl 8) -bor
                            ($stub[$ri+6] -shl 16) -bor ($stub[$ri+7] -shl 24)
                        )
                        $dans = [uint32](
                            $stub[0] -bor ($stub[1] -shl 8) -bor
                            ($stub[2] -shl 16) -bor ($stub[3] -shl 24)
                        ) -bxor $xorKey
                        if ($dans -eq 0x536E6144) {
                            $richEntries = [System.Collections.Generic.List[pscustomobject]]::new()
                            $pos = 16   # skip DanS + 3 padding DWORDs
                            while ($pos + 8 -le $ri) {
                                $d0 = [uint32](
                                    $stub[$pos] -bor ($stub[$pos+1] -shl 8) -bor
                                    ($stub[$pos+2] -shl 16) -bor ($stub[$pos+3] -shl 24)
                                ) -bxor $xorKey
                                $d1 = [uint32](
                                    $stub[$pos+4] -bor ($stub[$pos+5] -shl 8) -bor
                                    ($stub[$pos+6] -shl 16) -bor ($stub[$pos+7] -shl 24)
                                ) -bxor $xorKey
                                $toolId   = ($d0 -shr 16) -band 0xFFFF
                                $buildNum = $d0 -band 0xFFFF
                                $useCount = $d1
                                $toolName = switch ($toolId) {
                                    0x0001 { 'Imports (no build)' }
                                    0x0002 { 'Linker' }
                                    0x0004 { 'Resource Compiler' }
                                    0x0006 { 'cvtres' }
                                    0x000A { 'MASM' }
                                    0x000C { 'cl.exe (C)' }
                                    0x000E { 'cl.exe (C)' }
                                    0x0066 { 'cl.exe (C++)' }
                                    0x007C { 'link.exe' }
                                    default { "tool_0x$($toolId.ToString('X4'))" }
                                }
                                $richEntries.Add([pscustomobject]@{
                                    ToolId      = '0x{0:X4}' -f $toolId
                                    ToolName    = $toolName
                                    BuildNumber = $buildNum
                                    UseCount    = $useCount
                                })
                                $pos += 8
                            }
                            $linkerEntry = $richEntries |
                                Where-Object { $_.ToolName -match 'link|Linker' } |
                                Select-Object -First 1
                            $vsHint = ''
                            if ($linkerEntry -and $linkerEntry.BuildNumber -gt 0) {
                                $major  = [int]([Math]::Floor($linkerEntry.BuildNumber / 100) * 100)
                                $vsHint = if ($vsNames.ContainsKey($major)) { $vsNames[$major] } else {
                                    "build $($linkerEntry.BuildNumber)"
                                }
                            }
                            $richHeader = [pscustomobject]@{
                                Present  = $true
                                XorKey   = '0x{0:X8}' -f $xorKey
                                Entries  = $richEntries.ToArray()
                                VsHint   = $vsHint
                            }
                        }
                        break
                    }
                }
            }
            if (-not $richHeader) {
                $richHeader = [pscustomobject]@{
                    Present  = $false
                    XorKey   = ''
                    Entries  = @()
                    VsHint   = ''
                }
            }

            # VersionInfo strings: UTF-16LE wide-string scan.
            # Read the resource section first (if present), else scan the whole file.
            $verKeys  = @('FileVersion','ProductVersion','CompanyName','ProductName',
                          'OriginalFilename','FileDescription','InternalName','LegalCopyright')
            $verInfo  = @{}
            foreach ($vk in $verKeys) { $verInfo[$vk] = '' }

            $scanBytes = $null
            if ($resourceRva -ne 0) {
                $rsrcOff = _RvaToOff $resourceRva $secRawArr
                if ($rsrcOff -ge 0) {
                    $rsrcSz = 0
                    foreach ($s in $secRawArr) {
                        if ($resourceRva -ge $s.VA -and $resourceRva -lt ($s.VA + $s.VSize)) {
                            $rsrcSz = [Math]::Min([int]$s.VSize, [int]($fs.Length - $rsrcOff))
                            break
                        }
                    }
                    if ($rsrcSz -gt 0) {
                        $fs.Position = $rsrcOff
                        $scanBytes   = $br.ReadBytes([Math]::Min($rsrcSz, 512 * 1024))
                    }
                }
            }
            if (-not $scanBytes) {
                $fs.Position = 0
                $scanBytes   = $br.ReadBytes([Math]::Min([int]$fs.Length, 2 * 1024 * 1024))
            }

            foreach ($vk in $verKeys) {
                $val = _FindWideString $scanBytes $vk
                if ($val) { $verInfo[$vk] = $val }
            }

            # Manifest: scan for requestedExecutionLevel in the scan bytes as ASCII
            $executionLevel = ''
            $rawAscii = [Text.Encoding]::ASCII.GetString($scanBytes)
            if ($rawAscii -match "requestedExecutionLevel[^>]*level\s*=\s*[`"']([^`"']+)[`"']") {
                $executionLevel = $matches[1]
            } elseif ($rawAscii -match '(?i)(asInvoker|requireAdministrator|highestAvailable)') {
                $executionLevel = $matches[1]
            }

            # Compiler hint from import table strings + Rich Header
            $importText = Read-TcpkAllText -Path $peFile.FullName
            $isManaged  = $importText -and $importText.Contains('BSJB')
            $compiler   = 'Unknown'
            if ($isManaged) {
                $compiler = '.NET/CIL'
            } elseif ($importText -match '(?i)\bmsvbvm60\.dll\b') {
                $compiler = 'Visual Basic 6 (msvbvm60)'
            } elseif ($importText -match '(?i)\b(rtl\d+\.bpl|vcl\d+\.bpl|borlndmm\.dll)\b') {
                $compiler = 'Delphi/C++Builder (BPL/RTL)'
            } elseif ($richHeader.VsHint) {
                $compiler = "MSVC $($richHeader.VsHint)"
            } elseif ($majorLinker -gt 0) {
                $compiler = "Linker $majorLinker.$minorLinker"
            }

            # Timestamp decode (Unix epoch -> UTC)
            $compiledAt = if ($timeDateSt -ne 0 -and $timeDateSt -lt 0x7FFFFFFF) {
                try {
                    [DateTimeOffset]::FromUnixTimeSeconds($timeDateSt).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
                } catch { '?' }
            } else { 'zeroed (reproducible build)' }

            [pscustomobject]@{
                # File identity
                Name             = $peFile.Name
                FullPath         = $peFile.FullName
                FileSize         = $peFile.Length

                # Architecture and type
                Arch             = switch ($machine) {
                                       0x14C  { 'x86 (i386)' }
                                       0x8664 { 'x64 (AMD64)' }
                                       0xAA64 { 'ARM64' }
                                       0x1C0  { 'ARM' }
                                       default { "Machine=0x$($machine.ToString('X4'))" }
                                   }
                Is64Bit          = $isPE32Plus
                IsManaged        = $isManaged
                Subsystem        = if ($subsysNames.ContainsKey([int]$subsystem)) {
                                       $subsysNames[[int]$subsystem]
                                   } else { "0x$($subsystem.ToString('X'))" }
                Characteristics    = '0x{0:X4}' -f $coffChars
                DllCharacteristics = '0x{0:X4}' -f $dllChar

                # Build metadata
                CompiledAt       = $compiledAt
                LinkerVersion    = "$majorLinker.$minorLinker"
                Compiler         = $compiler
                ImageBase        = '0x{0:X}' -f $imageBase
                SizeOfImage      = $sizeOfImage
                OEP              = '0x{0:X8}' -f $oepRva
                OEPSection       = $oepSection
                NumberOfSections = $numSec

                # Rich Header (compiler/linker version fingerprint in DOS stub)
                RichHeader       = $richHeader

                # Sections with per-section entropy
                Sections         = $sections.ToArray()
                HighEntropySecs  = @($sections | Where-Object { $_.Entropy -gt 7.0 } |
                                     ForEach-Object { "$($_.Name) (H=$($_.Entropy))" })

                # PE overlay -- bytes after the last section
                OverlayOffset    = if ($overlayOffset -gt 0) { '0x{0:X}' -f $overlayOffset } else { 'none' }
                OverlaySize      = $overlaySize

                # Exports
                ExportCount      = $exportList.Count
                ForwardedExports = @($exportList | Where-Object { $_.IsForwarded })
                Exports          = $exportList.ToArray()

                # Version resource strings
                FileVersion      = $verInfo['FileVersion']
                ProductVersion   = $verInfo['ProductVersion']
                CompanyName      = $verInfo['CompanyName']
                ProductName      = $verInfo['ProductName']
                OriginalFilename = $verInfo['OriginalFilename']
                FileDescription  = $verInfo['FileDescription']
                InternalName     = $verInfo['InternalName']
                LegalCopyright   = $verInfo['LegalCopyright']

                # Embedded manifest
                ExecutionLevel   = $executionLevel
            }
        } catch {
            # Skip unparseable files silently
        } finally {
            if ($br) { try { $br.Dispose() } catch {} }
            if ($fs) { try { $fs.Dispose() } catch {} }
        }
    }
}
