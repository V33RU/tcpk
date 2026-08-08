function Expand-TcpkPyInstaller {
<#
.SYNOPSIS
    Carve the CArchive out of a PyInstaller-frozen .exe (and extract a cx_Freeze /
    py2exe library.zip) so the rest of TCPK can actually read the app's code surface.

.DESCRIPTION
    TCPK already carves .NET single-file apphosts (Expand-TcpkSingleFile) and Electron
    asar bundles (Expand-TcpkAsar). Python-frozen thick clients were the remaining hole:
    Test-TcpkAppStack fingerprints them as 'python-frozen' and then every static scanner
    sees one opaque .exe, so the entire code surface reads as clean.

    This parses the documented PyInstaller CArchive:

      * The cookie sits at the end of the file. Magic is the ASCII bytes 'MEI' followed
        by 0x0C 0x0B 0x0A 0x0B 0x0E. It is searched for backwards in the file tail.
      * Cookie fields after the 8-byte magic are BIG-ENDIAN:
        int32 lengthofPackage, int32 toc, int32 tocLen, int32 pyver, and - on
        PyInstaller 2.1 and later - char[64] pylibname. Both cookie sizes (24 and 88
        bytes including the magic) are handled; the 64-byte pylibname slot is probed for
        the literal 'python' to tell them apart, the same test pyinstxtractor uses.
      * The archive base is (cookie offset + cookie size - lengthofPackage). The cookie
        size term matters: lengthofPackage covers the cookie itself, and any bytes
        appended after the cookie (an added signature or installer tail) shift the whole
        archive, so the base is derived rather than assumed to be the cookie offset.
      * Each TOC record is big-endian int32 entryLen, int32 entryPos, int32
        cmprsdDataSize, int32 uncmprsdDataSize, then byte cmprsFlag and char typeCode.
        The name fills the remaining entryLen - 18 bytes, NUL-padded. Entry data lives
        at (archive base + entryPos); cmprsFlag 1 means the data is a zlib stream.

    Type codes recorded: 's' PYSOURCE entry script, 'm'/'M' PYMODULE, 'z'/'Z' PYZ
    archive, 'b' shipped binary, everything else is written as-is.

    HONESTY NOTE. This recovers .pyc bytecode, it does NOT decompile it. PyInstaller
    stores 's'/'m'/'M' entries as marshalled code objects that in many builds do not
    carry the 16-byte .pyc header, and the header magic differs per CPython release, so
    no header is fabricated here - the inventory finding reports whether the recovered
    entries already carry one. Turning the recovered bytecode into readable Python is a
    manual follow-up step with decompyle3 / uncompyle6.

    The nested PYZ archive is written to disk but not unpacked: its own table of
    contents is a marshalled Python object, which needs a Python interpreter to read.
    Use pyinstxtractor for that layer.

    cx_Freeze and py2exe ship library.zip / base_library.zip next to the executable
    instead of an embedded CArchive. Those are ordinary ZIPs and are extracted here too.

    Entry names are sanitized before anything is written. A name that resolves outside
    -OutDir (a '..' traversal, a leading separator, or a drive letter) is refused and
    reported, so a hostile archive cannot write outside the extraction root.

.PARAMETER Path
    A frozen .exe, a library.zip / base_library.zip, or a directory to search
    recursively for either.

.PARAMETER OutDir
    Extraction root. Default: a fresh folder under the system temp directory. The
    per-target root is reported on the inventory finding's .File so other Test-Tcpk*
    cmdlets can be pointed at it.

.PARAMETER MaxEntries
    Per-archive cap on TOC entries extracted. Default 20000.

.PARAMETER MaxTotalBytes
    Per-archive cap on bytes written. Default 1 GB. Hitting it stops extraction and
    emits a Skipped finding rather than filling the disk silently.

.PARAMETER TailSearchBytes
    How many bytes of the file tail to search for the cookie magic. Default 8192.

.PARAMETER PassThru
    Also emit the extraction root path (a string) after the findings, for callers that
    want to chain another scanner onto it directly.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutDir,
        [ValidateRange(1, 1000000)][int]$MaxEntries = 20000,
        [ValidateRange(1, 1099511627776)][long]$MaxTotalBytes = 1073741824,
        [ValidateRange(8, 16777216)][int]$TailSearchBytes = 8192,
        [switch]$PassThru
    )

    # --- local helpers -----------------------------------------------------------
    # Big-endian (network order) uint32 read, returned as int64 so the high bit does
    # not come back negative.
    function _Be32([byte[]]$Buf, [int]$Off) {
        if ($Off -lt 0 -or ($Off + 4) -gt $Buf.Length) { return [int64](-1) }
        return ([int64]$Buf[$Off] * 16777216L) + ([int64]$Buf[$Off + 1] * 65536L) +
               ([int64]$Buf[$Off + 2] * 256L) + [int64]$Buf[$Off + 3]
    }

    # Sanitize an archive-supplied name into a relative path under the extraction root.
    # Both separators are folded to the platform separator FIRST so a Windows-style
    # '..\..\x' traversal is still recognized as a traversal when running elsewhere.
    function _SafeRel([string]$Name, [int]$Index) {
        $r = "$Name"
        $nul = $r.IndexOf([char]0)
        if ($nul -ge 0) { $r = $r.Substring(0, $nul) }
        $r = $r.Trim()
        if (-not $r) { return "entry_$Index.bin" }
        $r = $r -replace '^[A-Za-z]:', ''          # drive letter
        $sep = [System.IO.Path]::DirectorySeparatorChar
        $r = $r.Replace('\', $sep).Replace('/', $sep)
        $r = $r.TrimStart($sep)
        if (-not $r) { return "entry_$Index.bin" }
        return $r
    }

    # zlib stream -> raw bytes. The 2-byte zlib header is skipped and the trailing
    # adler32 is ignored; DeflateStream stops at the end of the deflate data.
    function _Inflate([byte[]]$Data) {
        if ($null -eq $Data -or $Data.Length -lt 3) { return $null }
        $ms = $null; $ds = $null; $out = $null
        try {
            $ms  = New-Object System.IO.MemoryStream(, $Data)
            $ms.Position = 2
            $ds  = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $out = New-Object System.IO.MemoryStream
            $ds.CopyTo($out)
            # Comma-wrap: a bare byte[] return would be unrolled onto the pipeline and come
            # back to the caller as Object[], which WriteAllBytes will not accept.
            return , $out.ToArray()
        } catch {
            return $null
        } finally {
            if ($ds)  { $ds.Dispose() }
            if ($ms)  { $ms.Dispose() }
            if ($out) { $out.Dispose() }
        }
    }

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.path-missing' -Severity 'INFO' -Confidence 'Skipped' `
            -Title "PyInstaller carve skipped: path not found" -File $Path `
            -Evidence "Get-Item returned nothing for: $Path" `
            -Description 'Nothing was analyzed because the supplied path does not exist.'
        return
    }

    $isDir  = [bool]$item.PSIsContainer
    $libNames = @('library.zip', 'base_library.zip')

    $exes = @()
    $libs = @()
    if ($isDir) {
        foreach ($f in (Get-ChildItem -LiteralPath $item.FullName -Recurse -File -ErrorAction SilentlyContinue)) {
            $ext = $f.Extension.ToLowerInvariant()
            if ($ext -eq '.exe') { $exes += $f }
            elseif ($libNames -contains $f.Name.ToLowerInvariant()) { $libs += $f }
        }
    } else {
        if ($libNames -contains $item.Name.ToLowerInvariant()) { $libs += $item } else { $exes += $item }
    }

    if (-not $OutDir) {
        $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-pyinst-' + [guid]::NewGuid().ToString('N'))
    }

    $magic = [byte[]]@(0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E)   # 'MEI' + 0C 0B 0A 0B 0E
    $rules = Get-TcpkSecretRegexRules
    $textExt = @('.py', '.pyw', '.json', '.cfg', '.ini', '.env', '.txt', '.yaml', '.yml', '.toml', '.xml')
    $anyArchive = $false

    foreach ($exe in $exes) {

        # ---- locate the cookie in the file tail ----------------------------------
        $fs = $null; $br = $null
        $cookiePos = -1
        try {
            $fs = [System.IO.File]::OpenRead($exe.FullName)
            $br = New-Object System.IO.BinaryReader($fs)
            $fileLen = $fs.Length
            # Too small to hold a cookie at all -> fall through to the not-a-PyInstaller
            # path below rather than skipping quietly.
            if ($fileLen -ge ($magic.Length + 16)) {
                $tail = [int][Math]::Min([int64]$TailSearchBytes, $fileLen)
                $tailStart = $fileLen - $tail
                $fs.Position = $tailStart
                $tailBuf = $br.ReadBytes($tail)

                for ($i = $tailBuf.Length - $magic.Length; $i -ge 0; $i--) {
                    $ok = $true
                    for ($j = 0; $j -lt $magic.Length; $j++) {
                        if ($tailBuf[$i + $j] -ne $magic[$j]) { $ok = $false; break }
                    }
                    if ($ok) { $cookiePos = $tailStart + $i; break }
                }
            }
        } catch {
            if ($br) { $br.Dispose() }; if ($fs) { $fs.Dispose() }
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.read-failed' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "PyInstaller carve skipped: could not read $($exe.Name)" -File $exe.FullName `
                -Evidence $_.Exception.Message `
                -Description 'The file could not be opened, so no conclusion about a PyInstaller archive was reached.'
            continue
        }

        if ($cookiePos -lt 0) {
            $br.Dispose(); $fs.Dispose()
            # Only report per-file when the caller named this exact file. In a directory
            # sweep almost every .exe is not a PyInstaller build and one record per file
            # would drown the report; the directory-level summary below covers that case.
            if (-not $isDir) {
                New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.not-pyinstaller' -Severity 'INFO' -Confidence 'Skipped' `
                    -Title "Not a PyInstaller archive: $($exe.Name)" -File $exe.FullName `
                    -Evidence "CArchive cookie magic 4D 45 49 0C 0B 0A 0B 0E not found in the last $TailSearchBytes bytes" `
                    -Description 'No PyInstaller CArchive was carved from this file. Nothing was extracted, and this is NOT a statement that the file is clean. If the app is frozen with cx_Freeze or py2exe the code lives in library.zip / base_library.zip beside the executable; if it is Nuitka-compiled there is no bytecode archive at all.' `
                    -Fix 'Confirm the packer with Test-TcpkAppStack, then point the right extractor at it.'
            }
            continue
        }

        # ---- parse the cookie ----------------------------------------------------
        $tocPos = -1L; $tocLen = 0L; $archiveBase = -1L; $pyver = -1L; $pylib = ''
        try {
            $fileLen = $fs.Length
            $cookieSize = 24
            if (($cookiePos + 88) -le $fileLen) {
                $fs.Position = $cookiePos + 24
                $probe = $br.ReadBytes(64)
                $probeTxt = [System.Text.Encoding]::ASCII.GetString($probe)
                if ($probeTxt.ToLowerInvariant().Contains('python')) { $cookieSize = 88 }
            }
            $fs.Position = $cookiePos
            $cookie = $br.ReadBytes($cookieSize)
            if ($cookie.Length -lt 24) { throw "cookie truncated ($($cookie.Length) bytes)" }

            $lengthofPackage = _Be32 $cookie 8
            $toc             = _Be32 $cookie 12
            $tocLen          = _Be32 $cookie 16
            $pyver           = _Be32 $cookie 20
            if ($cookieSize -eq 88) {
                $pylib = [System.Text.Encoding]::ASCII.GetString($cookie, 24, 64)
                $z = $pylib.IndexOf([char]0); if ($z -ge 0) { $pylib = $pylib.Substring(0, $z) }
            }

            # lengthofPackage includes the cookie, so the base is measured from the end
            # of the cookie. Anything appended after the cookie is therefore tolerated.
            $archiveBase = $cookiePos + $cookieSize - $lengthofPackage
            $tocPos = $archiveBase + $toc

            if ($lengthofPackage -le 0 -or $archiveBase -lt 0 -or $archiveBase -ge $fileLen) {
                throw "implausible lengthofPackage=$lengthofPackage (archive base resolved to $archiveBase, file is $fileLen bytes)"
            }
            if ($tocLen -le 0 -or $tocPos -lt 0 -or ($tocPos + $tocLen) -gt $fileLen) {
                throw "implausible table of contents: pos=$tocPos len=$tocLen (file is $fileLen bytes)"
            }
        } catch {
            $br.Dispose(); $fs.Dispose()
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.parse-failed' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "PyInstaller cookie found but the archive did not parse: $($exe.Name)" -File $exe.FullName `
                -Evidence $_.Exception.Message `
                -Description 'The CArchive cookie magic was present at the end of the file but the header fields did not describe a usable archive, so nothing was extracted. The build may use a PyInstaller variant or a modified bootloader. Treat this file as UNANALYZED, not clean.' `
                -Fix 'Extract with pyinstxtractor and re-run the static checks against the extracted folder.'
            continue
        }

        $anyArchive = $true

        # ---- read and walk the table of contents --------------------------------
        $fs.Position = $tocPos
        $tocBuf = $br.ReadBytes([int][Math]::Min($tocLen, [int64]([int]::MaxValue)))

        $outRoot = Join-Path $OutDir $exe.BaseName
        if (-not (Test-Path -LiteralPath $outRoot)) { New-Item -ItemType Directory -Path $outRoot -Force | Out-Null }
        $rootFull = [System.IO.Path]::GetFullPath($outRoot)
        $sep = [System.IO.Path]::DirectorySeparatorChar

        $written    = New-Object 'System.Collections.Generic.List[object]'
        $blocked    = New-Object 'System.Collections.Generic.List[string]'
        $typeCount  = @{}
        $failed     = 0
        $totalBytes = 0L
        $capHit     = ''
        $p = 0
        $idx = 0

        while (($p + 18) -le $tocBuf.Length) {
            $entryLen = _Be32 $tocBuf $p
            if ($entryLen -lt 18 -or ($p + $entryLen) -gt $tocBuf.Length) { break }
            $entryPos   = _Be32 $tocBuf ($p + 4)
            $cmprsdSize = _Be32 $tocBuf ($p + 8)
            $uncmprsd   = _Be32 $tocBuf ($p + 12)
            $cmprsFlag  = $tocBuf[$p + 16]
            $typeCode   = [char]$tocBuf[$p + 17]
            $nameLen    = [int]($entryLen - 18)
            $name = ''
            if ($nameLen -gt 0) { $name = [System.Text.Encoding]::UTF8.GetString($tocBuf, $p + 18, $nameLen) }
            $p += [int]$entryLen
            $idx++

            if ($idx -gt $MaxEntries) { $capHit = "entry cap $MaxEntries reached"; break }
            if ($totalBytes -ge $MaxTotalBytes) { $capHit = "size cap $MaxTotalBytes bytes reached"; break }

            $key = "$typeCode"
            if ($typeCount.ContainsKey($key)) { $typeCount[$key] = $typeCount[$key] + 1 } else { $typeCount[$key] = 1 }

            if ($cmprsdSize -le 0 -or $entryPos -lt 0 -or ($archiveBase + $entryPos + $cmprsdSize) -gt $fs.Length) {
                $failed++
                continue
            }

            $rel = _SafeRel $name $idx
            # PyInstaller stores 's'/'m'/'M' payloads as marshalled code objects with no
            # extension. Give them .pyc so they are obvious on disk and so a decompiler
            # will accept the filename.
            if (('s', 'm', 'M') -contains "$typeCode") {
                if (-not $rel.ToLowerInvariant().EndsWith('.pyc')) { $rel = $rel + '.pyc' }
            }

            $dest = Join-Path $outRoot $rel
            $destFull = ''
            try { $destFull = [System.IO.Path]::GetFullPath($dest) } catch { $destFull = '' }
            if (-not $destFull -or -not $destFull.StartsWith($rootFull + $sep, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning "PyInstaller entry name escapes the extraction root (zip-slip), refused: $name"
                $blocked.Add($name)
                continue
            }

            try {
                $fs.Position = $archiveBase + $entryPos
                $raw = $br.ReadBytes([int]$cmprsdSize)
                $data = $raw
                if ($cmprsFlag -eq 1) {
                    $data = _Inflate $raw
                    if ($null -eq $data) { $failed++; continue }
                }
                $ddir = Split-Path -Parent $destFull
                if ($ddir -and -not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                [System.IO.File]::WriteAllBytes($destFull, $data)
                $totalBytes += $data.Length
                $written.Add([pscustomobject]@{
                    Rel      = $rel
                    Path     = $destFull
                    Type     = "$typeCode"
                    Size     = $data.Length
                    Declared = $uncmprsd
                })
            } catch {
                $failed++
            }
        }

        $br.Dispose(); $fs.Dispose()

        # ---- python version from the cookie -------------------------------------
        $pyText = 'unknown'
        if ($pyver -ge 100 -and $pyver -lt 1000) {
            $pyText = "{0}.{1}" -f [int][Math]::Floor($pyver / 100), [int]($pyver % 100)
        } elseif ($pyver -ge 20 -and $pyver -lt 100) {
            $pyText = "{0}.{1}" -f [int][Math]::Floor($pyver / 10), [int]($pyver % 10)
        }

        $typeSummary = (($typeCount.Keys | Sort-Object | ForEach-Object { "$_=$($typeCount[$_])" }) -join ' ')

        New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.expanded' -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Extracted $($written.Count) entries from PyInstaller archive: $($exe.Name)" -File $outRoot `
            -Evidence ("entries=$($written.Count) blocked=$($blocked.Count) failed=$failed python=$pyText pylib='$pylib' types[$typeSummary] -> $outRoot") `
            -AttributionBasis 'established-footprint' `
            -Description 'A PyInstaller CArchive was carved out of the executable and its entries are now on disk, so the static scanners have something to read. Point other Test-Tcpk* cmdlets at this folder for coverage of the application code surface.' `
            -Fix 'Freezing is packaging, not a security control. Assume every bundled module, string and config value in this archive is recoverable by anyone holding the executable.' `
            -Subject "pyinstaller:$($exe.FullName)" -Dimension 'frozen-archive-contents' `
            -ObsValue ("{{""entries"":{0},""blocked"":{1},""failed"":{2},""python"":""{3}""}}" -f $written.Count, $blocked.Count, $failed, $pyText) `
            -Basis 'Measured'

        if ($capHit) {
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.cap-hit' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "PyInstaller extraction stopped early: $($exe.Name)" -File $outRoot `
                -Evidence $capHit `
                -Description 'Extraction stopped at a safety cap, so the recovered set is INCOMPLETE. Findings from the extracted folder are a lower bound.' `
                -Fix 'Re-run with a higher -MaxEntries / -MaxTotalBytes, or extract with pyinstxtractor.'
        }

        if ($blocked.Count -gt 0) {
            $sample = ($blocked | Select-Object -First 5) -join ', '
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.zipslip-blocked' -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "PyInstaller archive contains $($blocked.Count) entry names that resolve outside the extraction root" `
                -File $exe.FullName -Cwe @('CWE-22') `
                -Evidence "refused: $sample" `
                -AttributionBasis 'established-footprint' `
                -Description 'One or more table-of-contents entry names resolve outside the target directory once joined to an extraction root. TCPK refused to write them. A path-traversal name in a shipped archive is not normal build output; any extractor that joins these names without a containment check writes to an attacker-chosen location.' `
                -Impact 'An extractor without a containment check writes archive contents to an arbitrary filesystem path, which on a writable startup or program directory turns into code execution at the next launch.' `
                -Fix 'Resolve every archive entry to an absolute path and reject any that does not stay under the extraction root before opening the output file.'
        }

        if ($failed -gt 0) {
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.entry-unreadable' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "$failed PyInstaller entries could not be recovered: $($exe.Name)" -File $exe.FullName `
                -Evidence "$failed of $idx table-of-contents records failed (out-of-range offset, zlib failure, or write error)" `
                -Description 'These entries were seen in the table of contents but not written, so the extracted folder is incomplete for them. This is a coverage gap, not a clean result.'
        }

        # ---- bytecode vs source -------------------------------------------------
        $pycFiles = @($written | Where-Object { $_.Rel.ToLowerInvariant().EndsWith('.pyc') })
        $srcFiles = @($written | Where-Object { $_.Rel.ToLowerInvariant().EndsWith('.py') -or $_.Rel.ToLowerInvariant().EndsWith('.pyw') })

        if ($pycFiles.Count -gt 0) {
            # A .pyc header is <2-byte magic><0x0D 0x0A>. PyInstaller often stores the bare
            # marshalled code object instead, and the correct magic differs per CPython
            # release, so report what was observed rather than fabricating a header.
            $withHeader = 0
            foreach ($pf in $pycFiles) {
                try {
                    $head = New-Object byte[] 4
                    $hs = [System.IO.File]::OpenRead($pf.Path)
                    $n = $hs.Read($head, 0, 4)
                    $hs.Dispose()
                    if ($n -eq 4 -and $head[2] -eq 0x0D -and $head[3] -eq 0x0A) { $withHeader++ }
                } catch { }
            }
            $hdrNote = "$withHeader of $($pycFiles.Count) recovered .pyc start with a magic + 0D 0A header; the rest are bare marshalled code objects and need a header for the matching CPython release prepended before a decompiler will load them."
        }

        if ($pycFiles.Count -gt 0 -and $srcFiles.Count -eq 0) {
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.bytecode-only' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Application logic recovered only as Python bytecode: $($exe.Name)" -File $outRoot `
                -Evidence ("pyc=$($pycFiles.Count) py=0 python=$pyText. " + $hdrNote) `
                -AttributionBasis 'established-footprint' `
                -Description 'Every code entry in this archive came back as .pyc bytecode with no matching .py source, so the code surface is present on disk but not yet readable. TCPK recovered the bytecode; it did NOT decompile it. This is the normal shape of a PyInstaller build rather than a defect in the application, which is why it is INFO / Skipped: it records a COVERAGE LIMIT, not a vulnerability. It is reported so that a clean result from the text-level checks against this target is read as "not yet examined" rather than "examined and clean".' `
                -Impact 'Coverage limit, not a measured weakness. The text-level checks (secrets, endpoints, callsites, JWT) read almost nothing of this application''s logic, so their results for this target carry little weight until the bytecode is decompiled. No claim is made here about what the bytecode contains; none of it was read.' `
                -Fix ("Decompile the recovered bytecode as a follow-up step, then re-run the static checks against the decompiled sources: python -m decompyle3 '<file>.pyc' (or uncompyle6 for older bytecode). Recovered .pyc are under: $outRoot")
        }

        if ($srcFiles.Count -gt 0) {
            $srcSample = (($srcFiles | Select-Object -First 5 | ForEach-Object { $_.Rel }) -join ', ')
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.source-recovered' -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($srcFiles.Count) plaintext Python source files recovered from $($exe.Name)" -File $outRoot `
                -Cwe @('CWE-540') -AttributionBasis 'established-footprint' `
                -Evidence "source entries: $srcSample" `
                -Description 'Readable .py source shipped inside the frozen archive. Source in a distributed artifact is readable by anyone holding the executable, so any credential, endpoint or key constant in it is disclosed.' `
                -Fix 'Review the recovered sources for credentials, endpoints and keys; rotate anything live.'
        }

        $pyzFiles = @($written | Where-Object { $_.Type -eq 'z' -or $_.Type -eq 'Z' })
        if ($pyzFiles.Count -gt 0) {
            $pyzSample = (($pyzFiles | Select-Object -First 5 | ForEach-Object { $_.Rel }) -join ', ')
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.pyz-not-unpacked' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "$($pyzFiles.Count) PYZ archives recovered but not unpacked: $($exe.Name)" -File $outRoot `
                -Evidence "pyz entries: $pyzSample" `
                -Description 'The PYZ container holds most of the bundled modules. Its own table of contents is a marshalled Python object, which needs a Python interpreter to read, so TCPK wrote the PYZ to disk without unpacking it. The modules inside it are NOT covered by anything downstream of this cmdlet.' `
                -Fix 'Unpack the PYZ with pyinstxtractor (it runs the marshal layer), then re-run the static checks over the result.'
        }

        # ---- light secret scan over recovered text entries -----------------------
        foreach ($wf in $written) {
            $ext = [System.IO.Path]::GetExtension($wf.Rel)
            if (-not $ext) { continue }
            if ($textExt -notcontains $ext.ToLowerInvariant()) { continue }
            $t = Read-TcpkAllText -Path $wf.Path
            if (-not $t) { continue }
            foreach ($r in $rules) {
                $m = $null
                try { $m = $r._RX.Match($t) } catch { continue }
                if ($m -and $m.Success) {
                    $v = $m.Value; if ($v.Length -gt 80) { $v = $v.Substring(0, 80) + ' ...' }
                    $sev = 'MEDIUM'; if ($r.severity) { $sev = $r.severity }
                    New-TcpkFinding -Module 'static' -RuleId "pyfrozen.$($r.id)" -Severity $sev -Confidence 'Inferred' `
                        -Title "$($r.title) in $($wf.Rel) (PyInstaller archive)" -File $wf.Path `
                        -Evidence $v -Cwe (@($r.cwe)) -AttributionBasis 'established-footprint' `
                        -Description 'A secret-pattern match in a file recovered from the frozen archive. The string is present in the shipped artifact; confirm it is live and rotate if so.'
                    break
                }
            }
        }

        if ($PassThru) { $outRoot }
    }

    # ---- cx_Freeze / py2exe: library.zip is an ordinary ZIP ----------------------
    foreach ($lib in $libs) {
        $anyArchive = $true
        $libRoot = Join-Path $OutDir ($lib.Directory.Name + '_' + $lib.BaseName)
        if (-not (Test-Path -LiteralPath $libRoot)) { New-Item -ItemType Directory -Path $libRoot -Force | Out-Null }
        $libRootFull = [System.IO.Path]::GetFullPath($libRoot)
        $sep = [System.IO.Path]::DirectorySeparatorChar

        $zip = $null
        try { $zip = [System.IO.Compression.ZipFile]::OpenRead($lib.FullName) } catch { $zip = $null }
        if (-not $zip) {
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.libzip-unreadable' -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Could not open $($lib.Name) as a ZIP" -File $lib.FullName `
                -Evidence "ZipFile::OpenRead failed for $($lib.FullName)" `
                -Description 'The cx_Freeze / py2exe module archive did not open as a ZIP, so its modules were not recovered. Treat this archive as UNANALYZED.'
            continue
        }

        $libCount = 0; $libBlocked = New-Object 'System.Collections.Generic.List[string]'; $libFailed = 0
        try {
            foreach ($entry in $zip.Entries) {
                if ($libCount -ge $MaxEntries) { break }
                if (-not $entry.Name) { continue }          # directory record
                $rel = _SafeRel $entry.FullName $libCount
                $dest = Join-Path $libRoot $rel
                $destFull = ''
                try { $destFull = [System.IO.Path]::GetFullPath($dest) } catch { $destFull = '' }
                if (-not $destFull -or -not $destFull.StartsWith($libRootFull + $sep, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Write-Warning "library.zip entry name escapes the extraction root (zip-slip), refused: $($entry.FullName)"
                    $libBlocked.Add($entry.FullName)
                    continue
                }
                try {
                    $ddir = Split-Path -Parent $destFull
                    if ($ddir -and -not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destFull, $true)
                    $libCount++
                } catch { $libFailed++ }
            }
        } finally { $zip.Dispose() }

        New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.libzip-expanded' -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Extracted $libCount entries from $($lib.Name) (cx_Freeze / py2exe module archive)" -File $libRoot `
            -Evidence "entries=$libCount blocked=$($libBlocked.Count) failed=$libFailed -> $libRoot" `
            -AttributionBasis 'established-footprint' `
            -Description 'A cx_Freeze / py2exe module archive was extracted. Its .pyc modules are now on disk for review; TCPK recovered them and did not decompile them.' `
            -Fix 'Decompile the recovered .pyc (decompyle3 / uncompyle6) and re-run the static checks against the result.' `
            -Subject "libzip:$($lib.FullName)" -Dimension 'frozen-archive-contents' `
            -ObsValue ("{{""entries"":{0},""blocked"":{1},""failed"":{2}}}" -f $libCount, $libBlocked.Count, $libFailed) `
            -Basis 'Measured'

        if ($libBlocked.Count -gt 0) {
            $ls = ($libBlocked | Select-Object -First 5) -join ', '
            New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.zipslip-blocked' -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($lib.Name) contains $($libBlocked.Count) entry names that resolve outside the extraction root" `
                -File $lib.FullName -Cwe @('CWE-22') -Evidence "refused: $ls" `
                -AttributionBasis 'established-footprint' `
                -Description 'ZIP entry names in the shipped module archive resolve outside the target directory. TCPK refused to write them. Any extractor that joins these names without a containment check writes to an attacker-chosen location.' `
                -Fix 'Resolve every archive entry to an absolute path and reject any that does not stay under the extraction root before opening the output file.'
        }

        if ($PassThru) { $libRoot }
    }

    # ---- never finish silently ---------------------------------------------------
    if (-not $anyArchive -and $isDir) {
        New-TcpkFinding -Module 'static' -RuleId 'pyfrozen.not-pyinstaller' -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'No Python-frozen archive found under the scanned path' -File $item.FullName `
            -Evidence "checked $($exes.Count) .exe for the CArchive cookie and found no library.zip / base_library.zip" `
            -Description 'No PyInstaller CArchive and no cx_Freeze / py2exe module archive were found, so nothing was extracted here. This is a statement about packaging only, not about the security of the scanned files.' `
            -Fix 'Confirm the packer with Test-TcpkAppStack before concluding the Python code surface was covered.'
    }
}
