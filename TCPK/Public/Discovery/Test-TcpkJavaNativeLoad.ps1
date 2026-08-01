function Test-TcpkJavaNativeLoad {
<#
.SYNOPSIS
    A46. JNI native library search path: -Djava.library.path entries and JAR manifest
    Class-Path entries that resolve to a directory a non-administrator can write.

.DESCRIPTION
    Java thick clients -- common in industrial and IoT device tooling -- load native code
    through JNI. System.loadLibrary() resolves the library name against java.library.path,
    and the class loader resolves the JAR manifest Class-Path the same way. If any entry on
    either path resolves somewhere a low-privilege principal can write, an attacker plants a
    DLL (or replaces a JAR) there and it is loaded with the application's identity. This is
    DLL hijacking wearing a Java hat.

    WHAT THIS CHECK ACTUALLY READS (and nothing more):

      1. Launcher scripts (.bat .cmd .ps1 .vbs) and config files (.cfg .vmoptions .ini,
         which covers *.l4j.ini) are read as text and searched for -Djava.library.path=.
         The value is unquoted, split on ';', %VAR% is expanded, and relative entries are
         resolved against the target directory.
      2. Shipped .jar / .war files are opened as a ZIP and their META-INF/MANIFEST.MF entry
         is read WITHOUT extracting the archive. The Class-Path header is unfolded
         (MANIFEST.MF continuation lines begin with a single space), split on whitespace,
         and each entry is resolved as a URL relative to the JAR's own directory.
      3. Loose .dll files sitting in a directory that also contains .jar files -- the usual
         JNI layout -- are reported once, aggregated, at INFO as context.

    Each resolved path is then ACL-checked, and reported only if it EXISTS and grants a
    well-known low-privilege SID a right that actually lets a file be placed or replaced.

    LIMITS, stated because silence here is not a clean result:

      * TCPK DOES NOT DECOMPILE .class FILES. Java application LOGIC is not analysed by
        this check or by any other check in TCPK. Only the native load path is examined.
        A call to System.load() with a hard-coded absolute path, a path built at runtime, or
        a library path set programmatically via System.setProperty is invisible here. Use a
        decompiler (Jadx, CFR, Procyon) for the code itself.
      * Only paths that EXIST are reported. A configured entry pointing at an absent
        directory is deliberately NOT reported, even though planting the missing directory
        inside a writable parent is a real hijack, because reporting absent paths produced
        more noise than signal. Those entries are counted in the evidence instead.
      * Entries containing an unexpanded token ($APPDIR, $ROOTDIR, an unset %VAR%) are not
        guessed at. They are never resolved or ACL-checked; they are surfaced through the
        Skipped finding as explicitly unevaluated. A real directory whose name happens to
        contain a '$' is treated the same way, so it is skipped rather than misresolved.
      * The value is split on ';' only. A UNIX-style ':'-separated path in a launcher meant
        for another platform is not parsed.
      * The value is read up to the first whitespace unless it is quoted, so an UNQUOTED
        path containing a space (legal in a .vmoptions / .cfg line) is truncated and will
        normally land in the 'absent' count rather than being resolved. Under-report.
      * Relative entries are resolved against the TARGET directory, not against the JVM's
        real working directory, which is not knowable statically. A launcher in a
        subdirectory that uses a relative library path may therefore resolve elsewhere at
        runtime than it does here.
      * Manifest Class-Path is NOT followed transitively. Real class loading resolves the
        Class-Path of each referenced JAR in turn; this check reads only the manifests of
        the archives it enumerated on disk.
      * A Class-Path entry with a URL scheme (http://, file://, any 'scheme://' form) is
        skipped, not resolved as a local path. A remote class path is a separate problem
        and is not ACL-checkable here.
      * Only paths named in the parsed files are examined. The JVM's DEFAULT native search
        path (the JRE bin directories and, on Windows, every entry of %PATH%) is not
        enumerated by this check.
      * Writability is judged against the well-known low-privilege SIDs shared with the
        other DACL checks (Everyone S-1-1-0, Authenticated Users S-1-5-11, BUILTIN\Users
        S-1-5-32-545, INTERACTIVE S-1-5-4, ANONYMOUS LOGON S-1-5-7, Guests S-1-5-32-546).
        A grant to some other non-admin principal, or to the auditing user by an explicit
        ACE, is NOT detected. This errs toward under-reporting.
      * A grant whose ONLY right is Delete is not reported: deleting a directory or a JAR
        still requires AddFile / AddSubdirectory on the PARENT to put something back, so
        Delete alone does not plant a library. Reporting it would inflate a HIGH.
      * The ACL read is the ACL of the COPY being scanned. If the target was extracted or
        copied to a staging directory rather than installed, the inherited permissions are
        the auditor's, not the vendor's; the evidence carries inside-target-dir= so this is
        visible. Confirm against a real installation before filing.
      * ACL evaluation is Windows-only. Off Windows the parsing still runs and a SAMPLE of
        the resolved paths is reported through a Skipped finding that says writability was
        not evaluated, so the absence of findings is never mistaken for a pass.
      * The scan is bounded (see the -Max* parameters). Whenever a bound actually truncated
        the work -- files past the cap, entries past the per-value cap, archives whose ZIP
        could not be opened, or a missing System.IO.Compression.ZipFile -- the Skipped
        finding is emitted with the exact counts, on Windows as well as off it.

    Stays completely silent when the target shows no Java signal at all (no .jar/.war, no
    .class, no jvm.dll, no java/javaw/javaws launcher, no .vmoptions or .l4j.ini), so a
    non-Java application is never reported on. A bare .ini or .cfg does NOT count as Java
    evidence.

    Static and read-only: nothing is extracted, launched, or modified.

.PARAMETER Path
    File or directory to scan.

.PARAMETER MaxConfigFiles
    Cap on launcher/config files read as text (default 300). Files past the cap are counted
    and disclosed through the Skipped finding.

.PARAMETER MaxArchives
    Cap on .jar/.war archives whose manifest is read (default 250). Archives past the cap
    are counted and disclosed through the Skipped finding.

.PARAMETER MaxAclChecks
    Cap on DISTINCT resolved paths kept for ACL evaluation, per source (default 400). One
    Get-Acl per path is the expensive part of this check, and a hostile or generated
    launcher can name an unbounded number of entries. Paths past the cap are counted and
    disclosed through the Skipped finding.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxConfigFiles = 300,
        [int]$MaxArchives = 250,
        [int]$MaxAclChecks = 400
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $dir = $item.FullName
    if (-not $item.PSIsContainer) { $dir = $item.DirectoryName }
    if (-not $dir) { return }

    $onWindows = ($env:OS -eq 'Windows_NT')

    # Rights that actually let an attacker PLACE or REPLACE a file in the directory.
    # WriteAttributes / WriteEA are deliberately excluded: they change metadata only and
    # would fire on directories where no library could ever be planted.
    $rightsMap = [ordered]@{
        'WriteData/AddFile'          = 0x00000002
        'AppendData/AddSubdirectory' = 0x00000004
        'Delete'                     = 0x00010000
        'WriteDAC'                   = 0x00040000
        'WriteOwner'                 = 0x00080000
        'GenericAll'                 = 0x10000000
        'GenericWrite'               = 0x40000000
    }

    # Rights that actually PLACE or REPLACE a file. Delete is reported as context when it
    # comes with one of these, but Delete on its own is not enough: removing a directory or
    # a JAR still needs AddFile/AddSubdirectory on the PARENT to put something back, so a
    # Delete-only grant is not a plantable load-path entry and must not raise a HIGH.
    $placingRights = @('WriteData/AddFile', 'AppendData/AddSubdirectory',
                       'WriteDAC', 'WriteOwner', 'GenericAll', 'GenericWrite')

    # Returns @{ Ok; Grants[] }. Ok=$false means the ACL could not be read at all, which is
    # reported as Skipped rather than swallowed. A returned object (not a bare array) keeps
    # "denied" distinguishable from "readable and clean": PowerShell unrolls an empty array
    # to $null, so the two cases would otherwise be identical.
    function _WriteGrants([string]$p) {
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $p -ErrorAction Stop } catch {
            return [pscustomobject]@{ Ok = $false; Grants = @() }
        }
        if (-not $acl) { return [pscustomobject]@{ Ok = $false; Grants = @() } }

        $sddl = ''
        try { $sddl = "$($acl.Sddl)" } catch { }
        $granted = @(Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $rightsMap)
        if ($granted.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Grants = @() } }

        # Mask of the rights that actually place a file, used to decide whether a DENY ace is
        # relevant at all.
        $placingMask = 0
        foreach ($rn in $rightsMap.Keys) {
            if ($placingRights -contains $rn) { $placingMask = $placingMask -bor [int]$rightsMap[$rn] }
        }

        # FP guard: an explicit DENY ace for the same identity overrides the allow, and the
        # SDDL grant walk above only looks at allow ACEs. Drop any identity that also has a
        # deny entry covering a file-placing right, rather than reporting a right the OS
        # will refuse.
        #
        # The deny is matched NUMERICALLY against the placing mask, not by matching the
        # rights string. Two ways the old string match was wrong, in opposite directions:
        # a substring match on 'Write' also matches WriteAttributes / WriteExtendedAttributes
        # -- the metadata-only rights deliberately kept OUT of the map -- so a deny of
        # WriteAttributes alone suppressed a real WriteData grant (false negative on the
        # exact case this check exists to catch); and matching 'Delete' suppressed a
        # WriteData grant on the strength of a deny that does not touch file placement.
        # Both the account name and the SID are collected: the allow side may fall back to a
        # raw SID string when translation fails, and the two sides must still line up.
        $denyIds = @()
        $aces = @()
        try { $aces = @($acl.Access) } catch { }
        foreach ($ace in $aces) {
            $atype = ''
            try { $atype = "$($ace.AccessControlType)" } catch { continue }
            if ($atype -ne 'Deny') { continue }
            $dmask = 0
            try { $dmask = [int]$ace.FileSystemRights } catch { continue }
            if (($dmask -band $placingMask) -eq 0) { continue }
            try { $denyIds += "$($ace.IdentityReference.Value)" } catch { }
            $dsid = $null
            try { $dsid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { }
            if ($dsid) { $denyIds += "$($dsid.Value)" }
        }

        $out = @()
        foreach ($g in $granted) {
            if ($denyIds -contains "$($g.Account)") { continue }
            if ($denyIds -contains "$($g.Sid)") { continue }
            $gr = @($g.Granted)
            if (@($gr | Where-Object { $placingRights -contains $_ }).Count -eq 0) { continue }
            $out += "$($g.Account) -> $($gr -join ',')"
        }
        return [pscustomobject]@{ Ok = $true; Grants = $out }
    }

    # ------------------------------------------------------------------ inventory ----
    $files = @(Get-TcpkChildItemSafe -Path $dir -File)
    if (-not $files.Count) { return }

    $archives = New-Object 'System.Collections.Generic.List[object]'
    $configs  = New-Object 'System.Collections.Generic.List[object]'
    $jarDirs  = New-Object 'System.Collections.Generic.HashSet[string]'
    $dllByDir = @{}
    $jarByDir = @{}
    $classCount = 0
    $javaRuntimeSignal = ''
    # Every bound this check applies keeps an exact count of what it dropped. A silently
    # truncated scan reads as a clean scan, which is the failure mode this check is for.
    $configsSkipped  = 0
    $archivesSkipped = 0

    foreach ($f in $files) {
        $ext = ''
        try { $ext = $f.Extension.ToLowerInvariant() } catch { }
        $nm = ''
        try { $nm = $f.Name.ToLowerInvariant() } catch { }
        $fdir = "$($f.DirectoryName)"

        if ($ext -eq '.jar' -or $ext -eq '.war') {
            if ($archives.Count -lt $MaxArchives) { $archives.Add($f) } else { $archivesSkipped++ }
            [void]$jarDirs.Add($fdir.ToLowerInvariant())
            if (-not $jarByDir.ContainsKey($fdir)) { $jarByDir[$fdir] = 0 }
            $jarByDir[$fdir] = $jarByDir[$fdir] + 1
            continue
        }
        if ($ext -eq '.class') { $classCount++; continue }
        if ($ext -eq '.dll') {
            if (-not $dllByDir.ContainsKey($fdir)) { $dllByDir[$fdir] = 0 }
            $dllByDir[$fdir] = $dllByDir[$fdir] + 1
            if ($nm -eq 'jvm.dll' -and -not $javaRuntimeSignal) { $javaRuntimeSignal = "jvm.dll: $($f.FullName)" }
            continue
        }
        if ($nm -eq 'java.exe' -or $nm -eq 'javaw.exe' -or $nm -eq 'javaws.exe') {
            if (-not $javaRuntimeSignal) { $javaRuntimeSignal = "launcher: $($f.FullName)" }
            continue
        }
        if ($ext -eq '.bat' -or $ext -eq '.cmd' -or $ext -eq '.ps1' -or $ext -eq '.vbs' -or
            $ext -eq '.cfg' -or $ext -eq '.vmoptions' -or $ext -eq '.ini') {
            if ($configs.Count -lt $MaxConfigFiles) { $configs.Add($f) } else { $configsSkipped++ }
            # The Java-signal assignment is deliberately OUTSIDE the cap: a .vmoptions past
            # the cap still proves the target is Java even though its text is not read.
            if (($ext -eq '.vmoptions' -or $nm.EndsWith('.l4j.ini')) -and -not $javaRuntimeSignal) {
                $javaRuntimeSignal = "jvm options file: $($f.FullName)"
            }
        }
    }

    # Java-signal gate. .ini and .cfg alone do NOT count -- they are ubiquitous in native
    # applications, and treating them as Java evidence would run this check everywhere.
    $isJava = ($archives.Count -gt 0 -or $classCount -gt 0 -or $javaRuntimeSignal -ne '')
    if (-not $isJava) { return }

    # --------------------------------------------------- 1. -Djava.library.path ------
    # Resolved -> record. Deduped so one directory referenced by ten launchers is one
    # finding, and counts are kept exact while the samples are capped.
    $libResolved = @{}
    $libAbsent = 0
    $libUnresolved = 0
    $libDropped = 0        # entries a bound stopped this check from evaluating at all
    $libFilesSkippedBig = 0
    $libFilesUnreadable = 0
    $libUnresolvedSample = New-Object 'System.Collections.Generic.List[string]'

    $libRx = '(?i)-Djava\.library\.path\s*=\s*("[^"]*"|[^\s]+)'

    foreach ($cf in $configs) {
        if ($cf.Length -gt 1048576) { $libFilesSkippedBig++; continue }   # a >1MB launcher is not a launcher
        $txt = ''
        try { $txt = Get-Content -LiteralPath $cf.FullName -Raw -ErrorAction Stop } catch {
            $libFilesUnreadable++
            continue
        }
        if (-not $txt) { continue }
        if ($txt -notmatch '(?i)java\.library\.path') { continue }

        $mall = @([regex]::Matches($txt, $libRx))
        if ($mall.Count -gt 20) { $libDropped += ($mall.Count - 20) }
        $mset = @($mall | Select-Object -First 20)
        foreach ($m in $mset) {
            $raw = $m.Groups[1].Value.Trim()
            $raw = $raw.Trim('"').Trim("'")
            if (-not $raw) { continue }

            # A single -Djava.library.path= value can name an unbounded number of ';'
            # separated entries, and every distinct existing one costs a Get-Acl later.
            # Bound the split and count what was dropped rather than walking all of it.
            $pieces = @($raw -split ';')
            if ($pieces.Count -gt 200) {
                $libDropped += ($pieces.Count - 200)
                $pieces = @($pieces | Select-Object -First 200)
            }

            foreach ($piece in $pieces) {
                $entry = $piece.Trim().Trim('"').Trim("'")
                if (-not $entry) { continue }

                # Unexpanded tokens are never guessed at. $APPDIR / $ROOTDIR are jpackage
                # placeholders the JVM substitutes, not environment variables.
                if ($entry.Contains('$')) {
                    $libUnresolved++
                    if ($libUnresolvedSample.Count -lt 5) { $libUnresolvedSample.Add("$($cf.Name): $entry") }
                    continue
                }
                $expanded = $entry
                try { $expanded = [System.Environment]::ExpandEnvironmentVariables($entry) } catch { }
                if ($expanded -match '%[^%]+%') {
                    $libUnresolved++
                    if ($libUnresolvedSample.Count -lt 5) { $libUnresolvedSample.Add("$($cf.Name): $entry") }
                    continue
                }

                $cand = $expanded
                if (-not [System.IO.Path]::IsPathRooted($cand)) {
                    try { $cand = Join-Path $dir $cand } catch { continue }
                }
                $full = $cand
                try { $full = [System.IO.Path]::GetFullPath($cand) } catch { }
                if ([string]::IsNullOrWhiteSpace($full)) { continue }

                if (-not (Test-Path -LiteralPath $full -PathType Container)) { $libAbsent++; continue }

                $key = $full.TrimEnd('\', '/').ToLowerInvariant()
                if (-not $libResolved.ContainsKey($key)) {
                    if ($libResolved.Count -ge $MaxAclChecks) { $libDropped++; continue }
                    $libResolved[$key] = [pscustomobject]@{
                        Full = $full; Raw = $entry; Source = $cf.FullName
                        Line = (Get-TcpkRedact $m.Value.Trim())
                    }
                }
            }
        }
    }

    # ---------------------------------------------- 2. JAR manifest Class-Path -------
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }

    $cpResolved = @{}
    $cpAbsent = 0
    $manifestsRead = 0
    $archivesUnreadable = 0
    $cpDropped = 0
    $manifestsOversize = 0

    # If the ZIP API is not present, NO manifest is read at all. That is a check that could
    # not run, not a check that found nothing, so it is recorded and surfaced as Skipped.
    $zipAvailable = (('System.IO.Compression.ZipFile' -as [type]) -ne $null)

    if ($zipAvailable) {
        foreach ($arc in $archives) {
            $zip = $null
            try { $zip = [System.IO.Compression.ZipFile]::OpenRead($arc.FullName) } catch { $archivesUnreadable++; continue }
            try {
                $mEntry = $null
                $seen = 0
                foreach ($e in $zip.Entries) {
                    $seen++
                    if ($seen -gt 5000) { break }   # manifest is normally first; bound the walk
                    if ("$($e.FullName)".ToUpperInvariant() -eq 'META-INF/MANIFEST.MF') { $mEntry = $e; break }
                }
                if (-not $mEntry) { continue }
                if ($mEntry.Length -gt 524288) { $manifestsOversize++; continue }

                # ZipArchiveEntry.Length is the length DECLARED in the archive directory.
                # A crafted JAR can declare a small manifest and decompress to gigabytes, so
                # the read itself is capped too rather than trusting the declared size.
                # This is a scanner-DoS guard, not a parsing decision.
                $mtxt = ''
                try {
                    $sr = New-Object System.IO.StreamReader($mEntry.Open())
                    try {
                        $sb = New-Object System.Text.StringBuilder
                        $buf = New-Object char[] 8192
                        # StreamReader.Read can return a SHORT read on a decompressing
                        # stream, so loop; stop at the cap or at end of stream.
                        while ($sb.Length -lt 524288) {
                            $got = $sr.Read($buf, 0, $buf.Length)
                            if ($got -le 0) { break }
                            [void]$sb.Append($buf, 0, $got)
                        }
                        $mtxt = $sb.ToString()
                    } finally { $sr.Dispose() }
                } catch { $archivesUnreadable++; continue }
                if (-not $mtxt) { continue }
                $manifestsRead++

                # MANIFEST.MF folds long headers: a continuation line starts with exactly one
                # space and belongs to the previous line. Without unfolding, a Class-Path
                # longer than 72 bytes is parsed as garbage, which is the common case.
                $rawLines = @($mtxt -split "`r`n|`n|`r")
                $unfolded = New-Object 'System.Collections.Generic.List[string]'
                foreach ($ln in $rawLines) {
                    if ($ln.StartsWith(' ') -and $unfolded.Count -gt 0) {
                        $unfolded[$unfolded.Count - 1] = $unfolded[$unfolded.Count - 1] + $ln.Substring(1)
                    } else {
                        $unfolded.Add($ln)
                    }
                }

                $cpVal = ''
                foreach ($ln in $unfolded) {
                    $cm = [regex]::Match($ln, '(?i)^Class-Path\s*:\s*(.*)$')
                    if ($cm.Success) { $cpVal = $cm.Groups[1].Value.Trim(); break }
                }
                if (-not $cpVal) { continue }

                $arcDir = "$($arc.DirectoryName)"
                $cpEntries = @($cpVal -split '\s+' | Where-Object { $_ -and $_.Trim() })
                if ($cpEntries.Count -gt 60) { $cpDropped += ($cpEntries.Count - 60) }
                $n = 0
                foreach ($cpe in $cpEntries) {
                    if ($n -ge 60) { break }
                    $ce = $cpe.Trim()
                    if (-not $ce) { continue }
                    $n++
                    # A remote Class-Path entry is a different problem and is not ACL-checkable.
                    if ($ce -match '^[A-Za-z][A-Za-z0-9+.\-]*://') { continue }
                    # Class-Path entries are URLs, so they are URL-encoded, not env-expanded.
                    if ($ce.Contains('%')) {
                        try { $ce = [System.Uri]::UnescapeDataString($ce) } catch { }
                    }

                    $cand = $ce
                    if (-not [System.IO.Path]::IsPathRooted($cand)) {
                        try { $cand = Join-Path $arcDir $cand } catch { continue }
                    }
                    $full = $cand
                    try { $full = [System.IO.Path]::GetFullPath($cand) } catch { }
                    if ([string]::IsNullOrWhiteSpace($full)) { continue }

                    $kind = ''
                    if (Test-Path -LiteralPath $full -PathType Container) { $kind = 'directory' }
                    elseif (Test-Path -LiteralPath $full -PathType Leaf) { $kind = 'file' }
                    else { $cpAbsent++; continue }

                    $key = $full.TrimEnd('\', '/').ToLowerInvariant()
                    if ($cpResolved.ContainsKey($key)) {
                        # RefCount counts REFERENCING ARCHIVES, so a manifest that names the
                        # same path twice must not double-count it and inflate the evidence.
                        if ($cpResolved[$key].LastSource -ne $arc.FullName) {
                            $cpResolved[$key].RefCount = $cpResolved[$key].RefCount + 1
                            $cpResolved[$key].LastSource = $arc.FullName
                        }
                        continue
                    }
                    if ($cpResolved.Count -ge $MaxAclChecks) { $cpDropped++; continue }
                    $cpResolved[$key] = [pscustomobject]@{
                        Full = $full; Raw = $ce; Kind = $kind
                        Source = $arc.FullName; RefCount = 1; LastSource = $arc.FullName
                    }
                }
            } finally {
                if ($zip) { $zip.Dispose() }
            }
        }
    }

    # ------------------------------------------------------ 3. native libs (INFO) ----
    # Loose .dll beside .jar is the standard JNI layout. Context only: it says where native
    # code lives, not that anything is wrong.
    $jniDirs = New-Object 'System.Collections.Generic.List[string]'
    $jniDllTotal = 0
    $jniDirTotal = 0
    foreach ($k in @($dllByDir.Keys)) {
        if (-not $jarDirs.Contains("$k".ToLowerInvariant())) { continue }
        $jniDirTotal++
        $jniDllTotal += [int]$dllByDir[$k]
        $jars = 0
        if ($jarByDir.ContainsKey($k)) { $jars = [int]$jarByDir[$k] }
        if ($jniDirs.Count -lt 10) { $jniDirs.Add("$k (jars=$jars, dlls=$($dllByDir[$k]))") }
    }

    if ($jniDllTotal -gt 0) {
        # dirs-with-jar-and-dll and dlls are EXACT totals. The directory list after them is a
        # capped SAMPLE, and says so, so nobody reads 10 as the count.
        $jniSample = ($jniDirs -join '; ')
        if ($jniDirTotal -gt $jniDirs.Count) {
            $jniSample = "showing first $($jniDirs.Count) of $jniDirTotal -- " + $jniSample
        }
        New-TcpkFinding -Module 'static' -RuleId 'jni.native-libs' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Native libraries ship beside Java archives ($jniDllTotal DLL(s))" `
            -File $dir `
            -Evidence ("dirs-with-jar-and-dll=$jniDirTotal; dlls=$jniDllTotal; " + $jniSample) `
            -Cwe @('CWE-427') `
            -Description ('Loose .dll files sit in the same directories as .jar files, which is the ' +
                'usual layout for JNI native libraries. This is context, not a defect: it identifies ' +
                'the native attack surface a Java front end reaches through System.loadLibrary. Note ' +
                'that TCPK does not decompile .class files, so which of these libraries the ' +
                'application actually loads, and with what arguments, is not determined here.') `
            -Fix 'No action required for the layout itself. Ensure the directories holding these libraries are writable only by SYSTEM and Administrators, and that the DLLs are signed and version-pinned.'
    }

    # ------------------------------------------------------------------ report ------
    # Parse counts, always stated, so the caller can tell "nothing on the load path" from
    # "the load path was never evaluated".
    # NOTE the exact wording of $parseCounts is asserted by JavaNativeLoad.Tests.ps1, which
    # uses it to test the parser off Windows. Do not reword it without updating those tests.
    $parseCounts = ("existing java.library.path directories=$($libResolved.Count) " +
        "(absent=$libAbsent, unresolved-token=$libUnresolved); " +
        "manifests read=$manifestsRead; existing Class-Path entries=$($cpResolved.Count) " +
        "(absent=$cpAbsent, unreadable archives=$archivesUnreadable)")

    # Anything a BOUND removed from the scan. Kept separate from $parseCounts (whose wording
    # is pinned by the tests) and reported on BOTH platforms: a truncated scan that says
    # nothing is indistinguishable from a clean scan, which is the one outcome this check
    # must never produce.
    $limitNotes = @()
    if (-not $zipAvailable) {
        $limitNotes += ("System.IO.Compression.ZipFile is unavailable, so NO manifest was read at " +
            "all: $($archives.Count) archive(s) unexamined")
    }
    if ($configsSkipped -gt 0) {
        $limitNotes += "$configsSkipped launcher/config file(s) past -MaxConfigFiles ($MaxConfigFiles) were not read"
    }
    if ($archivesSkipped -gt 0) {
        $limitNotes += "$archivesSkipped archive(s) past -MaxArchives ($MaxArchives) had no manifest read"
    }
    if ($libFilesSkippedBig -gt 0) {
        $limitNotes += "$libFilesSkippedBig config file(s) over 1MB were not read"
    }
    if ($libFilesUnreadable -gt 0) {
        $limitNotes += "$libFilesUnreadable config file(s) could not be read (locked or denied)"
    }
    if ($manifestsOversize -gt 0) {
        $limitNotes += "$manifestsOversize manifest(s) over 512KB were not parsed"
    }
    if ($libDropped -gt 0) {
        $limitNotes += "$libDropped java.library.path entr(ies) were dropped by a per-file or -MaxAclChecks ($MaxAclChecks) bound"
    }
    if ($cpDropped -gt 0) {
        $limitNotes += "$cpDropped Class-Path entr(ies) were dropped by the 60-per-manifest or -MaxAclChecks ($MaxAclChecks) bound"
    }
    $limitText = ''
    if ($limitNotes.Count -gt 0) { $limitText = 'BOUNDED SCAN: ' + ($limitNotes -join '; ') + '.' }

    if (-not $onWindows) {
        $samples = @()
        foreach ($v in @($libResolved.Values | Select-Object -First 4)) { $samples += "library.path: $($v.Full)" }
        foreach ($v in @($cpResolved.Values | Select-Object -First 4)) { $samples += "class-path: $($v.Full)" }
        foreach ($u in @($libUnresolvedSample)) { $samples += "unresolved: $u" }
        $reason = ("ACL evaluation is Windows-only and this host is not Windows, so WRITABILITY WAS " +
            "NOT EVALUATED for any resolved path. Parsing did run: " + $parseCounts + ". " +
            "Sampled paths (at most 4 per source): " + ($samples -join '; ') + " " + $limitText)
        New-TcpkSkippedFinding -RuleId 'jni.load-path-unevaluated' `
            -Title 'JNI native load path: writability not evaluated (not Windows)' `
            -Reason $reason.Trim()
        return
    }

    $aclDenied = 0

    foreach ($k in @($libResolved.Keys)) {
        $rec = $libResolved[$k]
        $res = _WriteGrants $rec.Full
        if (-not $res.Ok) { $aclDenied++; continue }
        if (@($res.Grants).Count -eq 0) { continue }

        # Prefix compare on a SEPARATOR-TERMINATED root, so C:\App does not swallow
        # C:\AppData and mislabel an out-of-tree path as inside the target.
        $inTarget = 'no'
        $rootKey = $dir.TrimEnd('\', '/').ToLowerInvariant()
        $fullKey = $rec.Full.TrimEnd('\', '/').ToLowerInvariant()
        if ($fullKey -eq $rootKey -or
            $fullKey.StartsWith($rootKey + '\') -or
            $fullKey.StartsWith($rootKey + '/')) { $inTarget = 'yes' }

        New-TcpkFinding -Module 'static' -RuleId 'jni.library-path-writable' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "java.library.path entry is user-writable: $($rec.Full)" `
            -File $rec.Source `
            -Evidence ("entry '$($rec.Raw)' resolves to $($rec.Full); grants: " + (@($res.Grants) -join '; ') +
                       "; inside-target-dir=$inTarget; config line: $($rec.Line)") `
            -Cwe @('CWE-427', 'CWE-732') `
            -Description ('This directory is on the JVM native library search path configured by a ' +
                'file shipped with the application, and it is writable by a low-privilege principal. ' +
                'System.loadLibrary resolves an unqualified library name against java.library.path in ' +
                'order, so an attacker who drops a DLL with the expected name into this directory gets ' +
                'it loaded into the JVM with the application''s identity and privileges. This is the ' +
                'Java equivalent of DLL search-order hijacking, and no code signing check in the Java ' +
                'layer applies to it: JNI libraries are loaded by the OS loader, not verified by the JVM. ' +
                'Verify against a real installation before filing: the permissions read here are those ' +
                'of the copy that was scanned, so a target extracted or copied into a staging directory ' +
                'inherits the auditor''s ACL rather than the vendor''s.') `
            -Fix 'Restrict the directory ACL so only SYSTEM and Administrators can write to it, and point java.library.path at an absolute path inside the protected install directory. Do not include the working directory or any per-user path on the native library search path.'
    }

    foreach ($k in @($cpResolved.Keys)) {
        $rec = $cpResolved[$k]
        $res = _WriteGrants $rec.Full
        if (-not $res.Ok) { $aclDenied++; continue }
        if (@($res.Grants).Count -eq 0) { continue }

        $what = 'directory on the class path'
        if ($rec.Kind -eq 'file') { $what = 'JAR on the class path' }

        New-TcpkFinding -Module 'static' -RuleId 'jni.manifest-classpath-writable' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "Manifest Class-Path $($rec.Kind) is user-writable: $($rec.Full)" `
            -File $rec.Source `
            -Evidence ("Class-Path entry '$($rec.Raw)' in $(Split-Path -Leaf $rec.Source) resolves to " +
                       "$($rec.Full) ($($rec.Kind)); referenced by $($rec.RefCount) archive(s); grants: " +
                       (@($res.Grants) -join '; ')) `
            -Cwe @('CWE-427', 'CWE-732') `
            -Description ("The JAR manifest Class-Path header extends the class loader's search to this " +
                "$what, and it is writable by a low-privilege principal. An attacker can replace or add " +
                'a class file there, and the JVM will load it in place of the intended one -- including ' +
                'any class that itself calls System.loadLibrary, which turns this into native code ' +
                'execution with the application''s identity. Class-Path resolution happens before the ' +
                'application''s own code runs, so in-application integrity checks do not cover it. ' +
                'Verify against a real installation before filing: the permissions read here are those ' +
                'of the copy that was scanned, so a target extracted or copied into a staging directory ' +
                'inherits the auditor''s ACL rather than the vendor''s.') `
            -Fix 'Restrict the ACL on the referenced path to SYSTEM and Administrators. Where possible remove the Class-Path header and pass an explicit, fully qualified class path at launch from a protected location.'
    }

    # Anything the check could not decide is stated rather than dropped: an ACL it could not
    # read, and a configured entry whose path token it refused to guess at. Both leave a
    # real load-path entry unevaluated, which is not the same as evaluating it as clean.
    if ($aclDenied -gt 0 -or $libUnresolved -gt 0 -or $archivesUnreadable -gt 0 -or $limitNotes.Count -gt 0) {
        $bits = @()
        if ($aclDenied -gt 0) {
            $bits += ("$aclDenied resolved path(s) on the JVM native library search path or manifest " +
                'Class-Path could not have their ACL read, so their writability is UNKNOWN rather ' +
                'than clean. Re-run elevated, or check those paths manually with icacls.')
        }
        if ($libUnresolved -gt 0) {
            $bits += ("$libUnresolved java.library.path entr(ies) contain a token this check does not " +
                'expand (a jpackage $APPDIR / $ROOTDIR placeholder, or an environment variable that ' +
                'is unset in the auditing session). They were NOT resolved and NOT ACL-checked: ' +
                (@($libUnresolvedSample) -join '; '))
        }
        if ($archivesUnreadable -gt 0) {
            $bits += ("$archivesUnreadable archive(s) could not be opened as a ZIP or their manifest " +
                'could not be read, so any Class-Path they declare is UNKNOWN rather than absent.')
        }
        $bits += $parseCounts
        if ($limitText) { $bits += $limitText }
        New-TcpkSkippedFinding -RuleId 'jni.load-path-unevaluated' `
            -Title 'JNI native load path: some entries could not be evaluated' `
            -Reason ($bits -join ' | ')
    }
}
