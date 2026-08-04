function Test-TcpkTempFileToctou {
<#
.SYNOPSIS
    C37. Predictable temp file TOCTOU (time-of-check to time-of-use) race condition.

.DESCRIPTION
    Temp-file races arise when an application constructs a predictable filename
    in a world-writable directory (TEMP / %TMP%). An attacker who knows the name
    can create the file (or a symlink to a privileged target) before the app does,
    causing the app to read attacker-supplied content or overwrite a file it did not
    intend to touch.

    Safe practice: use Path.GetTempFileName() (.NET) or GetTempFileNameW() (Win32),
    which create a zero-byte file atomically with a unique, unpredictable name.
    The file is owned by the app before any content is written.

    Unsafe patterns detected:

    Source level:

    1. Path.GetTempPath() combined with a fixed or variable filename on the same
       or an immediately adjacent line -- the app builds the path manually instead
       of using the atomic API. Confidence: Confirmed MEDIUM.

    2. GetTempFileName() followed by File.Delete() or File.Create() of the same
       variable -- the app discards the atomicity guarantee by deleting the file
       and recreating it (a race window exists between Delete and Create).
       Confidence: Confirmed MEDIUM.

    3. Environment.GetEnvironmentVariable("TEMP") or $env:TEMP used to build a
       file path with a fixed or predictable suffix. Confidence: Confirmed MEDIUM.

    Binary level:

    4. Native PE imports GetTempPath / GetTempPathW but does NOT import
       GetTempFileName / GetTempFileNameW -- suggests manual path construction
       without the atomic API. Confidence: Inferred LOW.

.PARAMETER Path
    Root directory of the application to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkTempFileToctou')) { return }
    if (-not (Test-Path $Path)) { return }

    # ---- Binary: native PE import-level check ----
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text -or $text.Contains('BSJB')) { continue }   # skip managed

        $hasTempPath = $text -match '(?i)\bGetTempPath(?:W|A)?\b'
        $hasTempFile = $text -match '(?i)\bGetTempFileName(?:W|A)?\b'

        if ($hasTempPath -and -not $hasTempFile) {
            New-TcpkFinding -Module 'filesystem' -RuleId 'tempfile.native-no-atomic-api' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "$($pe.Name) uses GetTempPath without GetTempFileName (predictable temp path risk)" `
                -File $pe.FullName `
                -Evidence 'GetTempPath(W) present; GetTempFileName(W) absent' `
                -Cwe @('CWE-377','CWE-362') `
                -Description ('The native binary imports GetTempPath but not GetTempFileName. ' +
                    'GetTempPath only returns the temp directory -- the caller must still choose ' +
                    'a filename. If that filename is fixed or predictable, an attacker can pre-create ' +
                    'it (or a symlink) before the app opens it, causing the app to read attacker data ' +
                    'or overwrite an unintended target (TOCTOU). Disassemble the call site to confirm ' +
                    'whether a fixed or uniquely-generated name is appended to the temp path.') `
                -Fix ('Replace with GetTempFileNameW(GetTempPath(), "prefix", 0, szPath) which ' +
                    'creates the file atomically with a unique name. In .NET: Path.GetTempFileName(). ' +
                    'In C: tmpfile() (anonymous) or _mktemp_s (unique name without creating file -- ' +
                    'still has a race; prefer GetTempFileNameW).')
        }
    }

    # ---- Source-level scan ----
    $srcFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include '*.cs','*.vb','*.java','*.cpp','*.c' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 500)

    # Pattern 1: Path.GetTempPath() combined with file/path construction
    # Matches: Path.GetTempPath() on a line that also has Path.Combine, +, Append, or new FileInfo
    $getTempPathCombineRx = '(?i)(Path\.GetTempPath\s*\(\s*\)|GetTempPath\s*\()' +
                            '.*(?:Path\.Combine|"\s*\+|\+\s*"|Path\.Join|new\s+FileInfo|new\s+FileStream)'
    $getTempPathLineRx    = '(?i)(Path\.GetTempPath\s*\(\s*\)|GetTempPath\s*\()'
    $pathCombineNextRx    = '(?i)(Path\.Combine|Path\.Join|"\s*\+\s*"\w|new\s+FileInfo|new\s+FileStream|File\.Open|File\.Create)'

    # Pattern 2: GetTempFileName() followed by Delete + Create of same var
    $getTempFileNameRx    = '(?i)(Path\.GetTempFileName\s*\(\s*\)|GetTempFileName\s*\()'
    $deleteRx             = '(?i)(File\.Delete|DeleteFile\s*\(|\.Delete\s*\()'
    $createRx             = '(?i)(File\.Create|File\.Open|new\s+FileStream|new\s+StreamWriter)'

    # Pattern 3: TEMP environment variable used to build a path
    $tempEnvRx = '(?i)(Environment\.GetEnvironmentVariable\s*\(\s*"(TEMP|TMP)"|' +
                 '\$env:(TEMP|TMP)\b|%TEMP%|%TMP%|getenv\s*\(\s*"TEMP"|getenv\s*\(\s*"TMP")'

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        $lineCount = $lines.Count

        # Track GetTempFileName variable name to detect delete+recreate
        $tempFileVar = $null
        $tempFileVarLine = -1

        for ($i = 0; $i -lt $lineCount; $i++) {
            $line = $lines[$i]
            if ($line.TrimStart() -match '^(?://|#|/\*|\*|''')') { continue }

            # ---- Pattern 1: GetTempPath + path construction ----
            if ($line -match $getTempPathLineRx) {
                # Check this line or the next 2 lines for a combine/construct
                $window = @($line)
                for ($j = $i+1; $j -lt [Math]::Min($i+3, $lineCount); $j++) { $window += $lines[$j] }
                $wText = $window -join ' '
                if ($wText -match $pathCombineNextRx -or $line -match $getTempPathCombineRx) {
                    $loc = "$($src.FullName):$($i+1)"
                    if ($seen.Add("gettemppath|$loc")) {
                        New-TcpkFinding -Module 'filesystem' -RuleId 'tempfile.predictable-name' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed' `
                            -Title "Predictable temp path construction (GetTempPath + Combine/new): $($src.Name):$($i+1)" `
                            -File $src.FullName `
                            -Evidence "Line $($i+1): $($line.Trim())" `
                            -Cwe @('CWE-377','CWE-362') `
                            -Description ('Path.GetTempPath() is used to get the temp directory, ' +
                                'followed by a path construction operation. If the filename appended ' +
                                'to GetTempPath() is fixed (e.g. "myapp.tmp") or derived from a ' +
                                'predictable value (process name, PID, timestamp without sufficient ' +
                                'entropy), an attacker can pre-create that path before the app does. ' +
                                'If the file is opened without FILE_FLAG_OPEN_EXISTING and exclusive ' +
                                'access, or if a symlink is followed, the attacker controls the target. ' +
                                'Replace with Path.GetTempFileName() which atomically creates the file ' +
                                'with a guaranteed-unique, unpredictable name.') `
                            -Fix ('Replace: var tmp = Path.Combine(Path.GetTempPath(), "myapp.tmp"); ' +
                                'With: var tmp = Path.GetTempFileName(); // atomically creates a unique file ' +
                                'If you need a specific extension, rename after creation: ' +
                                'var final = Path.ChangeExtension(tmp, ".dat"); File.Move(tmp, final);')
                    }
                }
            }

            # ---- Pattern 2: GetTempFileName followed by Delete + Create of same var ----
            if ($line -match $getTempFileNameRx) {
                # Try to capture the variable name assigned from GetTempFileName
                $varName = $null
                if ($line -match '(?i)(?:var|string|let|const|val)\s+(\w+)\s*=.*GetTempFileName') {
                    $varName = $matches[1]
                }
                if ($varName) {
                    $tempFileVar     = $varName
                    $tempFileVarLine = $i
                }
            }

            if ($tempFileVar -and $i -gt $tempFileVarLine -and $i -le $tempFileVarLine + 20) {
                if ($line -match $deleteRx -and $line -match [regex]::Escape($tempFileVar)) {
                    # Found Delete of the temp file; check next 5 lines for Create/Open of same
                    $foundRecreate = $false
                    for ($j = $i+1; $j -lt [Math]::Min($i+6, $lineCount); $j++) {
                        if ($lines[$j] -match $createRx -and $lines[$j] -match [regex]::Escape($tempFileVar)) {
                            $foundRecreate = $true
                            $loc = "$($src.FullName):$($i+1)"
                            if ($seen.Add("gettempfilename-deletecreate|$loc")) {
                                New-TcpkFinding -Module 'filesystem' -RuleId 'tempfile.delete-recreate' `
                                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                                    -Title "GetTempFileName result deleted then recreated (TOCTOU window): $($src.Name):$($i+1)" `
                                    -File $src.FullName `
                                    -Evidence "Line $($i+1): $($line.Trim())" `
                                    -Cwe @('CWE-377','CWE-362') `
                                    -Description ("The code calls Path.GetTempFileName() (which atomically " +
                                        "creates a unique file) but then deletes the file ('$tempFileVar') " +
                                        "and recreates it. The delete+recreate sequence opens a race " +
                                        "window: between the delete and the subsequent File.Create(), " +
                                        "an attacker can create a symlink at that path, causing the " +
                                        "subsequent open to follow the symlink to an attacker-chosen " +
                                        "target. This defeats the atomicity guarantee of GetTempFileName.") `
                                    -Fix ('Do not delete the file returned by GetTempFileName(). ' +
                                        'Open it directly for read/write: using var fs = File.Open(tmp, ' +
                                        'FileMode.Open, FileAccess.ReadWrite, FileShare.None). ' +
                                        'The file is already created; use FileMode.Open, not Create.')
                            }
                            break
                        }
                    }
                    if ($foundRecreate) { $tempFileVar = $null }
                }
            } elseif ($tempFileVar -and $i -gt $tempFileVarLine + 20) {
                $tempFileVar = $null  # too far from assignment, reset
            }

            # ---- Pattern 3: TEMP env var used to build a path ----
            if ($line -match $tempEnvRx) {
                $window = @($line)
                for ($j = $i+1; $j -lt [Math]::Min($i+3, $lineCount); $j++) { $window += $lines[$j] }
                if (($window -join ' ') -match $pathCombineNextRx) {
                    $loc = "$($src.FullName):$($i+1)"
                    if ($seen.Add("tempenv|$loc")) {
                        New-TcpkFinding -Module 'filesystem' -RuleId 'tempfile.env-var-path' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed' `
                            -Title "TEMP env variable used to construct a file path: $($src.Name):$($i+1)" `
                            -File $src.FullName `
                            -Evidence "Line $($i+1): $($line.Trim())" `
                            -Cwe @('CWE-377','CWE-426') `
                            -Description ('The application reads the TEMP or TMP environment variable ' +
                                'and appends a filename to it. Environment variables can be controlled by ' +
                                'the user who set them, and in some configurations an admin process may ' +
                                'inherit a user-controlled TEMP path. If a fixed filename is appended, ' +
                                'the resulting path is predictable and subject to a TOCTOU race. ' +
                                'Additionally, the TEMP variable could be set to a directory the ' +
                                'attacker controls, redirecting the app''s temp output.') `
                            -Fix ('Use Path.GetTempFileName() which reads the system temp directory ' +
                                'internally and creates an atomic unique file, rather than reading ' +
                                'the env var directly. On Windows, Path.GetTempPath() reads TEMP/TMP ' +
                                'but GetTempFileName additionally creates the file atomically.')
                    }
                }
            }
        }
    }
}
