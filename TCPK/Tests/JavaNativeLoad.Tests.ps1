#requires -Version 5.1
# Pester 5: Test-TcpkJavaNativeLoad (A46).
#
# The value of this check is entirely in its boundaries: it must stay silent on a non-Java
# app, must never report a configured-but-absent path, must not guess at an unexpanded
# token, and must say out loud when it could not evaluate writability. The tests below
# target those boundaries rather than the happy path.
#
# ACL evaluation is Windows-only, so the positive "writable" cases are gated on Windows and
# the parsing behaviour is asserted cross-platform through the Skipped finding, which
# carries the parse counts precisely so the parser stays testable off Windows.
#
# The exact substrings asserted against the Skipped record ("existing java.library.path
# directories=N", "absent=N", "unresolved-token=N", "existing Class-Path entries=N",
# "unreadable archives=N") are the detector's $parseCounts string. Changing that wording in
# Test-TcpkJavaNativeLoad.ps1 requires changing these tests in the same commit.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
    $script:isWin = ($env:OS -eq 'Windows_NT')

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    # Fail loudly here rather than letting every manifest fixture die inside New-TestJar
    # with an unrelated "method not found" error.
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        throw 'System.IO.Compression.ZipFile is unavailable; the JAR fixtures cannot be built.'
    }

    function New-TestDir {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-jni-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        return $d
    }

    # Minimal but real JAR: a ZIP with a META-INF/MANIFEST.MF entry. The check reads the
    # manifest out of the archive without extracting, so a real ZIP is required.
    function New-TestJar([string]$JarPath, [string]$ManifestText) {
        $zip = [System.IO.Compression.ZipFile]::Open($JarPath, 'Create')
        try {
            $e = $zip.CreateEntry('META-INF/MANIFEST.MF')
            $sw = New-Object System.IO.StreamWriter($e.Open())
            try { $sw.Write($ManifestText) } finally { $sw.Dispose() }
        } finally { $zip.Dispose() }
    }

    function New-PlainJar([string]$JarPath) {
        New-TestJar -JarPath $JarPath -ManifestText "Manifest-Version: 1.0`r`nMain-Class: com.x.Main`r`n`r`n"
    }

    function New-FakeDll([string]$Path) {
        $b = New-Object byte[] 64
        $b[0] = 0x4D; $b[1] = 0x5A       # MZ
        [System.IO.File]::WriteAllBytes($Path, $b)
    }

    # Windows only: give BUILTIN\Users (S-1-5-32-545) Modify on a directory we created, so
    # the low-privilege-grant path can be exercised for real rather than mocked.
    function Grant-UsersModify([string]$DirPath) {
        $acl = Get-Acl -LiteralPath $DirPath
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $DirPath -AclObject $acl
    }

    # Windows only: replace the directory's ACL with an explicit, NON-inherited one, so the
    # machine's %TEMP% permissions cannot leak into the assertion. The current user keeps
    # FullControl (otherwise the finally-block cleanup could not remove the fixture) and
    # BUILTIN\Users gets exactly $UsersRights and nothing else.
    function Set-OnlyUsersRight([string]$DirPath, [string]$UsersRights) {
        $acl = Get-Acl -LiteralPath $DirPath
        $acl.SetAccessRuleProtection($true, $false)      # drop inheritance, copy nothing
        # RemoveAccessRuleSpecific, not RemoveAccessRule: it drops the exact rule object and
        # cannot throw on a partial-rights match while we are clearing the whole DACL.
        foreach ($r in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($r) }
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $UsersRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        Set-Acl -LiteralPath $DirPath -AclObject $acl
    }

    function Get-SkipReason($Findings) {
        $s = @($Findings | Where-Object { $_.RuleId -eq 'jni.load-path-unevaluated' })
        if (-not $s.Count) { return '' }
        return "$($s[0].Evidence)"
    }
}

Describe 'Test-TcpkJavaNativeLoad -- Java-signal gate' {

    It 'stays completely silent on a target with no Java signal at all' {
        $d = New-TestDir
        try {
            # A launcher that literally contains the option string, but nothing Java-shaped
            # anywhere: no .jar, no .class, no jvm.dll, no java.exe, no .vmoptions.
            # Reporting here would mean firing on ordinary native applications.
            $lib = Join-Path $d 'lib'
            New-Item -ItemType Directory -Path $lib -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'run.bat') -Encoding ASCII `
                -Value 'set OPTS=-Djava.library.path=lib'
            @(Test-TcpkJavaNativeLoad -Path $d).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not treat a bare .ini or .cfg as Java evidence' {
        $d = New-TestDir
        try {
            Set-Content -LiteralPath (Join-Path $d 'app.ini') -Encoding ASCII -Value 'foo=bar'
            Set-Content -LiteralPath (Join-Path $d 'app.cfg') -Encoding ASCII -Value 'baz=qux'
            @(Test-TcpkJavaNativeLoad -Path $d).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'engages once a .jar is present' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            $lib = Join-Path $d 'native'
            New-Item -ItemType Directory -Path $lib -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'run.bat') -Encoding ASCII `
                -Value 'java -Djava.library.path=native -jar app.jar'
            # Off Windows the parse counts are asserted through the Skipped record. On
            # Windows the outcome depends on the real temp-directory ACL, which the test
            # must not assume, so only the absence of an exception is asserted here; the
            # positive case is covered by the Windows-only suite below.
            if (-not $script:isWin) {
                $f = @(Test-TcpkJavaNativeLoad -Path $d)
                (Get-SkipReason $f) | Should -Match 'existing java\.library\.path directories=1'
            } else {
                { Test-TcpkJavaNativeLoad -Path $d } | Should -Not -Throw
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-TcpkJavaNativeLoad -- false-positive guards' {

    It 'never reports a configured-but-absent library path' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=does-not-exist;also-missing'
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'jni.library-path-writable' }) | Should -BeNullOrEmpty
            if (-not $script:isWin) {
                (Get-SkipReason $f) | Should -Match 'existing java\.library\.path directories=0'
                (Get-SkipReason $f) | Should -Match 'absent=2'
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not guess at an unexpanded jpackage token' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            Set-Content -LiteralPath (Join-Path $d 'app.cfg') -Encoding ASCII -Value @'
[JavaOptions]
java-options=-Djava.library.path=$APPDIR/lib
'@
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'jni.library-path-writable' }) | Should -BeNullOrEmpty
            # An entry it refuses to resolve must be declared, not dropped -- on every
            # platform. Silence here would read as "the load path is clean".
            (Get-SkipReason $f) | Should -Match 'unresolved-token=1'
            (Get-SkipReason $f) | Should -Match 'APPDIR'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not report a Class-Path entry that does not exist on disk' {
        $d = New-TestDir
        try {
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: missing.jar missinglib/`r`n`r`n"
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'jni.manifest-classpath-writable' }) | Should -BeNullOrEmpty
            if (-not $script:isWin) {
                (Get-SkipReason $f) | Should -Match 'existing Class-Path entries=0'
                (Get-SkipReason $f) | Should -Match 'absent=2'
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not report a remote http Class-Path entry as a local path' {
        $d = New-TestDir
        try {
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: http://example.invalid/x.jar`r`n`r`n"
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'jni.manifest-classpath-writable' }) | Should -BeNullOrEmpty
            if (-not $script:isWin) {
                (Get-SkipReason $f) | Should -Match 'existing Class-Path entries=0'
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not report native-libs when the DLLs are not beside the JARs' {
        $d = New-TestDir
        try {
            $jarDir = Join-Path $d 'lib';    New-Item -ItemType Directory -Path $jarDir -Force | Out-Null
            $binDir = Join-Path $d 'bin';    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
            New-PlainJar (Join-Path $jarDir 'app.jar')
            New-FakeDll (Join-Path $binDir 'helper.dll')
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'jni.native-libs' }) | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-TcpkJavaNativeLoad -- manifest parsing' {

    It 'unfolds a MANIFEST.MF continuation line before resolving Class-Path' {
        $d = New-TestDir
        try {
            # 'nativel' + continuation ' ibs/' must rejoin to 'nativelibs/'. Without
            # unfolding, every Class-Path longer than 72 bytes parses as garbage, which is
            # the common case in real JARs.
            New-Item -ItemType Directory -Path (Join-Path $d 'nativelibs') -Force | Out-Null
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: nativel`r`n ibs/`r`nMain-Class: com.x.Main`r`n`r`n"
            if (-not $script:isWin) {
                $f = @(Test-TcpkJavaNativeLoad -Path $d)
                (Get-SkipReason $f) | Should -Match 'existing Class-Path entries=1'
                (Get-SkipReason $f) | Should -Match 'nativelibs'
            } else {
                { Test-TcpkJavaNativeLoad -Path $d } | Should -Not -Throw
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'URL-unescapes a Class-Path entry rather than treating %20 literally' {
        $d = New-TestDir
        try {
            New-Item -ItemType Directory -Path (Join-Path $d 'my libs') -Force | Out-Null
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: my%20libs/`r`n`r`n"
            if (-not $script:isWin) {
                $f = @(Test-TcpkJavaNativeLoad -Path $d)
                (Get-SkipReason $f) | Should -Match 'existing Class-Path entries=1'
            } else {
                { Test-TcpkJavaNativeLoad -Path $d } | Should -Not -Throw
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'survives a JAR that is not a valid ZIP without throwing' {
        $d = New-TestDir
        try {
            [System.IO.File]::WriteAllBytes((Join-Path $d 'broken.jar'), (New-Object byte[] 32))
            { Test-TcpkJavaNativeLoad -Path $d } | Should -Not -Throw
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'discloses an archive it could not open instead of treating it as clean' {
        $d = New-TestDir
        try {
            # An unopenable JAR means its Class-Path is UNKNOWN, not absent. Swallowing it
            # would let a corrupt or locked archive read as an empty class path -- on
            # Windows too, where the Skipped record used to fire only for ACL problems.
            [System.IO.File]::WriteAllBytes((Join-Path $d 'broken.jar'), (New-Object byte[] 32))
            $f = @(Test-TcpkJavaNativeLoad -Path $d)
            (Get-SkipReason $f) | Should -Match 'unreadable archives=1'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'counts one referencing archive per JAR even when a manifest repeats an entry' {
        $d = New-TestDir
        try {
            New-Item -ItemType Directory -Path (Join-Path $d 'shared') -Force | Out-Null
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: shared/ shared/`r`n`r`n"
            if (-not $script:isWin) {
                $f = @(Test-TcpkJavaNativeLoad -Path $d)
                (Get-SkipReason $f) | Should -Match 'existing Class-Path entries=1'
            } else {
                { Test-TcpkJavaNativeLoad -Path $d } | Should -Not -Throw
            }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-TcpkJavaNativeLoad -- native library context' {

    It 'reports loose DLLs beside JARs at INFO with exact counts' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            New-FakeDll (Join-Path $d 'jni1.dll')
            New-FakeDll (Join-Path $d 'jni2.dll')
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.native-libs' })
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -Be 'INFO'
            $f[0].Evidence | Should -Match 'dlls=2'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'names the no-decompilation limit so silence is not read as clean' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            New-FakeDll (Join-Path $d 'jni1.dll')
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.native-libs' })
            $f[0].Description | Should -Match 'does not decompile'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-TcpkJavaNativeLoad -- off-Windows degradation' -Skip:($script:isWin) {

    It 'emits a Skipped finding saying writability was not evaluated' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            New-Item -ItemType Directory -Path (Join-Path $d 'native') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            $s = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.load-path-unevaluated' })
            $s | Should -Not -BeNullOrEmpty
            $s[0].Confidence | Should -Be 'Skipped'
            $s[0].Evidence | Should -Match 'WRITABILITY WAS NOT EVALUATED'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'emits no HIGH finding off Windows, because nothing was proven' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            New-Item -ItemType Directory -Path (Join-Path $d 'native') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.Severity -eq 'HIGH' }) | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Test-TcpkJavaNativeLoad -- writable path detection' -Skip:(-not $script:isWin) {

    It 'flags a java.library.path directory that grants BUILTIN\Users write' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            $native = Join-Path $d 'native'
            New-Item -ItemType Directory -Path $native -Force | Out-Null
            Grant-UsersModify $native
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.library-path-writable' })
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Evidence | Should -Match 'native'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not flag a sibling directory that was never on the library path' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            $native = Join-Path $d 'native'
            $other  = Join-Path $d 'unrelated'
            New-Item -ItemType Directory -Path $native -Force | Out-Null
            New-Item -ItemType Directory -Path $other -Force | Out-Null
            Grant-UsersModify $other
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.library-path-writable' })
            ($f | ForEach-Object { $_.Evidence }) -join ' ' | Should -Not -Match 'unrelated'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not flag a Delete-only grant, which cannot plant a library' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            $native = Join-Path $d 'native'
            New-Item -ItemType Directory -Path $native -Force | Out-Null
            # Delete is in the rights map, but deleting the directory still needs
            # AddFile/AddSubdirectory on the PARENT to put anything back, so on its own it
            # is not a plantable load-path entry and must not raise a HIGH.
            Set-OnlyUsersRight $native 'Delete'
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.library-path-writable' })
            $f | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags the same directory once it also grants a file-placing right' {
        $d = New-TestDir
        try {
            New-PlainJar (Join-Path $d 'app.jar')
            $native = Join-Path $d 'native'
            New-Item -ItemType Directory -Path $native -Force | Out-Null
            # Same fixture as the Delete-only case, one right different. This is the pair
            # that proves the Delete-only filter is not just suppressing everything.
            Set-OnlyUsersRight $native 'CreateFiles'
            Set-Content -LiteralPath (Join-Path $d 'app.vmoptions') -Encoding ASCII `
                -Value '-Djava.library.path=native'
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.library-path-writable' })
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -Be 'HIGH'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a writable Class-Path directory referenced from a manifest' {
        $d = New-TestDir
        try {
            $libs = Join-Path $d 'plugins'
            New-Item -ItemType Directory -Path $libs -Force | Out-Null
            Grant-UsersModify $libs
            New-TestJar -JarPath (Join-Path $d 'app.jar') `
                -ManifestText "Manifest-Version: 1.0`r`nClass-Path: plugins/`r`n`r`n"
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.manifest-classpath-writable' })
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Evidence | Should -Match 'plugins'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'emits one finding per resolved path, not one per referencing JAR' {
        $d = New-TestDir
        try {
            $libs = Join-Path $d 'shared'
            New-Item -ItemType Directory -Path $libs -Force | Out-Null
            Grant-UsersModify $libs
            1..3 | ForEach-Object {
                New-TestJar -JarPath (Join-Path $d "a$_.jar") `
                    -ManifestText "Manifest-Version: 1.0`r`nClass-Path: shared/`r`n`r`n"
            }
            $f = @(Test-TcpkJavaNativeLoad -Path $d | Where-Object { $_.RuleId -eq 'jni.manifest-classpath-writable' })
            @($f).Count | Should -Be 1
            $f[0].Evidence | Should -Match 'referenced by 3 archive'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
