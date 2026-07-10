#requires -Version 5.1
# Pester 5: extra-ecosystem CVE component collectors (Java/Maven, Python/PyPI, Rust/crates.io).
# Offline -- asserts the manifest PARSERS (the OSV query itself is network + covered elsewhere).
# Go + asar collectors need a real binary/archive and are exercised by a live audit, not here.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $script:fx = Join-Path $env:TEMP ('tcpk-ecot-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Python component collector (PyPI)' {
    It 'parses requirements.txt pins and dist-info METADATA' {
        Set-Content -LiteralPath (Join-Path $script:fx 'requirements.txt') -Value "requests==2.19.0`nurllib3==1.24.1`n# comment`nunpinned-pkg" -Encoding ASCII
        $di = Join-Path $script:fx 'Django-2.2.0.dist-info'; New-Item -ItemType Directory -Path $di | Out-Null
        Set-Content -LiteralPath (Join-Path $di 'METADATA') -Value "Metadata-Version: 2.1`nName: Django`nVersion: 2.2.0" -Encoding ASCII
        $c = @(InModuleScope TCPK -Parameters @{ p = $script:fx } { param($p) Get-TcpkPythonComponents -Dir $p })
        ($c | Where-Object Name -eq 'requests').Version | Should -Be '2.19.0'
        ($c | Where-Object Name -eq 'Django').Version   | Should -Be '2.2.0'
        # an unpinned requirement has no version -> not emitted
        ($c | Where-Object Name -eq 'unpinned-pkg')      | Should -BeNullOrEmpty
    }
}

Describe 'Rust component collector (crates.io)' {
    It 'parses [[package]] name/version pairs from Cargo.lock' {
        Set-Content -LiteralPath (Join-Path $script:fx 'Cargo.lock') -Value "[[package]]`nname = `"time`"`nversion = `"0.1.42`"`n`n[[package]]`nname = `"libc`"`nversion = `"0.2.0`"" -Encoding ASCII
        $c = @(InModuleScope TCPK -Parameters @{ p = $script:fx } { param($p) Get-TcpkRustComponents -Dir $p })
        ($c | Where-Object Name -eq 'time').Version | Should -Be '0.1.42'
        ($c | Where-Object Name -eq 'libc').Version | Should -Be '0.2.0'
    }
}

Describe 'Java/Maven component collector' {
    It 'reads groupId:artifactId@version from a jar META-INF/maven pom.properties' {
        $jar = Join-Path $script:fx 'lib.jar'
        $zip = [System.IO.Compression.ZipFile]::Open($jar, 'Create')
        $e = $zip.CreateEntry('META-INF/maven/org.example/widget/pom.properties')
        $sw = New-Object System.IO.StreamWriter($e.Open()); $sw.Write("groupId=org.example`nartifactId=widget`nversion=1.4.2`n"); $sw.Dispose()
        $zip.Dispose()
        $c = @(InModuleScope TCPK -Parameters @{ p = $script:fx } { param($p) Get-TcpkJarMavenComponents -Dir $p })
        ($c | Where-Object Name -eq 'org.example:widget').Version | Should -Be '1.4.2'
    }
}
