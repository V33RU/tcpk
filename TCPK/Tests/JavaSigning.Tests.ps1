#requires -Version 5.1
# Pester 5: Test-TcpkJavaSigning.
#
# Every fixture is a REAL ZIP built by System.IO.Compression, because the check reads the
# archive's entry table and the text of META-INF/MANIFEST.MF and META-INF/*.SF out of the
# archive without extracting it. A stubbed file would not exercise any of that.
#
# The boundaries under test, in order of how badly a mistake would hurt:
#   * a signed archive whose signature covers everything must produce NO defect finding
#     (false positives on correctly signed JARs would make the rule useless),
#   * a long entry name folded across manifest continuation lines must still be recognised
#     as covered (this is the single most likely source of mass false positives),
#   * an entry present in neither the .SF nor MANIFEST.MF must fire incomplete-coverage,
#   * MD5 / SHA1 digest headers must fire weak-digest,
#   * a truncated entry walk must SUPPRESS the coverage verdict and say so,
#   * an unopenable archive and a bound that dropped archives must be reported, never
#     silently treated as clean.
#
# The writability half of the unsigned severity split is measured, not assumed: a temp
# directory is writable so the HIGH case is asserted everywhere, and the MEDIUM case is
# asserted only when a genuinely non-writable directory could be constructed on this host.

BeforeDiscovery {
    # The MEDIUM (non-writable) branch needs a directory this account really cannot write.
    # Construct one and verify the premise rather than assuming chmod worked, so the case is
    # skipped rather than failing under root or on a filesystem that ignores the mode bits.
    $script:roProbeOk = $false
    if ($env:OS -ne 'Windows_NT') {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-jsprobe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
            & chmod 555 $d 2>$null
            $t = Join-Path $d 'probe.tmp'
            try {
                [System.IO.File]::WriteAllBytes($t, (New-Object byte[] 0))
                [System.IO.File]::Delete($t)
            } catch { $script:roProbeOk = $true }
        } catch { }
        try { & chmod 755 $d 2>$null } catch { }
        Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
    }
}

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        throw 'System.IO.Compression.ZipFile is unavailable; the JAR fixtures cannot be built.'
    }

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-jsign-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null

    function New-Dir([string]$Name) {
        $d = Join-Path $script:root $Name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        return $d
    }

    # Build a real JAR. $Entries is an ordered array of @{ Name; Text }; entry ORDER matters
    # because the -MaxEntries truncation test depends on the signature files coming first,
    # exactly as a real jarsigner-produced archive orders them.
    function New-Jar([string]$JarPath, [object[]]$Entries) {
        $zip = [System.IO.Compression.ZipFile]::Open($JarPath, 'Create')
        try {
            foreach ($e in $Entries) {
                $ze = $zip.CreateEntry($e.Name)
                $sw = New-Object System.IO.StreamWriter($ze.Open())
                try { $sw.Write($e.Text) } finally { $sw.Dispose() }
            }
        } finally { $zip.Dispose() }
    }

    # MANIFEST.MF wraps a header at 72 bytes and continues it on a line beginning with exactly
    # one space. Long entry names are therefore ALWAYS folded in a real archive, so the fixtures
    # fold them too.
    function Format-ManifestLine([string]$Line) {
        if ($Line.Length -le 70) { return $Line }
        $out = $Line.Substring(0, 70)
        $rest = $Line.Substring(70)
        while ($rest.Length -gt 69) {
            $out += "`r`n " + $rest.Substring(0, 69)
            $rest = $rest.Substring(69)
        }
        if ($rest) { $out += "`r`n " + $rest }
        return $out
    }

    # Section text for one signed entry: "Name: <path>" (folded) + "<Alg>-Digest: <base64>".
    function New-Section([string]$EntryName, [string]$Alg, [string]$Digest) {
        return (Format-ManifestLine ("Name: " + $EntryName)) + "`r`n$($Alg)-Digest: $($Digest)`r`n`r`n"
    }

    $script:classA = 'com/x/A.class'
    $script:resB   = 'res/config.properties'
    # 96 characters, so "Name: " + this is well past the 72-byte fold boundary.
    $script:longName = 'com/example/' + ('deeppackage/' * 5) + 'FinalComponentWithALongName.class'

    # ---------------------------------------------------------------- unsigned ----
    $script:dirUnsigned = New-Dir 'unsigned'
    New-Jar (Join-Path $script:dirUnsigned 'plain.jar') @(
        @{ Name = 'META-INF/MANIFEST.MF'; Text = "Manifest-Version: 1.0`r`nCreated-By: 17 (TCPK test)`r`nMain-Class: com.x.A`r`n`r`n" }
        @{ Name = $script:classA;         Text = 'CAFEBABE-not-really' }
        @{ Name = $script:resB;           Text = "key=value`r`n" }
    )

    # ------------------------------------------------------ signed, full coverage ----
    # Every content entry has a Name section in BOTH MANIFEST.MF and the .SF, and the long
    # name is folded in both, which is the case a naive line-by-line parser gets wrong.
    $script:dirSigned = New-Dir 'signed'
    $manSigned = "Manifest-Version: 1.0`r`nCreated-By: 17.0.1 (TCPK test)`r`n`r`n" +
                 (New-Section $script:classA   'SHA-256' 'bWFuaWZlc3QtYQ==') +
                 (New-Section $script:resB     'SHA-256' 'bWFuaWZlc3QtYg==') +
                 (New-Section $script:longName 'SHA-256' 'bWFuaWZlc3QtYw==')
    $sfSigned  = "Signature-Version: 1.0`r`nSHA-256-Digest-Manifest: c2lnLW1hbmlmZXN0`r`nCreated-By: 17.0.1 (TCPK test)`r`n`r`n" +
                 (New-Section $script:classA   'SHA-256' 'c2lnLWE=') +
                 (New-Section $script:resB     'SHA-256' 'c2lnLWI=') +
                 (New-Section $script:longName 'SHA-256' 'c2lnLWM=')
    New-Jar (Join-Path $script:dirSigned 'signed.jar') @(
        @{ Name = 'META-INF/MANIFEST.MF'; Text = $manSigned }
        @{ Name = 'META-INF/TCPK.SF';     Text = $sfSigned }
        @{ Name = 'META-INF/TCPK.RSA';    Text = 'pkcs7-block-placeholder' }
        @{ Name = $script:classA;         Text = 'CAFEBABE-not-really' }
        @{ Name = $script:resB;           Text = "key=value`r`n" }
        @{ Name = $script:longName;       Text = 'CAFEBABE-not-really' }
    )

    # --------------------------------------------- signed, one entry uncovered ----
    # The realistic mixed-signature JAR: an entry was ADDED after signing, so it appears in
    # neither the .SF nor MANIFEST.MF.
    $script:dirGap = New-Dir 'gap'
    $manGap = "Manifest-Version: 1.0`r`nCreated-By: 17.0.1 (TCPK test)`r`n`r`n" +
              (New-Section $script:classA 'SHA-256' 'bWFuaWZlc3QtYQ==') +
              (New-Section $script:resB   'SHA-256' 'bWFuaWZlc3QtYg==')
    $sfGap  = "Signature-Version: 1.0`r`nSHA-256-Digest-Manifest: c2lnLW1hbmlmZXN0`r`nCreated-By: 17.0.1 (TCPK test)`r`n`r`n" +
              (New-Section $script:classA 'SHA-256' 'c2lnLWE=') +
              (New-Section $script:resB   'SHA-256' 'c2lnLWI=')
    New-Jar (Join-Path $script:dirGap 'gap.jar') @(
        @{ Name = 'META-INF/MANIFEST.MF';  Text = $manGap }
        @{ Name = 'META-INF/TCPK.SF';      Text = $sfGap }
        @{ Name = 'META-INF/TCPK.RSA';     Text = 'pkcs7-block-placeholder' }
        @{ Name = $script:classA;          Text = 'CAFEBABE-not-really' }
        @{ Name = $script:resB;            Text = "key=value`r`n" }
        @{ Name = 'com/x/Injected.class';  Text = 'CAFEBABE-injected' }
    )

    # -------------------------------------------------------- signed with SHA1 ----
    $script:dirSha1 = New-Dir 'sha1'
    $manSha1 = "Manifest-Version: 1.0`r`nCreated-By: 1.6.0 (TCPK test)`r`n`r`n" +
               (New-Section $script:classA 'SHA1' 'bWFuaWZlc3QtYQ==')
    $sfSha1  = "Signature-Version: 1.0`r`nSHA1-Digest-Manifest: c2lnLW1hbmlmZXN0`r`nCreated-By: 1.6.0 (TCPK test)`r`n`r`n" +
               (New-Section $script:classA 'SHA1' 'c2lnLWE=')
    New-Jar (Join-Path $script:dirSha1 'legacy.jar') @(
        @{ Name = 'META-INF/MANIFEST.MF'; Text = $manSha1 }
        @{ Name = 'META-INF/LEGACY.SF';   Text = $sfSha1 }
        @{ Name = 'META-INF/LEGACY.DSA';  Text = 'pkcs7-block-placeholder' }
        @{ Name = $script:classA;         Text = 'CAFEBABE-not-really' }
    )

    # ------------------------------------------------------------- corrupt jar ----
    $script:dirBad = New-Dir 'bad'
    [System.IO.File]::WriteAllText((Join-Path $script:dirBad 'broken.jar'), 'this is not a zip archive at all')

    # ------------------------------------------------------------- no archives ----
    $script:dirEmpty = New-Dir 'empty'
    [System.IO.File]::WriteAllText((Join-Path $script:dirEmpty 'readme.txt'), 'nothing java here')

    # ------------------------------------------------------ many unsigned jars ----
    $script:dirMany = New-Dir 'many'
    foreach ($i in 1..4) {
        New-Jar (Join-Path $script:dirMany "lib$($i).jar") @(
            @{ Name = 'META-INF/MANIFEST.MF'; Text = "Manifest-Version: 1.0`r`n`r`n" }
            @{ Name = "com/x/C$($i).class";   Text = 'CAFEBABE-not-really' }
        )
    }

    # ------------------------------------------- unsigned in a read-only folder ----
    $script:dirRo = New-Dir 'readonly'
    New-Jar (Join-Path $script:dirRo 'ro.jar') @(
        @{ Name = 'META-INF/MANIFEST.MF'; Text = "Manifest-Version: 1.0`r`n`r`n" }
        @{ Name = $script:classA;         Text = 'CAFEBABE-not-really' }
    )
    if ($env:OS -ne 'Windows_NT') { try { & chmod 555 $script:dirRo 2>$null } catch { } }

    function Get-Rule([object[]]$Findings, [string]$RuleId) {
        return @($Findings | Where-Object { $_.RuleId -eq $RuleId })
    }
}

AfterAll {
    if ($script:dirRo -and $env:OS -ne 'Windows_NT') { try { & chmod 755 $script:dirRo 2>$null } catch { } }
    if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkJavaSigning - unsigned archive' {
    BeforeAll { $script:fUn = @(Test-TcpkJavaSigning -Path $script:dirUnsigned) }

    It 'fires javasign.unsigned for an archive with no .SF and no block file' {
        $r = Get-Rule $script:fUn 'javasign.unsigned'
        $r.Count | Should -Be 1
        $r[0].Confidence | Should -Be 'Confirmed'
        $r[0].Cwe | Should -Contain 'CWE-347'
        $r[0].Title | Should -Match 'plain\.jar'
    }

    It 'rates it HIGH when the containing directory is writable by the current user' {
        $r = Get-Rule $script:fUn 'javasign.unsigned'
        $r[0].Severity | Should -Be 'HIGH'
        $r[0].Evidence | Should -Match 'writable by current user: yes'
    }

    It 'emits the per-archive inventory record marked UNSIGNED' {
        $r = Get-Rule $script:fUn 'javasign.archive'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'INFO'
        $r[0].Title | Should -Match 'UNSIGNED'
        $r[0].Evidence | Should -Match 'content-entries=2'
    }

    It 'emits no signer inventory and no coverage or digest finding for an unsigned archive' {
        (Get-Rule $script:fUn 'javasign.signer-info').Count | Should -Be 0
        (Get-Rule $script:fUn 'javasign.incomplete-coverage').Count | Should -Be 0
        (Get-Rule $script:fUn 'javasign.weak-digest').Count | Should -Be 0
    }

    It 'leaves no writability probe file behind' {
        @(Get-ChildItem -LiteralPath $script:dirUnsigned -Filter '_tcpk_jsign_*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        (Get-Rule $script:fUn 'javasign.scan-incomplete').Count | Should -Be 0
    }
}

Describe 'Test-TcpkJavaSigning - correctly signed archive' {
    BeforeAll { $script:fOk = @(Test-TcpkJavaSigning -Path $script:dirSigned) }

    It 'reports no defect for an archive whose signature covers every entry' {
        (Get-Rule $script:fOk 'javasign.unsigned').Count | Should -Be 0
        (Get-Rule $script:fOk 'javasign.incomplete-coverage').Count | Should -Be 0
        (Get-Rule $script:fOk 'javasign.weak-digest').Count | Should -Be 0
        (Get-Rule $script:fOk 'javasign.coverage-unevaluated').Count | Should -Be 0
    }

    It 'still emits the inventory record, marked signed' {
        $r = Get-Rule $script:fOk 'javasign.archive'
        $r.Count | Should -Be 1
        $r[0].Title | Should -Match 'signed'
        $r[0].Title | Should -Not -Match 'UNSIGNED'
        $r[0].Evidence | Should -Match 'signature-files=1'
        $r[0].Evidence | Should -Match 'digest-algorithms=SHA-256'
    }

    It 'emits signer metadata naming the block file type and the digest algorithm' {
        $r = Get-Rule $script:fOk 'javasign.signer-info'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'INFO'
        $r[0].Evidence | Should -Match 'META-INF/TCPK\.RSA'
        $r[0].Evidence | Should -Match 'type: RSA'
        $r[0].Evidence | Should -Match 'Created-By=17\.0\.1'
    }

    It 'treats a folded (continuation-line) entry name as covered' {
        # The long name is wrapped across manifest continuation lines in both the manifest and
        # the .SF. Without unfolding it would be read as a truncated name and reported as
        # uncovered, which is the mass-false-positive failure mode for this rule.
        $script:longName.Length | Should -BeGreaterThan 72
        (Get-Rule $script:fOk 'javasign.incomplete-coverage').Count | Should -Be 0
    }

    It 'states plainly that no cryptographic verification was performed' {
        $r = Get-Rule $script:fOk 'javasign.signer-info'
        $r[0].Description | Should -Match 'NOT parsed|unverified'
        $r[0].Description | Should -Match 'jarsigner'
    }
}

Describe 'Test-TcpkJavaSigning - signed archive with an uncovered entry' {
    BeforeAll { $script:fGap = @(Test-TcpkJavaSigning -Path $script:dirGap) }

    It 'fires javasign.incomplete-coverage at HIGH' {
        $r = Get-Rule $script:fGap 'javasign.incomplete-coverage'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'HIGH'
        $r[0].Confidence | Should -Be 'Confirmed'
        $r[0].Cwe | Should -Contain 'CWE-347'
    }

    It 'names the uncovered entry and counts it against the content entries' {
        $r = Get-Rule $script:fGap 'javasign.incomplete-coverage'
        $r[0].Evidence | Should -Match 'com/x/Injected\.class'
        $r[0].Evidence | Should -Match '1 of 3 content entries'
        $r[0].Evidence | Should -Match 'META-INF/TCPK\.SF'
    }

    It 'does not also report the archive as unsigned' {
        (Get-Rule $script:fGap 'javasign.unsigned').Count | Should -Be 0
        (Get-Rule $script:fGap 'javasign.archive')[0].Title | Should -Not -Match 'UNSIGNED'
    }
}

Describe 'Test-TcpkJavaSigning - weak signature digest' {
    BeforeAll { $script:fSha1 = @(Test-TcpkJavaSigning -Path $script:dirSha1) }

    It 'fires javasign.weak-digest at MEDIUM with CWE-328' {
        $r = Get-Rule $script:fSha1 'javasign.weak-digest'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'MEDIUM'
        $r[0].Confidence | Should -Be 'Confirmed'
        $r[0].Cwe | Should -Contain 'CWE-328'
    }

    It 'names the weak algorithm and where each occurrence was read' {
        $r = Get-Rule $script:fSha1 'javasign.weak-digest'
        $r[0].Evidence | Should -Match 'SHA1'
        $r[0].Evidence | Should -Match 'in \.SF'
        $r[0].Evidence | Should -Match 'in MANIFEST\.MF'
    }

    It 'reports the DSA block file type in the signer inventory' {
        $r = Get-Rule $script:fSha1 'javasign.signer-info'
        $r.Count | Should -Be 1
        $r[0].Evidence | Should -Match 'type: DSA'
    }

    It 'does not report a coverage gap when every entry is listed' {
        (Get-Rule $script:fSha1 'javasign.incomplete-coverage').Count | Should -Be 0
    }
}

Describe 'Test-TcpkJavaSigning - single archive path' {
    It 'accepts a single .jar file as -Path' {
        $f = @(Test-TcpkJavaSigning -Path (Join-Path $script:dirGap 'gap.jar'))
        (Get-Rule $f 'javasign.incomplete-coverage').Count | Should -Be 1
        (Get-Rule $f 'javasign.archive').Count | Should -Be 1
    }
}

Describe 'Test-TcpkJavaSigning - coverage and bounds are never silent' {
    It 'suppresses the coverage verdict and says so when the entry walk is truncated' {
        $f = @(Test-TcpkJavaSigning -Path $script:dirGap -MaxEntries 3)
        $r = Get-Rule $f 'javasign.coverage-unevaluated'
        $r.Count | Should -Be 1
        $r[0].Confidence | Should -Be 'Skipped'
        $r[0].Evidence | Should -Match 'MaxEntries'
        # The truncated run must NOT invent a coverage gap out of the entries it never walked.
        (Get-Rule $f 'javasign.incomplete-coverage').Count | Should -Be 0
    }

    It 'reports an archive it could not open as a ZIP instead of passing over it' {
        $f = @(Test-TcpkJavaSigning -Path $script:dirBad)
        $r = Get-Rule $f 'javasign.archive-unreadable'
        $r.Count | Should -Be 1
        $r[0].Confidence | Should -Be 'Skipped'
        $r[0].Evidence | Should -Match 'UNKNOWN'
        (Get-Rule $f 'javasign.unsigned').Count | Should -Be 0
    }

    It 'reports archives dropped by -MaxArchives' {
        $f = @(Test-TcpkJavaSigning -Path $script:dirMany -MaxArchives 1)
        (Get-Rule $f 'javasign.archive').Count | Should -Be 1
        $r = Get-Rule $f 'javasign.scan-incomplete'
        $r.Count | Should -Be 1
        $r[0].Confidence | Should -Be 'Skipped'
        $r[0].Evidence | Should -Match '3 archive\(s\) past -MaxArchives'
    }

    It 'examines every archive when no bound is hit' {
        $f = @(Test-TcpkJavaSigning -Path $script:dirMany)
        (Get-Rule $f 'javasign.archive').Count | Should -Be 4
        (Get-Rule $f 'javasign.unsigned').Count | Should -Be 4
        (Get-Rule $f 'javasign.scan-incomplete').Count | Should -Be 0
    }

    It 'stays silent on a target that ships no Java archive' {
        @(Test-TcpkJavaSigning -Path $script:dirEmpty).Count | Should -Be 0
    }

    It 'reports an unreadable -Path instead of returning nothing' {
        $missing = Join-Path $script:root ('absent-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $f = @(Test-TcpkJavaSigning -Path $missing)
        $r = Get-Rule $f 'javasign.path-unreadable'
        $r.Count | Should -Be 1
        $r[0].Confidence | Should -Be 'Skipped'
    }
}

Describe 'Test-TcpkJavaSigning - unsigned in a non-writable directory' {
    It 'rates the unsigned archive MEDIUM when the directory refuses a write' -Skip:(-not $script:roProbeOk) {
        $f = @(Test-TcpkJavaSigning -Path $script:dirRo)
        $r = Get-Rule $f 'javasign.unsigned'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'MEDIUM'
        $r[0].Evidence | Should -Match 'writable by current user: no'
    }
}

Describe 'Test-TcpkJavaSigning - source hygiene' {
    It 'contains no em dash' {
        $src = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public/Discovery/Test-TcpkJavaSigning.ps1'
        $src | Should -Exist
        ([System.IO.File]::ReadAllText($src)).IndexOf([char]0x2014) | Should -Be -1
    }
}
