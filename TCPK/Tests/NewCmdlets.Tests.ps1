#requires -Version 5.1
# Pester 5 tests for the cmdlets added in v1.7 (batches A-D + deliverables).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK\TCPK.psd1'
    if (-not (Test-Path $psd1)) { $psd1 = 'C:\Users\admin\Desktop\TCPK\TCPK\TCPK.psd1' }
    Import-Module $psd1 -Force
    try { Disable-TcpkExploit | Out-Null } catch {}   # ensure gate OFF for the throw tests

    $script:fx = Join-Path $env:TEMP ('tcpk-pester-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # appsettings.json: one digit-bearing high-entropy key (should flag),
    # one pure-alpha identifier (must NOT flag), one sha256 integrity (must NOT flag)
    @'
{
  "EncryptionKey": "a8F3kQ9mZ2pL7xR4tB1cW6sY0dN5eUq",
  "NodeName": "InstallerSettingsSearchTreeNodeInfoProvider",
  "integrity": "sha256-9b74c9897bac770ffc029102a200c5de"
}
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'appsettings.json') -Encoding UTF8

    # deps.json: must be skipped entirely by entropy + crypto hunters
    @'
{ "Secret": "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWo=" }
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'App.deps.json') -Encoding UTF8

    # cleartext PEM private key
    @'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0123456789abcdefghijklmnopqrstuvwxyzFAKEKEYDATA
-----END RSA PRIVATE KEY-----
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'server.key') -Encoding UTF8

    # JWT with alg=none
    $b64u = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+','-').Replace('/','_') }
    $jwt = "$(& $b64u '{"alg":"none","typ":"JWT"}').$(& $b64u '{"sub":"admin","role":"root"}')."
    "token=$jwt" | Set-Content -LiteralPath (Join-Path $script:fx 'tokens.txt') -Encoding UTF8

    # a real PE for the SBOM test
    Copy-Item "$env:WINDIR\System32\version.dll" (Join-Path $script:fx 'version.dll') -Force
}

AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'v1.7 cmdlets are exported' {
    $names = @(
        'Test-TcpkEntropySecrets','Test-TcpkCryptoMisuse','Test-TcpkJwt','Test-TcpkKeyMaterial',
        'Test-TcpkTrustStore','Test-TcpkSelfHostedServer','Test-TcpkZipSlip','Test-TcpkDebugFlags',
        'Test-TcpkFirewallRules','Test-TcpkAvExclusions','Test-TcpkServiceBinaryAcl','Test-TcpkProcessDacl',
        'Get-TcpkAttackSurface','Export-TcpkSbom','Test-TcpkMemorySecrets','Test-TcpkProcessEnvSecrets',
        'Invoke-TcpkMemoryFlagFlip','Invoke-TcpkGuiUnlock','Invoke-TcpkPipeProbe','Invoke-TcpkInputFuzz'
    )
    It '<_> is available' -ForEach $names {
        Get-Command $_ -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Static hunters - true positives + FP guards' {
    It 'EntropySecrets flags the key but NOT the identifier/integrity, and skips deps.json' {
        $r = @(Test-TcpkEntropySecrets -Path $script:fx)
        ($r | Where-Object { $_.File -like '*appsettings.json' }).Count | Should -Be 1
        ($r | Where-Object { $_.File -like '*deps.json' }).Count       | Should -Be 0
    }
    It 'CryptoMisuse flags the hardcoded key material' {
        $r = @(Test-TcpkCryptoMisuse -Path $script:fx)
        ($r | Where-Object { $_.RuleId -eq 'crypto.hardcoded-key-material' }).Count | Should -BeGreaterThan 0
    }
    It 'Jwt finds the alg=none token as CRITICAL' {
        $r = @(Test-TcpkJwt -Path $script:fx)
        $j = $r | Where-Object { $_.RuleId -eq 'jwt.embedded-token' } | Select-Object -First 1
        $j | Should -Not -BeNullOrEmpty
        $j.Severity | Should -Be 'CRITICAL'
    }
    It 'KeyMaterial flags the cleartext PEM private key as HIGH' {
        $r = @(Test-TcpkKeyMaterial -Path $script:fx)
        $k = $r | Where-Object { $_.RuleId -eq 'keymaterial.pem-cleartext-key' } | Select-Object -First 1
        $k | Should -Not -BeNullOrEmpty
        $k.Severity | Should -Be 'HIGH'
    }
    It 'ZipSlip / DebugFlags / SelfHostedServer run without throwing' {
        { Test-TcpkZipSlip -Path $script:fx }          | Should -Not -Throw
        { Test-TcpkDebugFlags -Path $script:fx }       | Should -Not -Throw
        { Test-TcpkSelfHostedServer -Path $script:fx } | Should -Not -Throw
    }
}

Describe 'Host-footprint hunters run clean' {
    It 'FirewallRules / AvExclusions / ServiceBinaryAcl / TrustStore do not throw' {
        { Test-TcpkFirewallRules -NameLike 'TcpkNoSuchVendor' }   | Should -Not -Throw
        { Test-TcpkAvExclusions  -NameLike 'TcpkNoSuchVendor' }   | Should -Not -Throw
        { Test-TcpkServiceBinaryAcl -NameLike 'TcpkNoSuchSvc' }   | Should -Not -Throw
        { Test-TcpkTrustStore -NameLike 'TcpkNoSuchVendor' -Path $script:fx } | Should -Not -Throw
    }
}

Describe 'Deliverables' {
    It 'Get-TcpkAttackSurface returns a ranked map' {
        $surface = & (Get-Module TCPK) {
            $f = @()
            $f += New-TcpkFinding -Module os      -RuleId 'firewall.inbound-allow' -Severity HIGH -Title 'in'
            $f += New-TcpkFinding -Module runtime -RuleId 'namedpipe.dacl'          -Severity MEDIUM -Title 'pipe'
            $f | Get-TcpkAttackSurface
        }
        $surface.TotalEntryPoints | Should -BeGreaterThan 0
        @($surface.Categories).Count | Should -BeGreaterThan 0
    }
    It 'Export-TcpkSbom writes a valid CycloneDX BOM' {
        $out = Join-Path $script:fx 'sbom.cdx.json'
        Export-TcpkSbom -Path $script:fx -OutFile $out | Out-Null
        Test-Path $out | Should -BeTrue
        $bom = Get-Content $out -Raw | ConvertFrom-Json
        $bom.bomFormat | Should -Be 'CycloneDX'
        @($bom.components).Count | Should -BeGreaterThan 0
    }
    It 'ATT&CK mapping resolves a known rule' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackText 'truststore.app-installed-cert' }
        $t | Should -Match 'T1553'
    }
}

Describe 'Read-only live tools do not throw (self process)' {
    It 'ProcessDacl / ProcessEnvSecrets / MemorySecrets run against the current PID' {
        { Test-TcpkProcessDacl       -ProcessId $PID }               | Should -Not -Throw
        { Test-TcpkProcessEnvSecrets -ProcessId $PID }               | Should -Not -Throw
        { Test-TcpkMemorySecrets     -ProcessId $PID -MaxScanMB 16 } | Should -Not -Throw
    }
}

Describe 'Gated cmdlets refuse without Enable-TcpkExploit' {
    It '<_> throws a gate error' -ForEach @(
        'Invoke-TcpkPipeProbe','Invoke-TcpkGuiUnlock','Invoke-TcpkMemoryFlagFlip','Invoke-TcpkInputFuzz'
    ) {
        $cmd = $_
        $sb = switch ($cmd) {
            'Invoke-TcpkPipeProbe'      { { Invoke-TcpkPipeProbe -PipeName 'x' } }
            'Invoke-TcpkGuiUnlock'      { { Invoke-TcpkGuiUnlock -ProcessId $PID } }
            'Invoke-TcpkMemoryFlagFlip' { { Invoke-TcpkMemoryFlagFlip -ProcessId $PID -Pattern 'x' -NewBytesHex '01' } }
            'Invoke-TcpkInputFuzz'      { { Invoke-TcpkInputFuzz -TargetExe 'x.exe' -SeedFile 'y' } }
        }
        $sb | Should -Throw -ExpectedMessage '*gated*'
    }
}
