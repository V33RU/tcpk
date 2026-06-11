#requires -Version 5.1
# Recon improvement #2: endpoints are normalized + classified (first-party / telemetry /
# cloud-storage / cdn / auth / update) with risk flags (cleartext, raw-ip, private-ip,
# internal, non-prod), deduped into an EndpointMap, and the classification is folded into
# the endpoint Detail so existing report tables show it.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-recon-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    $script:Info = { param($hn,$raw) & (Get-Module TCPK) { param($h,$r) Get-TcpkEndpointInfo -HostName $h -Raw $r } $hn $raw }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Get-TcpkEndpointInfo classification' {
    It 'classifies telemetry hosts'      { (& $script:Info 'o123.ingest.sentry.io' 'https://o123.ingest.sentry.io').Category | Should -Be 'telemetry' }
    It 'classifies cloud storage'        { (& $script:Info 'acme.blob.core.windows.net' 'https://acme.blob.core.windows.net/x').Category | Should -Be 'cloud-storage' }
    It 'first-party by default'          { (& $script:Info 'api.acme-internal-product.com' 'https://api.acme-internal-product.com').Category | Should -Be 'first-party' }
    It 'detects cleartext + http scheme' {
        $i = & $script:Info 'api.example.com' 'http://api.example.com/v1'
        $i.Cleartext | Should -BeTrue; $i.Scheme | Should -Be 'http'; $i.Flags | Should -Contain 'cleartext'
    }
    It 'flags a raw private IP' {
        $i = & $script:Info '10.0.0.5' 'http://10.0.0.5/api'
        $i.Flags | Should -Contain 'raw-ip'; $i.Flags | Should -Contain 'private-ip'
    }
    It 'flags non-prod hosts' { (& $script:Info 'staging.api.example.com' 'https://staging.api.example.com').Flags | Should -Contain 'non-prod' }
}

Describe 'EndpointMap in the target profile' {
    BeforeAll {
        $script:prof = & (Get-Module TCPK) { param($dir)
            $f = @(
                New-TcpkFinding -Module 'network' -RuleId 'backend.endpoint' -Severity 'INFO' -Confidence 'Inferred' -Title 'Backend host: o9.ingest.sentry.io' -Evidence 'https://o9.ingest.sentry.io/api/store' -File 'app.dll'
                New-TcpkFinding -Module 'network' -RuleId 'backend.endpoint' -Severity 'LOW'  -Confidence 'Inferred' -Title 'Backend host: 10.0.0.5' -Evidence 'http://10.0.0.5/telemetry' -File 'core.dll'
            )
            Get-TcpkTargetProfile -Path $dir -Findings $f
        } $script:work
    }
    It 'builds a deduped, classified EndpointMap' {
        $m = @($script:prof.EndpointMap)
        $m.Count | Should -BeGreaterThan 0
        ($m | Where-Object { $_.Host -eq 'o9.ingest.sentry.io' }).Category | Should -Be 'telemetry'
        ($m | Where-Object { $_.Host -eq '10.0.0.5' }).Cleartext         | Should -BeTrue
    }
    It 'folds the classification tag into the endpoint Detail' {
        ($script:prof.Endpoints | Where-Object { $_.Host -eq '10.0.0.5' }).Detail | Should -Match 'cleartext'
    }
}
