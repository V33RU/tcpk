function Test-TcpkBackendEndpoints {
<#
.SYNOPSIS
    F03. Inventory backend API endpoints + inferred auth model.

.DESCRIPTION
    Pulls every https:// URL out of first-party PEs, groups by host, and for
    each emits an INFO finding with auth-method markers found nearby in the
    binary (Bearer, Authorization, X-Api-Key, client_secret, etc.).
    Triage aid; severity is INFO across the board.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $urlRx = [regex]'https?://[A-Za-z0-9./?_=&%:#@~+\-]+'
    $authMarkers = @('Authorization','Bearer','X-Api-Key','client_secret','client_id','Basic ','Negotiate')

    $byHost = @{}
    $authsByHost = @{}

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name) { continue }   # bundled native runtimes are not the app's backends
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        # Skip the bundled Chromium runtime: its string table holds hundreds of built-in
        # search-engine / Google URLs that are not the app's backends (pure noise here).
        if (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) { continue }
        foreach ($m in $urlRx.Matches($text)) {
            try { $h = ([Uri]$m.Value).Host } catch { continue }
            if (-not $h) { continue }
            # stock-tool homepages baked into bundled helper binaries (NSIS stub, the stock
            # elevate.exe) are not the audited app's backends.
            if ($h -match '(?i)(microsoft|w3\.org|xmlsoap|schemas\.|github\.io|aka\.ms|gnu\.org|tools\.ietf|skiasharp|harfbuzz|wikipedia|json-schema|nuget|nsis\.sf\.net|sourceforge\.net|int3\.de)') { continue }
            if (-not $byHost.ContainsKey($h)) { $byHost[$h] = @{Count=0; SamplePe=$pe.FullName; SampleUrl=$m.Value} }
            $byHost[$h].Count++
        }
        foreach ($a in $authMarkers) {
            if ($text.Contains($a)) {
                # Crude: attribute auth markers to all hosts in this PE
                foreach ($u in $urlRx.Matches($text)) {
                    try { $h = ([Uri]$u.Value).Host } catch { continue }
                    if (-not $h) { continue }
                    if (-not $authsByHost.ContainsKey($h)) { $authsByHost[$h] = @{} }
                    $authsByHost[$h][$a] = $true
                }
            }
        }
    }

    foreach ($h in ($byHost.Keys | Sort-Object)) {
        $authList = if ($authsByHost.ContainsKey($h)) { ($authsByHost[$h].Keys | Sort-Object) -join ', ' } else { '(none in nearby PE)' }
        New-TcpkFinding -Module 'network' -RuleId 'backend.endpoint' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "Backend host: $h (URLs=$($byHost[$h].Count))" `
            -File $byHost[$h].SamplePe -Evidence "$($byHost[$h].SampleUrl)  | auth markers in same PE: $authList" `
            -Description 'Triage aid. Use the auth-marker list as a starting point for understanding how the app authenticates to this host.'
    }
}
