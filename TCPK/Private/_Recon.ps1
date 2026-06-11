# Recon helpers: normalize + classify the endpoints the audit surfaced, so the recon
# profile shows WHO the app talks to and HOW (first-party backend vs telemetry vs cloud
# storage vs CDN vs auth/update), with risk flags (cleartext, raw IP, private/internal,
# non-prod). Pure post-processing of data already collected -- no new collection.

# Classify a single endpoint host/URL. Returns Host / Scheme / Cleartext / Category / Flags.
function Get-TcpkEndpointInfo {
    [CmdletBinding()]
    param([string]$HostName, [string]$Raw)

    $text = ("$Raw $HostName").ToLowerInvariant()
    $scheme = 'https'; $cleartext = $false
    if     ($text -match 'http://')  { $scheme = 'http'; $cleartext = $true }
    elseif ($text -match 'ws://')    { $scheme = 'ws';   $cleartext = $true }
    elseif ($text -match 'wss://')   { $scheme = 'wss' }
    elseif ($text -match 'https://') { $scheme = 'https' }

    # bare host: strip scheme + any path/port
    $h = ("$HostName").ToLowerInvariant() -replace '^[a-z][a-z0-9+.\-]*://','' -replace '[/:].*$',''

    $flags = New-Object 'System.Collections.Generic.List[string]'
    if ($cleartext) { [void]$flags.Add('cleartext') }
    if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') {
        [void]$flags.Add('raw-ip')
        if ($h -match '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { [void]$flags.Add('private-ip') }
    }
    if ($h -eq 'localhost' -or $h -eq '::1' -or $h -match '\.(local|internal|corp|lan|intranet)$') { [void]$flags.Add('internal') }
    if ($h -match '(^|[.\-])(dev|stage|staging|qa|uat|test|sandbox|preprod)([.\-]|$)') { [void]$flags.Add('non-prod') }

    $cat = 'first-party'
    if     ($h -match 'blob\.core\.windows\.net|s3\.amazonaws|\.s3[.\-]|storage\.googleapis|\.blob\.|digitaloceanspaces|backblazeb2') { $cat = 'cloud-storage' }
    elseif ($h -match 'sentry|segment\.(io|com)|google-analytics|googletagmanager|mixpanel|amplitude|bugsnag|datadoghq|newrelic|crashlytics|app-measurement|fullstory|hotjar|rollbar|matomo') { $cat = 'telemetry' }
    elseif ($h -match 'login\.microsoftonline|login\.live|sts\.|auth0\.com|okta\.com|accounts\.google|oauth|identity') { $cat = 'auth' }
    elseif ($h -match '(^|\.)cdn\.|jsdelivr|cloudflare|akamai|unpkg|fonts\.(googleapis|gstatic)|fastly|cloudfront') { $cat = 'cdn' }
    elseif ($h -match 'update|releases?|download|dl\.') { $cat = 'update' }

    [pscustomobject]@{
        Host = $HostName; Scheme = $scheme; Cleartext = $cleartext; Category = $cat; Flags = @($flags)
    }
}

# Build a deduped, classified map (one row per host) from the enriched endpoint records.
function Get-TcpkEndpointMap {
    [CmdletBinding()]
    param([object[]]$Endpoints = @())
    if (-not $Endpoints.Count) { return ,@() }
    $map = @($Endpoints | Group-Object Host | ForEach-Object {
        $g = $_.Group
        [pscustomobject]@{
            Host      = $_.Name
            Category  = ($g | Where-Object Category | Select-Object -First 1 -ExpandProperty Category)
            Schemes   = (@($g | ForEach-Object { $_.Scheme } | Where-Object { $_ } | Sort-Object -Unique) -join ',')
            Cleartext = [bool](@($g | Where-Object { $_.Cleartext }).Count)
            Flags     = @(@($g | ForEach-Object { $_.Flags } | Where-Object { $_ } | Sort-Object -Unique))
            Files     = @(@($g | ForEach-Object { $_.File } | Where-Object { $_ } | Sort-Object -Unique))
            Count     = $g.Count
        }
    })
    return ,@($map)
}
