function Test-TcpkElectronUpdaterFeed {
<#
.SYNOPSIS
    A67. electron-updater / Squirrel.Windows auto-update feed audit. Parses the
    shipped update.yml / app-update.yml / dev-app-update.yml and the electron-builder
    publish config for an insecure update channel.

.DESCRIPTION
    electron-updater (the electron-builder auto-update stack) reads a feed config
    that ships INSIDE the app (resources\app-update.yml) and points at a release
    feed. The update path is the highest-value target in an Electron app: whoever
    controls the feed pushes signed-looking code to every install.

    Rules:
      update.electron-feed-plaintext      HIGH   Confirmed  The feed url / provider
                                                             endpoint is http://.
      update.electron-feed-generic-nopin  HIGH   Confirmed  provider: generic with no
                                                             publisherName / no channel
                                                             signature verification -
                                                             a generic HTTP(S) feed with
                                                             no code-signing identity to
                                                             pin means a compromised feed
                                                             host serves arbitrary code.
      update.electron-dev-update-shipped  MEDIUM Confirmed  dev-app-update.yml is
                                                             present in the release. It
                                                             overrides the real feed for
                                                             local testing and should
                                                             never ship.
      update.electron-no-publisher        MEDIUM Confirmed  The electron-builder win
                                                             config (or the shipped
                                                             update.yml) names no
                                                             publisherName, so
                                                             electron-updater cannot
                                                             verify the downloaded
                                                             installer's Authenticode
                                                             signer against an expected
                                                             identity.

.PARAMETER Path
    Install directory or a single update.yml / app-update.yml file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $ymlNames = @('app-update.yml','update.yml','dev-app-update.yml','latest.yml','latest-linux.yml','latest-mac.yml')

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $ymlNames -contains $_.Name.ToLowerInvariant() -and $_.Length -lt 65536 })
        } catch { return }
    } elseif ($ymlNames -contains $item.Name.ToLowerInvariant()) {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    foreach ($f in $files) {
        $text = ''
        try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $text) { continue }

        $isDev = ($f.Name -ieq 'dev-app-update.yml')

        # ---- update.electron-dev-update-shipped ------------------------------------
        if ($isDev) {
            New-TcpkFinding -Module 'discovery' -RuleId 'update.electron-dev-update-shipped' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title 'dev-app-update.yml shipped in the release' `
                -File $f.FullName -Evidence 'dev-app-update.yml present' `
                -Cwe @('CWE-1188','CWE-489') `
                -Description ('dev-app-update.yml overrides the production auto-update feed for local ' +
                    'development. Shipping it in a release means the app can be pointed at a developer feed ' +
                    '(often an http:// localhost or a staging host) that has weaker controls than production, ' +
                    'and it discloses the internal update-testing endpoint.') `
                -Fix 'Exclude dev-app-update.yml from the packaged build (electron-builder files config).'
        }

        # ---- update.electron-feed-plaintext ----------------------------------------
        $httpFeed = [regex]::Match($text, '(?im)^\s*(url|updaterCacheDirName|feedUrl|endpoint)\s*:\s*[''"]?(http://[^\s''"]+)')
        if (-not $httpFeed.Success) {
            $httpFeed = [regex]::Match($text, '(?i)(http://[a-z0-9][^\s''"]+)')
        }
        if ($httpFeed.Success) {
            $url = if ($httpFeed.Groups.Count -ge 3 -and $httpFeed.Groups[2].Value) { $httpFeed.Groups[2].Value } else { $httpFeed.Groups[1].Value }
            New-TcpkFinding -Module 'discovery' -RuleId 'update.electron-feed-plaintext' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "electron-updater feed over plaintext HTTP: $url" `
                -File $f.FullName -Evidence "url=$url" `
                -Cwe @('CWE-319','CWE-494') `
                -Description ('The electron-updater feed is served over plaintext HTTP. A network attacker on ' +
                    'the path substitutes the update manifest and the installer it points at. Even with an ' +
                    'Authenticode check on the downloaded installer, the manifest itself (version, sha512, ' +
                    'url) is unauthenticated over http, so a downgrade or a swap to an older signed-but-' +
                    'vulnerable release is possible.') `
                -Fix 'Serve the feed over HTTPS to a publisher-controlled host and set publisherName so the downloaded installer signature is verified against the expected identity.'
        }

        # ---- update.electron-feed-generic-nopin ------------------------------------
        # provider: generic + no publisherName -> a plain HTTP(S) directory feed with
        # no code-signing identity to pin.
        if ($text -match '(?im)^\s*provider\s*:\s*[''"]?generic\b') {
            $hasPublisher = ($text -match '(?im)^\s*publisherName\s*:')
            if (-not $hasPublisher) {
                New-TcpkFinding -Module 'discovery' -RuleId 'update.electron-feed-generic-nopin' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title 'electron-updater generic feed with no publisherName pin' `
                    -File $f.FullName -Evidence 'provider: generic; publisherName absent' `
                    -Cwe @('CWE-494','CWE-347') `
                    -Description ('The feed uses provider: generic (a plain directory of releases) and names no ' +
                        'publisherName. electron-updater verifies the downloaded installer Authenticode signer ' +
                        'against publisherName; without it, any installer the feed serves is accepted as long ' +
                        'as it is signed by ANY certificate (or, on some configs, at all). A compromised feed ' +
                        'host then serves attacker code that installs under the app identity.') `
                    -Fix 'Set publisherName in the electron-builder win config to the exact CN of your code-signing certificate so electron-updater pins the downloaded installer signer. Prefer a provider with its own integrity (GitHub releases, S3 with object-signing) over a bare generic feed.'
            }
        }

        # ---- update.electron-no-publisher (non-dev app-update.yml only) ------------
        if (-not $isDev -and $f.Name -ieq 'app-update.yml' -and $text -notmatch '(?im)^\s*publisherName\s*:') {
            New-TcpkFinding -Module 'discovery' -RuleId 'update.electron-no-publisher' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title 'electron-updater app-update.yml names no publisherName' `
                -File $f.FullName -Evidence 'publisherName absent from app-update.yml' `
                -Cwe @('CWE-347') `
                -Description ('The shipped app-update.yml declares no publisherName, so electron-updater cannot ' +
                    'verify the Authenticode signer of the downloaded installer against an expected identity ' +
                    'before running it.') `
                -Fix 'Add publisherName (your code-signing certificate CN) to the electron-builder win config so it is emitted into app-update.yml.'
        }
    }
}
