function Test-TcpkNugetConfigCreds {
<#
.SYNOPSIS
    A62. Shipped nuget.config credential leak: `<packageSourceCredentials>` block contains
    a live username + password (or a base64-encoded password) for a private NuGet feed.

.DESCRIPTION
    A `nuget.config` under the install tree that carries a `<packageSourceCredentials>`
    block hands the operator a live credential to the vendor's private NuGet feed:

      <configuration>
        <packageSourceCredentials>
          <MyPrivateFeed>
            <add key="Username"          value="build-svc" />
            <add key="ClearTextPassword" value="hunter2" />
          </MyPrivateFeed>
        </packageSourceCredentials>
      </configuration>

    Two shapes:

      * `ClearTextPassword` - the credential is in the file verbatim. CRITICAL Confirmed.
      * `Password`          - the credential is encrypted with the Windows Data Protection
        API (DPAPI), reversible ONLY on the machine + user context that produced the
        nuget.config. HIGH Confirmed for shipping the encrypted blob (an attacker with
        machine access + the app's user context can dpapi-decrypt it), but not as
        catastrophic as a plaintext leak.

    Rules:
      supply.nuget.cleartext-password  CRITICAL  Confirmed  A `ClearTextPassword` value
                                                             is present in a shipped
                                                             nuget.config.
      supply.nuget.dpapi-password      HIGH      Confirmed  A `Password` value is present
                                                             - DPAPI-encrypted, only
                                                             reversible on the origin
                                                             machine+user, but shipped
                                                             regardless.
      supply.nuget.private-feed        LOW       Confirmed  A `<packageSources>` entry
                                                             names a non-nuget.org URL
                                                             (`https://vendor.internal/`)
                                                             without credentials, i.e. the
                                                             app depends on a private
                                                             feed at runtime. Inventory
                                                             only; helpful scope info.

.PARAMETER Path
    Install directory or a single nuget.config file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -match '^(?i)(nuget\.config|packages\.config|\.nuget[\\/]nuget\.config)$' -and $_.Length -lt 524288 })
        } catch { return }
        # Filename match is case-insensitive but the regex missed patterns like `NuGet.Config`
        # with mixed case AND a subfolder root; add a broader sweep.
        try {
            $files += @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '(?i)^nuget\.config$' -and $_.Length -lt 524288 -and $_ -notin $files })
        } catch { }
        $files = $files | Select-Object -Unique
    } elseif ($item.Name -match '(?i)^nuget\.config$') {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    foreach ($f in $files) {
        $doc = New-Object System.Xml.XmlDocument
        try { $doc.Load($f.FullName) } catch { continue }
        $root = $doc.DocumentElement
        if (-not $root -or $root.LocalName -ne 'configuration') { continue }

        # ---- packageSourceCredentials ----------------------------------------------
        # Structure:
        #   <configuration>
        #     <packageSourceCredentials>
        #       <FeedName>
        #         <add key="Username" value="..." />
        #         <add key="ClearTextPassword" value="..." />   (or <add key="Password" .../>)
        #       </FeedName>
        #     </packageSourceCredentials>
        $psc = $root.SelectSingleNode('packageSourceCredentials')
        if ($psc) {
            foreach ($feed in $psc.ChildNodes) {
                if ($feed.NodeType -ne 'Element') { continue }
                $feedName = $feed.LocalName
                $user = ''
                foreach ($add in $feed.SelectNodes('add')) {
                    $k = "$($add.GetAttribute('key'))"
                    if ($k -eq 'Username') { $user = "$($add.GetAttribute('value'))" }
                }
                foreach ($add in $feed.SelectNodes('add')) {
                    $k = "$($add.GetAttribute('key'))"
                    $v = "$($add.GetAttribute('value'))"
                    if ($k -eq 'ClearTextPassword') {
                        if (-not $v -or $v -match '^\s*(\$\{|%[A-Z_]+%|placeholder|todo|changeme|xxx+)') { continue }
                        $masked = if ($v.Length -le 2) { '***' } else { $v.Substring(0,1) + '***' + $v.Substring($v.Length-1,1) }
                        New-TcpkFinding -Module 'discovery' -RuleId 'supply.nuget.cleartext-password' `
                            -Severity 'CRITICAL' -Confidence 'Confirmed' `
                            -Title "$($f.Name) ships a plaintext NuGet feed password (feed=$feedName, user=$user)" `
                            -File $f.FullName -Evidence "<$feedName><add key='ClearTextPassword' value='$masked'/></$feedName>" `
                            -Cwe @('CWE-798','CWE-312') `
                            -Description ('A `nuget.config` in the install tree carries a `ClearTextPassword` for a ' +
                                'private NuGet feed. Any installer holder can restore packages under this credential, ' +
                                'push malicious packages if the account has publish rights, and (depending on the ' +
                                'feed provider) enumerate the vendor''s private package inventory. Shipped credentials ' +
                                'are permanent - they cannot be rotated by the vendor without breaking every install.') `
                            -Fix 'Delete the packageSourceCredentials block from the shipped nuget.config. Feed authentication should live in the developer''s user-scoped %APPDATA%\NuGet\NuGet.Config, or be injected by the CI pipeline at pack time (dotnet nuget add source ... --username ... --password ... --store-password-in-clear-text false).'
                    }
                    elseif ($k -eq 'Password') {
                        if (-not $v) { continue }
                        $sample = $v.Substring(0, [Math]::Min(24, $v.Length)) + '...'
                        New-TcpkFinding -Module 'discovery' -RuleId 'supply.nuget.dpapi-password' `
                            -Severity 'HIGH' -Confidence 'Confirmed' `
                            -Title "$($f.Name) ships a DPAPI-encrypted NuGet feed password (feed=$feedName, user=$user)" `
                            -File $f.FullName -Evidence "<$feedName><add key='Password' value='$sample'/></$feedName>" `
                            -Cwe @('CWE-798','CWE-321') `
                            -Description ('The password is stored using the Windows Data Protection API and is ' +
                                'reversible ONLY on the machine + user context that produced this nuget.config. ' +
                                'Lower severity than ClearTextPassword because a random installer holder cannot ' +
                                'directly decrypt the value, but: (a) if the file was produced on a build agent ' +
                                'that also produced the shipping binaries, and (b) any tester has code execution ' +
                                'in that user context, DPAPI unprotect returns the plaintext. Do not treat as ' +
                                'safe just because it is not plaintext.') `
                            -Fix 'Do not ship a machine-bound credential. See the ClearTextPassword fix; the same guidance applies.'
                    }
                }
            }
        }

        # ---- private-feed inventory (LOW) -------------------------------------------
        # A packageSources entry that is NOT the default nuget.org (or its GitHub Packages
        # equivalent for OSS) tells the tester the app depends on a private feed at runtime.
        $ps = $root.SelectSingleNode('packageSources')
        if ($ps) {
            foreach ($add in $ps.SelectNodes('add')) {
                $key   = "$($add.GetAttribute('key'))"
                $value = "$($add.GetAttribute('value'))"
                if (-not $value) { continue }
                if ($value -match '(?i)https?://api\.nuget\.org/') { continue }   # default
                if ($value -match '(?i)https?://[^/]+/nuget/v3/index\.json' -and $value -match '(?i)nuget\.org') { continue }
                New-TcpkFinding -Module 'discovery' -RuleId 'supply.nuget.private-feed' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "$($f.Name) declares a private NuGet feed: $key -> $value" `
                    -File $f.FullName -Evidence "<packageSources><add key='$key' value='$value'/></packageSources>" `
                    -Cwe @('CWE-1104') `
                    -Description ('The app depends on a non-nuget.org NuGet feed at build / restore time. This is ' +
                        'inventory information for the tester: the private feed is now part of the supply chain ' +
                        'the vendor trusts (its uptime, its ACL, whoever can publish to it). Not a defect on its ' +
                        'own; combine with supply.nuget.cleartext-password if the same file also ships credentials.') `
                    -Fix 'No fix required. Track the private feed in the SBOM and monitor its authentication policy.'
            }
        }
    }
}
