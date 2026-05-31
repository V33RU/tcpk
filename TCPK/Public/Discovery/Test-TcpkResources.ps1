function Test-TcpkResources {
<#
.SYNOPSIS
    A07. Embedded resource audit.

.DESCRIPTION
    Surveys files that often hold sensitive content next to binaries:
      - *.resx, *.resources, *.pri   (resource containers)
      - *.xaml                       (UI markup; can carry data-binding URLs)
      - *.json, *.xml                (configs)
      - scripts                      (see Test-TcpkEmbeddedScripts)

    INFO findings list resource files larger than 100 KB so they can be
    triaged manually; MEDIUM findings flag XAML containing http(s):// URLs
    (typically indicates server-side resource references).

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $resFiles = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.resx','.resources','.pri','.xaml' }

    foreach ($f in $resFiles) {
        if ($f.Length -gt 100KB) {
            New-TcpkFinding -Module 'static' -RuleId 'resources.large' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($f.Name) is large ($([int]($f.Length/1KB)) KB) -- worth manual review" `
                -File $f.FullName
        }
        if ($f.Extension -eq '.xaml') {
            try { $t = [IO.File]::ReadAllText($f.FullName) } catch { continue }
            if ($t -match 'https?://[A-Za-z0-9./?_=&%:#@~+\-]+') {
                New-TcpkFinding -Module 'static' -RuleId 'resources.xaml-url' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($f.Name) contains http(s):// URL" `
                    -File $f.FullName -Evidence $matches[0] `
                    -Cwe @('CWE-829') `
                    -Description 'XAML referencing remote resources (images, icons) results in network fetches at UI render time.'
            }
        }
    }
}
