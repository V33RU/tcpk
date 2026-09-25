# HTML escaping helper for the report generators.

function ConvertTo-TcpkHtmlSafe {
    [CmdletBinding()] param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text -replace '&','&amp;' `
          -replace '<','&lt;' `
          -replace '>','&gt;' `
          -replace '"','&quot;' `
          -replace "'",'&#39;'
}

# Brand logo for the standalone HTML reports.
#
# Every report generator writes ONE self-contained .html that gets mailed around or
# dropped in a ticket, so a <img src='assets/...'> would break the moment the file
# moves. The logo is therefore inlined as a data URI. tcpk-logo.png is 1000x300 and
# ~14 KB, so the base64 adds ~19 KB to a report -- irrelevant next to the findings.
#
# Encoding is done once per process and cached: Export-TcpkReportIntel and the agentic
# workbench can both run in a single session, and re-reading plus re-encoding the file
# each time is pure waste.
#
# Returns '' if the asset is missing (a module copied without assets\ still produces a
# valid report, just without the mark). Callers must treat '' as "no logo", never as
# an error.
function Get-TcpkBrandLogoTag {
    [CmdletBinding()]
    param(
        # Rendered height in CSS pixels. The source is 1000x300, so width follows at 10:3.
        [int]$Height = 44,
        # Extra CSS appended to the style attribute (margins, alignment).
        [string]$Style = '',
        # Asset file name under assets\. tcpk-logo.png is the wordmark; tcpk-mark.png is
        # the square icon for tight headers that already print the product name in text.
        [ValidateSet('tcpk-logo.png','tcpk-mark.png','tcpk-badge.png')]
        [string]$Asset = 'tcpk-logo.png'
    )

    # Explicit null test, not -not: the truthiness of an empty hashtable is the kind
    # of 5.1 detail that silently turns the cache into a no-op.
    if ($null -eq $script:TcpkLogoB64Cache) { $script:TcpkLogoB64Cache = @{} }

    if (-not $script:TcpkLogoB64Cache.ContainsKey($Asset)) {
        $b64 = ''
        try {
            $assetDir = Join-Path (Split-Path $script:TcpkRoot -Parent) 'assets'
            $assetPath = Join-Path $assetDir $Asset
            if (Test-Path -LiteralPath $assetPath) {
                $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($assetPath))
            }
        } catch {
            # A locked or unreadable asset must not take the whole report down.
            $b64 = ''
        }
        $script:TcpkLogoB64Cache[$Asset] = $b64
    }

    $b64 = $script:TcpkLogoB64Cache[$Asset]
    if (-not $b64) { return '' }

    $css = "height:${Height}px;width:auto"
    if ($Style) { $css = $css + ';' + $Style }

    # Attributes are DOUBLE-quoted on purpose. Export-TcpkReportIntel builds its header
    # inside a single-quoted JavaScript string, so a single-quoted attribute here would
    # terminate that string. Base64 itself contains only A-Za-z0-9+/= so it is safe in
    # both, and every PowerShell call site interpolates this into an @" here-string
    # where a double quote is not a terminator.
    '<img alt="TCPK" style="' + $css + '" src="data:image/png;base64,' + $b64 + '">'
}
