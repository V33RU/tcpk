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
