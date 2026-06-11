# JavaScript text helpers for the Electron / web-bundle checks.
#
# Get-TcpkJsCodeOnly strips JS comments BEFORE config-flag detection, so a flag that
# only appears in a comment ("// we deliberately avoid webSecurity:false") no longer
# fires a finding -- the false-positive class found reviewing a real Electron app.
# URL-safe: '//' inside http:// / https:// / ws:// (preceded by ':') is NOT treated
# as a comment and is preserved, so config on the same line as a URL is not lost.
function Get-TcpkJsCodeOnly {
    [CmdletBinding()]
    param([string]$Js)
    if (-not $Js) { return '' }
    $s = [regex]::Replace($Js, '/\*[\s\S]*?\*/', ' ')          # block comments  /* ... */
    $s = [regex]::Replace($s, '(?m)(?<![:/])//[^\r\n]*', ' ')   # line comments // (but not '://')
    return $s
}

# True if a webPreferences / BrowserWindow / BrowserView / webContents context appears
# in the window of code immediately BEFORE $Index -- used to tell a real renderer-config
# flag from a bare 'key: false' in prose or an unrelated options object.
function Test-TcpkWebPrefsContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Code, [Parameter(Mandatory)][int]$Index, [int]$Window = 500)
    if ($Index -le 0) { return $false }
    $start = [Math]::Max(0, $Index - $Window)
    $ctx = $Code.Substring($start, $Index - $start)
    return [regex]::IsMatch($ctx, '(?i)(webPreferences|new\s+BrowserWindow|new\s+BrowserView|webContents)')
}
