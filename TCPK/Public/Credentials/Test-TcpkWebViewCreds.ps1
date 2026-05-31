function Test-TcpkWebViewCreds {
<#
.SYNOPSIS
    D06. WebView2 Edge user profile -- saved login state.

.DESCRIPTION
    WebView2 hosts a full Chromium profile per app, stored under
    %LOCALAPPDATA%\Packages\<pkgFamilyName>\AC\Microsoft\Edge\User Data\
    (for packaged apps) or under app-controlled paths for non-packaged.

    The profile carries cookies, Login Data, Web Data SQLite stores --
    each holds credentials decryptable as the current user (DPAPI under
    EdgeMaster Key). If the auditor's target has WebView2 navigations to
    auth-bearing origins, those creds persist here.

.PARAMETER PackageFamilyName
    e.g. YourApp_xxxxxxxxxxxxx. Required for packaged apps.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageFamilyName)

    if (-not (Assert-TcpkWindows 'Test-TcpkWebViewCreds')) { return }

    $base = "$env:LOCALAPPDATA\Packages\$PackageFamilyName\AC\Microsoft\Edge\User Data"
    if (-not (Test-Path -LiteralPath $base)) { return }

    $targets = @(
        @{ Rel='Default\Login Data';    Title='Login Data (saved passwords)';        Sev='HIGH' },
        @{ Rel='Default\Web Data';      Title='Web Data (autofill / cards)';         Sev='MEDIUM' },
        @{ Rel='Default\Cookies';       Title='Cookies (session tokens)';            Sev='HIGH' },
        @{ Rel='Default\Network\Cookies'; Title='Cookies (session tokens, Network)'; Sev='HIGH' }
    )

    foreach ($t in $targets) {
        $full = Join-Path $base $t.Rel
        if (-not (Test-Path -LiteralPath $full)) { continue }
        $info = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
        if (-not $info -or $info.Length -lt 1024) { continue }

        New-TcpkFinding -Module 'creds' -RuleId 'webview2.profile-cred-store' `
            -Severity $t.Sev -Confidence 'Confirmed' `
            -Title "WebView2 Edge profile: $($t.Title)" `
            -File $full -Evidence "size=$($info.Length) modified=$($info.LastWriteTime)" `
            -Cwe @('CWE-522') `
            -Description 'Chromium-managed credential store next to the app. DPAPI-protected against other users but readable by any code running as the current user.' `
            -Fix 'For sensitive auth flows, consider clearing the WebView2 profile on logout (CoreWebView2.CookieManager.DeleteAllCookies, etc.).'
    }
}
