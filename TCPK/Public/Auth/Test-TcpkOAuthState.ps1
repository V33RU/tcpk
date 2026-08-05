function Test-TcpkOAuthState {
<#
.SYNOPSIS
    C35. OAuth 2.0 state parameter CSRF bypass and implicit flow detection.

.DESCRIPTION
    Scans source files (.cs, .vb, .java, .js, .ts) and configuration files
    (appsettings.json, App.config) for OAuth 2.0 implementation patterns that
    omit the state parameter, use the deprecated implicit flow, or mix
    state validation with a non-constant comparison.

    OAuth state parameter CSRF (CWE-352):
      The state parameter is the CSRF token for OAuth flows. If the client
      does not generate a cryptographically random state, include it in the
      authorization request, and verify the returned state in the callback,
      an attacker can craft an authorization URL, trick a victim into completing
      the flow, and bind the victim's account/token to the attacker's session.

    Checks:

    Source level (Confirmed when found):
      - Authorization URL construction with redirect_uri or client_id but no
        state parameter (or no call to a CSPRNG near the URL construction).
      - OAuth callback handler that reads the code parameter but does not read
        or compare the state parameter.
      - response_type=token (implicit flow, deprecated RFC 6749 S4.2, RFC 9700).

    Configuration level (Inferred):
      - MSAL (Microsoft.Identity.Client) AcquireTokenInteractive without
        WithState() / WithExtraQueryParameters containing state.
      - OpenIdConnect middleware configuration without ValidateState = true
        or SaveTokens combined with a missing anti-forgery mechanism.

.PARAMETER Path
    Root directory of the application to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkOAuthState')) { return }
    if (-not (Test-Path $Path)) { return }

    # ---- Source-level scan ----
    $srcFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include '*.cs','*.vb','*.java','*.js','*.ts' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 500)

    # Implicit flow marker: response_type=token  or  response_type=id_token token
    $implicitRx = '(?i)response_type\s*[=:]\s*[''"]?token(?:\s|[''"]|$)'

    # Authorization URL construction: redirect_uri or client_id keyword but NO "state"
    # on the same line or the next two lines.
    $authUrlRx   = '(?i)(redirect_uri|client_id|AuthorizationEndpoint|authorization_endpoint|GetAuthorizationUri|BuildAuthorizationUrl)'
    $statePresRx = '(?i)\bstate\b'

    # Callback handler: processes 'code' parameter from query string without 'state'
    $callbackCodeRx  = '(?i)(["'']code["'']|\.QueryString\[.+code|\.GetQueryStringValue\(.+code|Request\.Query\[.+code)'
    $callbackStateRx = '(?i)(["'']state["'']|\.QueryString\[.+state|\.GetQueryStringValue\(.+state|Request\.Query\[.+state)'

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        $lineCount = $lines.Count

        for ($i = 0; $i -lt $lineCount; $i++) {
            $line = $lines[$i]
            # Skip comment lines
            if ($line.TrimStart() -match '^(?://|#|/\*|\*|'')') { continue }

            # 1. Implicit flow
            if ($line -match $implicitRx) {
                $loc = "$($src.FullName):$($i+1)"
                if ($seen.Add("implicit|$loc")) {
                    New-TcpkFinding -Module 'auth' -RuleId 'oauth.implicit-flow' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "OAuth 2.0 implicit flow (response_type=token) in $($src.Name):$($i+1)" `
                        -File $src.FullName `
                        -Evidence "Line $($i+1): $($line.Trim())" `
                        -Cwe @('CWE-352','CWE-319') `
                        -Description ('response_type=token is the OAuth 2.0 implicit flow, deprecated ' +
                            'by RFC 9700 (OAuth 2.0 Security Best Current Practice). Tokens are ' +
                            'returned in the URL fragment, which is exposed to the browser history, ' +
                            'referrer headers, proxy logs, and any JavaScript running on the page. ' +
                            'No refresh token is issued. The implicit flow also has no mechanism to ' +
                            'prevent token injection into a different client session.') `
                        -Fix ('Replace with authorization code flow + PKCE (Proof Key for Code Exchange): ' +
                            'response_type=code, code_challenge_method=S256, code_challenge=<sha256(verifier)>. ' +
                            'The client then exchanges the code for a token at the token endpoint using ' +
                            'the code_verifier. This keeps tokens out of the URL entirely. ' +
                            'RFC 9700 Section 2.1.2.')
                }
            }

            # 2. Authorization URL construction without state
            if ($line -match $authUrlRx) {
                # Look at this line + next 4 lines for a state reference
                $window = @($line)
                for ($j = $i+1; $j -lt [Math]::Min($i+5, $lineCount); $j++) { $window += $lines[$j] }
                $windowText = $window -join ' '
                if ($windowText -notmatch $statePresRx) {
                    $loc = "$($src.FullName):$($i+1)"
                    if ($seen.Add("no-state|$loc")) {
                        New-TcpkFinding -Module 'auth' -RuleId 'oauth.missing-state' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed' `
                            -Title "OAuth authorization URL constructed without state parameter: $($src.Name):$($i+1)" `
                            -File $src.FullName `
                            -Evidence "Line $($i+1): $($line.Trim())" `
                            -Cwe @('CWE-352') `
                            -Description ('An OAuth authorization URL is being built (redirect_uri, ' +
                                'client_id, or authorization endpoint reference detected) but no ' +
                                '"state" parameter was found on this line or the next four lines. ' +
                                'The state parameter is the CSRF token for OAuth flows (RFC 6749 ' +
                                'Section 10.12). Without it, an attacker can send a victim a crafted ' +
                                'authorization URL, the victim authenticates, and the attacker''s ' +
                                'session receives the victim''s token. This leads to account takeover ' +
                                'or session fixation. Confirm by checking whether a state value is ' +
                                'generated elsewhere and appended to this URL construction.') `
                            -Fix ('Generate a cryptographically random state value before the ' +
                                'authorization redirect: var state = Convert.ToBase64String(' +
                                'RandomNumberGenerator.GetBytes(32)); ' +
                                'Store it in session/cookie, append to the authorization URL, and ' +
                                'in the callback handler verify Request.Query["state"] == storedState ' +
                                'before processing the code.')
                    }
                }
            }

            # 3. Callback handler reads 'code' but not 'state'
            if ($line -match $callbackCodeRx) {
                # Check same line + next 6 lines for state read
                $cbWindow = @($line)
                for ($j = $i+1; $j -lt [Math]::Min($i+7, $lineCount); $j++) { $cbWindow += $lines[$j] }
                if (($cbWindow -join ' ') -notmatch $callbackStateRx) {
                    $loc = "$($src.FullName):$($i+1)"
                    if ($seen.Add("callback-no-state|$loc")) {
                        New-TcpkFinding -Module 'auth' -RuleId 'oauth.callback-no-state-check' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed' `
                            -Title "OAuth callback reads 'code' but no 'state' validation seen: $($src.Name):$($i+1)" `
                            -File $src.FullName `
                            -Evidence "Line $($i+1): $($line.Trim())" `
                            -Cwe @('CWE-352') `
                            -Description ('The OAuth callback handler reads the code parameter from ' +
                                'the query string but no state parameter read or comparison was found ' +
                                'in the next few lines. If state is not validated against the value ' +
                                'generated at the start of the authorization flow, the callback is ' +
                                'vulnerable to CSRF: an attacker can trick a victim''s browser into ' +
                                'hitting this URL with the attacker''s authorization code, binding ' +
                                'the victim''s account to the attacker''s identity. Verify that state ' +
                                'validation exists elsewhere in the method or a middleware layer.') `
                            -Fix ('Before exchanging the code for a token, verify: ' +
                                'if (Request.Query["state"] != HttpContext.Session.GetString("oauth_state")) ' +
                                '{ return Unauthorized(); } ' +
                                'PKCE (code_verifier / code_challenge) does not replace state -- ' +
                                'it mitigates code interception, not CSRF.')
                    }
                }
            }
        }
    }

    # ---- Configuration: OpenIdConnect middleware ----
    $oidcConfigs = @(Get-ChildItem -Path $Path -Recurse `
                       -Include 'appsettings*.json','Startup.cs','Program.cs' -File `
                       -ErrorAction SilentlyContinue | Select-Object -First 20)
    foreach ($cfg in $oidcConfigs) {
        $content = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        if ($content -notmatch '(?i)(AddOpenIdConnect|OpenIdConnectOptions|AddAuthentication.*OpenIdConnect)') { continue }

        if ($content -match '(?i)ValidateAntiForgeryToken\s*=\s*false' -or
            $content -match '(?i)ValidateState\s*=\s*false' -or
            $content -match '(?i)DisableNonceValidation\s*=\s*true') {
            $m = [regex]::Match($content, '(?i)(ValidateAntiForgeryToken\s*=\s*false|ValidateState\s*=\s*false|DisableNonceValidation\s*=\s*true)')
            New-TcpkFinding -Module 'auth' -RuleId 'oauth.oidc-state-disabled' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "OpenIdConnect middleware has state/nonce validation disabled: $($cfg.Name)" `
                -File $cfg.FullName `
                -Evidence $m.Value `
                -Cwe @('CWE-352','CWE-346') `
                -Description ('The OpenIdConnect authentication middleware has state or nonce validation ' +
                    'explicitly disabled. State validation is the CSRF check that prevents an attacker ' +
                    'from completing a flow initiated for a different session. Nonce validation prevents ' +
                    'ID token replay. Disabling either removes a core OIDC security guarantee.') `
                -Fix ('Remove the ValidateState=false / ValidateAntiForgeryToken=false / ' +
                    'DisableNonceValidation=true setting. The ASP.NET Core OIDC middleware ' +
                    'handles state and nonce automatically when these settings are at their defaults.')
        }
    }
}
