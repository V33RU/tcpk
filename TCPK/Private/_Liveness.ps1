# Credential-liveness engine for Test-TcpkCredentialLiveness. Given a credential recovered
# by TCPK (Invoke-TcpkSecretRecovery) or observed on the wire (Invoke-TcpkIntercept), it
# proves the credential actually AUTHENTICATES to a live service -- turning a recovered
# secret into demonstrated impact. Active by nature (it makes one real auth attempt); the
# public cmdlet gates it (Enable-TcpkExploit + -ConfirmActive). Authorized targets only.

# One HTTP GET, returning the status code (0 on a connection error). No redirects followed
# so a 401 is not masked by a login-page redirect to 200.
function Invoke-TcpkHttpProbe {
    param([string]$Url, [string]$Username, [string]$Password, [string]$BearerToken, [int]$TimeoutSec = 15)
    $handler = [System.Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url)
        if ($BearerToken) {
            $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $BearerToken)
        } elseif ($Username -or $Password) {
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $Username, $Password)))
            $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Basic', $b64)
        }
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        return [int]$resp.StatusCode
    } catch { return 0 } finally { $client.Dispose() }
}

# HTTP liveness by COMPARISON, to avoid a false positive on an unprotected URL: probe the
# URL WITHOUT the credential, then WITH it. The credential is proven only when the anonymous
# request is rejected (401/403) and the authenticated request is accepted (2xx/3xx).
function Test-TcpkHttpAuth {
    param([string]$Url, [string]$Username, [string]$Password, [string]$BearerToken, [int]$TimeoutSec = 15)
    $anon = Invoke-TcpkHttpProbe -Url $Url -TimeoutSec $TimeoutSec
    $auth = Invoke-TcpkHttpProbe -Url $Url -Username $Username -Password $Password -BearerToken $BearerToken -TimeoutSec $TimeoutSec
    if ($auth -eq 0) { return @{ ok = $false; verdict = 'error'; detail = "no HTTP response from $Url" } }
    if ($anon -in 401, 403 -and $auth -ge 200 -and $auth -lt 400) {
        return @{ ok = $true; verdict = 'authenticated'; detail = "anonymous=$anon, with credential=$auth (the credential unlocked the resource)" }
    }
    if ($auth -in 401, 403) { return @{ ok = $false; verdict = 'rejected'; detail = "the service rejected the credential (HTTP $auth)" } }
    return @{ ok = $false; verdict = 'inconclusive'; detail = "the resource is not credential-gated (anonymous=$anon, with credential=$auth)" }
}

# SQL Server liveness: open a connection with the credential. Uses whichever SqlClient the
# host has (Microsoft.Data.SqlClient preferred, then System.Data.SqlClient). Returns a
# 'no-client' verdict when neither is present (e.g. a stripped runtime) rather than failing.
function Test-TcpkSqlAuth {
    param([string]$Server, [string]$Database, [string]$Username, [string]$Password, [int]$TimeoutSec = 15)
    $db = if ($Database) { $Database } else { 'master' }
    $cs = "Server=$Server;Database=$db;User ID=$Username;Password=$Password;Connect Timeout=$TimeoutSec;TrustServerCertificate=True;Encrypt=True"
    foreach ($tn in 'Microsoft.Data.SqlClient.SqlConnection', 'System.Data.SqlClient.SqlConnection') {
        $t = $tn -as [type]
        if (-not $t) { continue }
        $conn = $null
        try { $conn = $t::new($cs); $conn.Open(); return @{ ok = $true; verdict = 'authenticated'; detail = "opened a SQL connection to $Server as $Username" } }
        catch { return @{ ok = $false; verdict = 'rejected'; detail = "SQL rejected the credential: $(("$($_.Exception.Message)" -split "`n")[0])" } }
        finally { if ($conn) { try { $conn.Dispose() } catch { } } }
    }
    return @{ ok = $false; verdict = 'no-client'; detail = 'no .NET SqlClient on this host; run the SQL liveness check where Microsoft.Data.SqlClient is available' }
}

# FTP liveness: attempt a directory listing with the credential.
function Test-TcpkFtpAuth {
    param([string]$Url, [string]$Username, [string]$Password, [int]$TimeoutSec = 15)
    try {
        $req = [System.Net.FtpWebRequest]::Create($Url)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $req.Credentials = [System.Net.NetworkCredential]::new($Username, $Password)
        $req.Timeout = $TimeoutSec * 1000
        $resp = $req.GetResponse(); $resp.Close()
        return @{ ok = $true; verdict = 'authenticated'; detail = "FTP login accepted at $Url as $Username" }
    } catch [System.Net.WebException] {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        return @{ ok = $false; verdict = 'rejected'; detail = "FTP rejected the credential (status $code)" }
    } catch { return @{ ok = $false; verdict = 'error'; detail = "FTP error: $(("$($_.Exception.Message)" -split "`n")[0])" } }
}
