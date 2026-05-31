# Per-finding manual re-validation playbook. For each finding returns:
#   line 1: a copy-paste-RUNNABLE command (or a '#' note for manual steps)
#   line 2: '# -> VULNERABLE if <X>;  OK if <Y>'  (how to read the output)
#
# Every returned string is paste-safe: line 1 runs, line 2 is a comment.
# Used by both the HTML and Excel reports.

function Get-TcpkVerifyHint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [string]$File,
        [string]$Evidence
    )

    $f   = if ($File) { $File } else { '<file>' }
    $dir = if ($File) { Split-Path -Parent $File } else { '<install-dir>' }
    $hostName = if ($Evidence -match 'https?://([^/\s|]+)') { $matches[1] } else { '<host>' }
    $nl  = "`r`n"

    $h = switch -Regex ($RuleId) {

        '^pe\.missing-mitigations' {
            "Get-TcpkPeHardening -Path '$f'$nl# -> VULNERABLE if ASLR or DEP = NO;  OK if all four (ASLR/DEP/CFG/HighEntropyVA) = YES   [tool: PowerShell, or: dumpbin /headers]"
        }
        '^pe-imports\.' {
            "dumpbin /imports '$f'$nl# -> VULNERABLE if a listed DLL can resolve from a user-writable dir (DLL planting);  OK if all bind from System32/the app dir   [tool: Visual Studio dumpbin]"
        }
        '^pe-exports\.' {
            "dumpbin /exports '$f'$nl# -> VULNERABLE if a sensitive function is callable without auth;  OK if exports are inert/internal   [tool: dumpbin]"
        }
        '^authenticode|^codeintegrity' {
            "Get-AuthenticodeSignature -FilePath '$f' | Format-List Status,StatusMessage,SignerCertificate$nl# -> VULNERABLE if Status = NotSigned / HashMismatch / Unknown;  OK if Status = Valid   [tool: PowerShell]"
        }
        '^strongname' {
            "[Reflection.AssemblyName]::GetAssemblyName('$f').GetPublicKeyToken()$nl# -> VULNERABLE if output is EMPTY (not strong-named, tamperable);  OK if a token (bytes) is printed   [tool: PowerShell]"
        }
        '^secrets\.|app-config\.connstring|app-config\.machine-key' {
            "([regex]::Matches([Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes('$f')),'AccountKey=\S{20,}|DefaultEndpointsProtocol=\S+|-----BEGIN [A-Z ]+KEY|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}')).Value$nl# -> VULNERABLE if it prints a real key / connection-string / token;  OK if it prints nothing (placeholder/none). For ASCII swap ::Unicode->::UTF8, or use: strings.exe -u '$f'   [tool: PowerShell / Sysinternals strings]"
        }
        '^(callsites\.|tls-bypass\.|deser\.|xxe\.|webview2\.)' {
            "Test-TcpkCallsites -Path '$f'$nl# -> decompile the flagged method in a .NET decompiler. VULNERABLE if the body returns constant true / deserializes untrusted input with no check;  OK if it calls X509Chain.Build / compares a thumbprint / validates input   [tool: PowerShell + any .NET decompiler]"
        }
        '^(backend\.endpoint|endpoints\.|scheme\.)' {
            "Test-NetConnection $hostName -Port 443$nl# -> VULNERABLE if the host carries credentials over http:// (cleartext) or accepts a forged cert;  OK if https with a valid, validated cert. Capture with Burp/Fiddler while using the app   [tool: PowerShell + intercepting proxy]"
        }
        '^update\.' {
            "Test-TcpkUpdateFlow -Path '$dir'$nl# -> decompile the update method. VULNERABLE if it applies a downloaded payload with NO signature/hash check;  OK if it verifies a signature before extract/exec   [tool: PowerShell + decompiler]"
        }
        '^tls\.' {
            "Test-TcpkTlsPinning -Path '$dir'$nl# -> MITM the app with a forged certificate. VULNERABLE if the app's HTTPS calls SUCCEED through your proxy;  OK if they FAIL (pinning/validation works)   [tool: PowerShell + mitmproxy/Burp]"
        }
        '^ports\.' {
            "Get-NetTCPConnection -State Listen -OwningProcess (Get-Process '<process>').Id$nl# -> VULNERABLE if LocalAddress = 0.0.0.0 / :: (all interfaces, unauthenticated);  OK if 127.0.0.1 only or the listener requires auth. App must be running   [tool: PowerShell]"
        }
        '^(pipe\.|pipe-dacl)' {
            "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | Select-String '<name>'$nl# -> then: accesschk -accepteula \\pipe\\<name>. VULNERABLE if Everyone/Users have write;  OK if restricted to the owner   [tool: PowerShell + Sysinternals accesschk]"
        }
        '^(com\.|msix\.com-server)' {
            "reg query `"HKCR\\CLSID`" /s /f `"$Evidence`"$nl# -> VULNERABLE if a standard user can register the same CLSID under HKCU (hijack);  OK if only HKLM and HKCU\\...\\CLSID is not user-writable   [tool: reg.exe]"
        }
        '^registry\.weak-dacl' {
            "(Get-Acl '$f').Access | Where-Object { `$_.IdentityReference -match 'Users|Everyone' -and `$_.RegistryRights -match 'Write|FullControl' }$nl# -> VULNERABLE if it returns ROWS (a standard user can write a machine-wide key);  OK if it returns NOTHING   [tool: PowerShell]"
        }
        '^registry\.footprint' {
            "Get-ItemProperty '$f'$nl# -> VULNERABLE if a value holds a secret / trust decision a user could read or change;  OK if only benign config   [tool: PowerShell]"
        }
        '^(acl\.|install-dir\.)' {
            "(Get-Acl '$f').Access | Format-Table IdentityReference,FileSystemRights,AccessControlType$nl# -> VULNERABLE if Users/Everyone have Write/Modify/FullControl;  OK if only SYSTEM/Administrators can write   [tool: PowerShell, or: icacls '$f']"
        }
        '^scheduled-task\.' {
            "schtasks /query /tn `"<taskname>`" /xml$nl# -> then: Get-Acl (Join-Path `$env:SystemRoot 'System32\\Tasks\\<taskname>'). VULNERABLE if a SYSTEM/HighestAvailable task's file is user-writable;  OK if only SYSTEM/Admins can write   [tool: schtasks + PowerShell]"
        }
        '^driver\.' {
            "Get-AuthenticodeSignature '$f' | Format-List Status$nl# -> VULNERABLE if unsigned/weakly-signed or its IOCTLs lack access checks (BYOVD);  OK if WHQL-signed with locked-down IOCTL surface. Also: sc.exe qc <serviceName>   [tool: PowerShell + sc.exe]"
        }
        '^uac\.' {
            "Test-TcpkUacManifest -Path '$f'$nl# -> VULNERABLE if autoElevate=true or level=requireAdministrator (every bug becomes EoP);  OK if asInvoker   [tool: PowerShell]"
        }
        '^wmi\.' {
            "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer; Get-CimInstance -Namespace root/subscription -ClassName __EventFilter$nl# -> VULNERABLE if an EventConsumer runs code on a trigger (persistence) and is undocumented;  OK if none / a documented product subscription   [tool: PowerShell]"
        }
        '^dpapi\.' {
            "# test box only: [Reflection.Assembly]::LoadWithPartialName('System.Security'); [Security.Cryptography.ProtectedData]::Unprotect((Get-Content '$f' -Encoding Byte),`$null,'CurrentUser')$nl# -> VULNERABLE if it DECRYPTS in the user context (recoverable without a master password);  OK if it throws / uses machine scope + entropy   [tool: PowerShell]"
        }
        '^cve\.' {
            "(Get-Item '$f').VersionInfo.FileVersion$nl# -> VULNERABLE if the shipped version is BELOW the fixed version in the advisory;  OK if >= fixed. Cross-check: Get-TcpkCveMatches -Path '$dir'   [tool: PowerShell]"
        }
        '^(log\.|pii\.|telemetry|etw\.)' {
            "Test-TcpkLogFiles -Path '$dir'; Test-TcpkPiiInLogs -Path '$dir'$nl# -> open the log/telemetry payloads. VULNERABLE if they contain secrets/tokens/PII;  OK if sanitized   [tool: PowerShell]"
        }
        '^named-object\.' {
            "# Sysinternals WinObj -> browse \\BaseNamedObjects$nl# -> VULNERABLE if a Global\\ object has a predictable name + default DACL (squattable for DoS/race);  OK if randomized name or restrictive DACL   [tool: Sysinternals WinObj]"
        }
        '^(antidebug\.|integrity\.|timing\.|antiinjection)' {
            "# decompile the flagged routine in a .NET/native decompiler$nl# -> this is a HARDENING signal (informational). 'Good' if the check actually GATES execution; not a vuln by itself   [tool: decompiler]"
        }
        '^(wer\.|pagefile\.|mem\.)' {
            "reg query `"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting`"$nl# -> VULNERABLE if full crash dumps are enabled or the pagefile isn't cleared (secrets reach disk);  OK if minidump-only + ClearPageFileAtShutdown=1   [tool: reg.exe / PowerShell]"
        }
        '^window\.exists' {
            "# Spy++ / Winspy on the running app$nl# -> VULNERABLE if a window handles WM_COPYDATA / custom messages without validating the sender or payload;  OK otherwise   [tool: Spy++]"
        }
        '^wcf\.' {
            "# inspect the app's .config ServiceModel bindings$nl# -> VULNERABLE if basicHttpBinding (clear-text) or security mode=None;  OK if TLS transport + a real auth mode   [tool: text editor]"
        }
        '^entropy\.' {
            "Select-String -Path '$f' -Pattern '[A-Za-z0-9+/_-]{24,}' -AllMatches | ForEach-Object { `$_.Matches.Value }$nl# -> VULNERABLE if a printed high-entropy token is a live key/secret;  OK if it is a hash/cache-buster/asset id   [tool: PowerShell]"
        }
        '^crypto\.' {
            "# decompile the crypto routine that references this file/value$nl# -> VULNERABLE if a hardcoded key/IV is used, or PaddingMode.None / PasswordDeriveBytes;  OK if keys are derived per-user (PBKDF2/Argon2) with a random salt + AES-GCM   [tool: .NET decompiler]"
        }
        '^jwt\.' {
            "`$p=('$Evidence' -split '\.'); [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((`$p[1]+'===').Substring(0,(`$p[1].Length+3) -band -4).Replace('-','+').Replace('_','/')))$nl# -> VULNERABLE if alg=none, or the token is unexpired/has sensitive claims;  OK if it is an expired sample with no secrets   [tool: PowerShell / jwt.io offline]"
        }
        '^keymaterial\.' {
            "Get-PfxData -FilePath '$f' -ErrorAction SilentlyContinue; Get-Content '$f' -TotalCount 2$nl# -> VULNERABLE if a PRIVATE KEY loads with no/empty password (server impersonation / signing);  OK if encrypted with a non-shipped password or only public certs   [tool: PowerShell]"
        }
        '^truststore\.' {
            "Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { `$_.Subject -match '<vendor>' }$nl# -> VULNERABLE if the app installed a custom ROOT CA (can MITM TLS / sign trusted code machine-wide);  OK if no app-owned root is present   [tool: PowerShell / certlm.msc]"
        }
        '^selfhost\.' {
            "# run the app, then: Get-NetTCPConnection -State Listen -OwningProcess (Get-Process '<process>').Id$nl# -> VULNERABLE if it binds 0.0.0.0/all and serves without auth (curl http://localhost:<port>/ returns data);  OK if 127.0.0.1 + authenticated   [tool: PowerShell + curl]"
        }
        '^zipslip\.' {
            "# decompile the extraction loop$nl# -> VULNERABLE if it writes Path.Combine(dest, entry.FullName) without verifying the resolved path stays under dest (craft an entry named ..\\..\\evil to test);  OK if it canonicalises + checks StartsWith(dest)   [tool: .NET decompiler]"
        }
        '^debugflags\.' {
            "Select-String -Path '$f' -Pattern '$Evidence'$nl# -> VULNERABLE if the flag is reachable via config/env/arg and disables a control (test by setting it and observing);  OK if dead/compile-time-only   [tool: PowerShell + decompiler]"
        }
        '^firewall\.' {
            "Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object DisplayName -match '<vendor>' | Get-NetFirewallPortFilter$nl# -> VULNERABLE if an inbound allow exposes an unauthenticated listener (esp. Any remote / Public);  OK if scoped/removed or the listener authenticates   [tool: PowerShell]"
        }
        '^avexclusion\.' {
            "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension$nl# -> VULNERABLE if the app's own path/process is excluded (malware there runs unscanned);  OK if no app-owned exclusion (run elevated to read)   [tool: PowerShell]"
        }
        '^(servicebin|taskbin)\.' {
            "(Get-Acl '$f').Access | Format-Table IdentityReference,FileSystemRights,AccessControlType$nl# -> VULNERABLE if Users/Everyone can Write/Modify the binary or its folder (replace it -> runs as the service account);  OK if admin-only   [tool: PowerShell / icacls]"
        }
        '^process\.dacl' {
            "# run the app, then with Process Hacker: right-click process -> Properties -> Security -> Permissions$nl# -> VULNERABLE if Users/Everyone have Write/CreateThread/AllAccess (inject into an elevated process);  OK if default DACL   [tool: Process Hacker / accesschk -p]"
        }
        '^(memsecret\.|env\.secret)' {
            "# with the app running: Test-TcpkMemorySecrets -ProcessName '<process>'  (or)  Test-TcpkProcessEnvSecrets -ProcessName '<process>'$nl# -> VULNERABLE if a live secret/token/password is recoverable from heap or environment;  OK if none (secrets are protected + cleared)   [tool: TCPK / Process Hacker memory search]"
        }
        '^attacksurface\.' {
            "# review attack-surface.json in the output folder$nl# -> triage each entry point (protocol/pipe/COM/RPC/port/listener) for auth + input validation. Informational map, not a vuln by itself   [tool: TCPK]"
        }
        default {
            "# re-run the TCPK check for rule '$RuleId' and inspect the File + Evidence$nl# -> use the Evidence value as the search term; confirm it is real and reachable"
        }
    }
    return [string](@($h) | Select-Object -First 1)
}
