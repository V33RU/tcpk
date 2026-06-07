# Per-finding manual re-validation playbook.
#
# Get-TcpkVerifyHint returns a clear, multi-line, COPY-PASTE-SAFE block per finding:
#   # WHAT THIS CHECKS: <plain-English purpose>
#   # STEP 1 - RUN THIS IN POWERSHELL:   (or: DO THIS MANUALLY)
#   <the actual command>                 <- the only non-comment line(s); paste-and-run
#   # STEP 2 - READ THE OUTPUT:
#   #   VULNERABLE  if  <what a bad result looks like>
#   #   OK          if  <what a good result looks like>
#   # NOTE: <extra guidance>              (optional)
#   # TOOL: <which tool>
#
# Every line except the command itself is a '#' comment, so pasting the whole
# block into PowerShell runs the command and ignores the explanations.
# Used by both the HTML and Excel reports.

function Format-TcpkVerifyHint {
    [CmdletBinding()]
    param(
        [string]$What,                 # plain-English: what this verifies / what the command does
        [string]$Run,                  # paste-and-run PowerShell one-liner (omit for manual-only checks)
        [string[]]$Manual = @(),       # manual steps, one per line (used when there is no one-liner)
        [string]$Vulnerable,           # what a BAD (vulnerable) result looks like
        [string]$Ok,                   # what a GOOD (safe) result looks like
        [string]$Info,                 # for informational checks: a single "what it means" line (instead of Vulnerable/Ok)
        [string]$Note,                 # optional extra guidance
        [string]$Tool                  # which tool(s) to use
    )
    $nl = "`r`n"
    $L = New-Object System.Collections.Generic.List[string]
    if ($What) { $L.Add("# WHAT THIS CHECKS: $What") }
    if ($Run) {
        $L.Add("# STEP 1 - RUN THIS IN POWERSHELL:")
        $L.Add($Run)
    } elseif ($Manual.Count) {
        $L.Add("# STEP 1 - DO THIS MANUALLY:")
        foreach ($m in $Manual) { $L.Add("#   - $m") }
    }
    if ($Info) {
        $L.Add("# STEP 2 - WHAT IT MEANS:")
        $L.Add("#   $Info")
    } else {
        $L.Add("# STEP 2 - READ THE OUTPUT:")
        if ($Vulnerable) { $L.Add("#   VULNERABLE  if  $Vulnerable") }
        if ($Ok)         { $L.Add("#   OK          if  $Ok") }
    }
    if ($Note) { $L.Add("# NOTE: $Note") }
    if ($Tool) { $L.Add("# TOOL: $Tool") }
    return ($L -join $nl)
}

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

    $h = switch -Regex ($RuleId) {

        '^pe\.missing-mitigations' {
            Format-TcpkVerifyHint `
                -What "Re-checks the binary's exploit mitigations (ASLR, DEP, CFG, HighEntropyVA)." `
                -Run "Get-TcpkPeHardening -Path '$f'" `
                -Vulnerable "the table shows ASLR=NO or DEP=NO (a core memory-corruption defense is missing)." `
                -Ok "ASLR, DEP, CFG and HighEntropyVA all show YES." `
                -Tool "PowerShell (alternative: dumpbin /headers)"
        }
        '^pe-imports\.' {
            Format-TcpkVerifyHint `
                -What "Lists the DLLs this binary imports, to spot any that could be planted from a writable folder." `
                -Run "dumpbin /imports '$f'" `
                -Vulnerable "a listed DLL can resolve from a user-writable directory (DLL planting / search-order hijack)." `
                -Ok "every imported DLL binds from System32 or the application directory." `
                -Tool "Visual Studio 'dumpbin' (Developer Command Prompt)"
        }
        '^pe-exports\.' {
            Format-TcpkVerifyHint `
                -What "Lists the functions this binary exposes to other callers." `
                -Run "dumpbin /exports '$f'" `
                -Vulnerable "a sensitive or privileged function is callable with no authentication." `
                -Ok "the exports are inert or internal-only." `
                -Tool "Visual Studio 'dumpbin'"
        }
        '^authenticode|^codeintegrity' {
            Format-TcpkVerifyHint `
                -What "Checks the file's Authenticode digital signature." `
                -Run "Get-AuthenticodeSignature -FilePath '$f' | Format-List Status,StatusMessage,SignerCertificate" `
                -Vulnerable "Status is NotSigned, HashMismatch, or Unknown (the file is unsigned, tampered, or untrusted)." `
                -Ok "Status is Valid." `
                -Tool "PowerShell"
        }
        '^strongname' {
            Format-TcpkVerifyHint `
                -What "Checks whether a .NET assembly is strong-named (which makes it harder to silently replace)." `
                -Run "[Reflection.AssemblyName]::GetAssemblyName('$f').GetPublicKeyToken()" `
                -Vulnerable "the output is EMPTY - the assembly is not strong-named and can be modified or swapped out." `
                -Ok "a public-key token (a row of bytes) is printed." `
                -Tool "PowerShell"
        }
        '^secrets\.|app-config\.connstring|app-config\.machine-key' {
            Format-TcpkVerifyHint `
                -What "Scans the file's text for things that look like LIVE secrets - Azure storage keys, connection strings, PEM private keys, AWS access keys, or JWT tokens." `
                -Run "([regex]::Matches([Text.Encoding]::Unicode.GetString([IO.File]::ReadAllBytes('$f')),'DefaultEndpointsProtocol=https?;[A-Za-z0-9=;._/+\-]{0,300}AccountKey=[A-Za-z0-9+/=]{20,}|AccountKey=[A-Za-z0-9+/=]{20,}|-----BEGIN [A-Z ]+KEY|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}')).Value" `
                -Vulnerable "it prints a real secret - e.g. AccountKey=..., a DefaultEndpointsProtocol=... connection string, an AKIA... AWS key, an eyJ... JWT, or a -----BEGIN ... KEY----- block." `
                -Ok "it prints nothing (only placeholders, or there are no secrets in the file)." `
                -Note "this reads the file as UTF-16 (Unicode) text. If the secret is stored as plain ASCII, change ::Unicode to ::UTF8 and run it again. To dump EVERY readable string instead: strings.exe -u '$f'" `
                -Tool "PowerShell built-in (alternative: Sysinternals strings.exe)"
        }
        '^session\.' {
            Format-TcpkVerifyHint `
                -What "Re-checks how the app handles session cookies/tokens (HttpOnly/Secure/SameSite flags, token in URL, weak token generation, expiry) in the flagged file." `
                -Run "Select-String -Path '$f' -Pattern 'HttpOnly|Secure|SameSite|cookieless|Guid\.NewGuid|new Random|sessionid=|access_token=|isPersistent|timeout' -AllMatches | Select-Object LineNumber,Line" `
                -Vulnerable "a session cookie is set without HttpOnly/Secure, a token is carried in the URL, the session id is generated from Guid.NewGuid()/Random, or the session never expires." `
                -Ok "session cookies set HttpOnly+Secure+SameSite, tokens travel in headers/secure cookies, and tokens come from a CSPRNG with a sane expiry." `
                -Note "for compiled .NET, open the flagged method in a decompiler (ILSpy/dnSpy) to confirm the setting governs a real session; for the running app, inspect the actual Set-Cookie headers/tokens with Burp or Fiddler." `
                -Tool "PowerShell + a .NET decompiler / intercepting proxy (Burp / Fiddler)"
        }
        '^tls-bypass\.cert-callback-accepts-all' {
            Format-TcpkVerifyHint `
                -What "TCPK proved from IL that a certificate-validation callback returns true unconditionally (or uses the BCL accept-all validator) - the client accepts ANY server certificate." `
                -Run "Test-TcpkTlsBypass -Path '$dir'" `
                -Vulnerable "the flagged method's body is 'ldc.i4.1; ret' (return true) with no chain build, thumbprint compare, or SslPolicyErrors check." `
                -Ok "the method validates the chain / compares a thumbprint / checks errors == SslPolicyErrors.None before returning." `
                -Note "this is already CONFIRMED. Open the flagged Type::Method in ILSpy/dnSpy to capture the PoC. The callback may live in a SIBLING assembly, so scan the whole install dir (-Path the folder, not one DLL)." `
                -Tool "PowerShell (TCPK IL prover) + ILSpy/dnSpy for the screenshot"
        }
        '^tls-bypass\.' {
            Format-TcpkVerifyHint `
                -What "A TLS validation override was referenced. Confirm whether it actually disables certificate/hostname checking." `
                -Run "Test-TcpkTlsBypass -Path '$dir'" `
                -Vulnerable "a cert/hostname callback returns true unconditionally, or validation mode is None." `
                -Ok "the callback builds a chain / compares a thumbprint / validates the hostname." `
                -Note "run against the whole install dir, not just one DLL - the callback often lives in a sibling assembly. TCPK auto-confirms accept-all callbacks (rule tls-bypass.cert-callback-accepts-all) via the Mono.Cecil IL prover." `
                -Tool "PowerShell + a .NET decompiler (ILSpy / dnSpy)"
        }
        '^(callsites\.|deser\.|xxe\.|webview2\.)' {
            Format-TcpkVerifyHint `
                -What "Finds the exact code locations TCPK flagged so you can read the real logic in a decompiler." `
                -Run "Test-TcpkCallsites -Path '$f'" `
                -Vulnerable "the flagged method returns a constant 'true' for certificate validation, or it deserializes/parses untrusted input with no checks." `
                -Ok "it builds an X509Chain, compares a certificate thumbprint, or validates the input before using it." `
                -Note "open the flagged method in a .NET decompiler (ILSpy or dnSpy) to read the method body." `
                -Tool "PowerShell + a .NET decompiler (ILSpy / dnSpy)"
        }
        '^csv\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether data the app exports to CSV/Excel could be interpreted as a spreadsheet FORMULA (CSV/formula injection)." `
                -Manual @(
                    "In the app, put a value that STARTS WITH = into a field that later gets exported -- e.g. type   =1+1   (or   =HYPERLINK('http://attacker/x','click')  ) into a name/comment/description field.",
                    "Use the app's normal Export-to-CSV / Export-to-Excel feature to export that data.",
                    "Open the exported .csv / .xlsx in Microsoft Excel and look at the cell you controlled."
                ) `
                -Vulnerable "Excel shows '2' (the formula ran) or a clickable hyperlink -- the leading '=' was NOT escaped, so =WEBSERVICE(...)/=HYPERLINK(...) can exfiltrate data and (older Excel) =cmd|... can run commands." `
                -Ok "Excel shows the literal text   =1+1   (the cell was prefixed with a single quote or the formula characters were neutralized)." `
                -Note "Also try leading   +   -   @   tab and carriage-return; all are treated as formula starters by spreadsheet apps." `
                -Tool "the app + Microsoft Excel"
        }
        '^(backend\.endpoint|endpoints\.|scheme\.)' {
            Format-TcpkVerifyHint `
                -What "Confirms whether a backend host the app talks to is reachable, and how the connection is secured." `
                -Run "Test-NetConnection $hostName -Port 443" `
                -Vulnerable "the host is contacted over http:// (credentials sent in cleartext) or it accepts a forged/invalid certificate." `
                -Ok "it uses https with a valid, properly-validated certificate." `
                -Note "to see the real traffic, capture it with Burp or Fiddler while using the app." `
                -Tool "PowerShell + an intercepting proxy (Burp / Fiddler)"
        }
        '^update\.' {
            Format-TcpkVerifyHint `
                -What "Inspects the app's update/download flow for missing integrity checks." `
                -Run "Test-TcpkUpdateFlow -Path '$dir'" `
                -Vulnerable "it applies a downloaded update with NO signature or hash check (remote code execution via a poisoned update server)." `
                -Ok "it verifies a signature or hash before extracting or running the payload." `
                -Note "decompile the update method to confirm the check actually runs." `
                -Tool "PowerShell + a .NET decompiler"
        }
        '^tls\.' {
            Format-TcpkVerifyHint `
                -What "Tests whether the app pins or validates its TLS server certificates." `
                -Run "Test-TcpkTlsPinning -Path '$dir'" `
                -Vulnerable "the app's HTTPS calls SUCCEED when routed through your forged-certificate proxy (no pinning / no validation)." `
                -Ok "those calls FAIL through the proxy (pinning or validation is working)." `
                -Note "to test live, MITM the running app with mitmproxy or Burp using a self-signed CA." `
                -Tool "PowerShell + mitmproxy / Burp"
        }
        '^ports\.' {
            Format-TcpkVerifyHint `
                -What "Shows which network ports the running process is listening on." `
                -Run "Get-NetTCPConnection -State Listen -OwningProcess (Get-Process '<process>').Id" `
                -Vulnerable "LocalAddress is 0.0.0.0 or :: (listening on all interfaces) and the service needs no authentication." `
                -Ok "it binds 127.0.0.1 only, or the listener requires authentication." `
                -Note "replace <process> with the app's process name; the app must be running." `
                -Tool "PowerShell"
        }
        '^(pipe\.|pipe-dacl)' {
            # the pipe name is the finding Evidence -- fill it in so the command is runnable as-is
            $pname = if ($Evidence) { $Evidence } else { '<name>' }
            Format-TcpkVerifyHint `
                -What "Checks named-pipe IPC endpoints and who is allowed to connect to them." `
                -Run "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | Select-String '$pname'" `
                -Vulnerable "Everyone or Users have write access to the pipe (any local user can inject IPC messages)." `
                -Ok "the pipe is restricted to its owner or SYSTEM." `
                -Note "after finding the pipe, check its permissions: accesschk -accepteula \\pipe\\$pname" `
                -Tool "PowerShell + Sysinternals accesschk"
        }
        '^(com\.|msix\.com-server)' {
            Format-TcpkVerifyHint `
                -What "Looks for a COM CLSID that a standard user could hijack." `
                -Run "reg query `"HKCR\\CLSID`" /s /f `"$Evidence`"" `
                -Vulnerable "a standard user can register the same CLSID under HKCU and hijack activation of the COM server." `
                -Ok "the CLSID lives only under HKLM and the HKCU path is not user-writable." `
                -Tool "reg.exe"
        }
        '^registry\.weak-dacl' {
            Format-TcpkVerifyHint `
                -What "Checks whether a standard user can write to a machine-wide registry key." `
                -Run "(Get-Acl '$f').Access | Where-Object { `$_.IdentityReference -match 'Users|Everyone' -and `$_.RegistryRights -match 'Write|FullControl' }" `
                -Vulnerable "it returns one or more rows (a normal user can modify this machine-wide key)." `
                -Ok "it returns nothing." `
                -Tool "PowerShell"
        }
        '^registry\.footprint' {
            Format-TcpkVerifyHint `
                -What "Shows the values stored under a registry key the app uses." `
                -Run "Get-ItemProperty '$f'" `
                -Vulnerable "a value holds a secret, or a trust decision that a user could read or change." `
                -Ok "only benign configuration is present." `
                -Tool "PowerShell"
        }
        '^(acl\.|install-dir\.)' {
            Format-TcpkVerifyHint `
                -What "Shows the file/folder permissions so you can see who is allowed to modify it." `
                -Run "(Get-Acl '$f').Access | Format-Table IdentityReference,FileSystemRights,AccessControlType" `
                -Vulnerable "Users or Everyone have Write / Modify / FullControl (they can replace the file)." `
                -Ok "only SYSTEM and Administrators can write." `
                -Note "for a quick one-line view: icacls '$f'" `
                -Tool "PowerShell (alternative: icacls)"
        }
        '^scheduled-task\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether a privileged scheduled task runs a file that a normal user can overwrite." `
                -Run "schtasks /query /tn `"<taskname>`" /xml" `
                -Vulnerable "a SYSTEM or HighestAvailable task's executable (or its folder) is user-writable (replace it and it runs elevated)." `
                -Ok "only SYSTEM/Admins can write both the task and its target binary." `
                -Note "then check the target binary's permissions: (Get-Acl '<path-to-task-exe>').Access" `
                -Tool "schtasks + PowerShell"
        }
        '^driver\.' {
            Format-TcpkVerifyHint `
                -What "Checks a kernel driver/service for weak signing or an exposed IOCTL surface (bring-your-own-vulnerable-driver risk)." `
                -Run "Get-AuthenticodeSignature '$f' | Format-List Status" `
                -Vulnerable "it is unsigned/weakly-signed, or its IOCTLs lack access checks." `
                -Ok "it is WHQL-signed with a locked-down IOCTL surface." `
                -Note "also inspect the service configuration: sc.exe qc <serviceName>" `
                -Tool "PowerShell + sc.exe"
        }
        '^uac\.' {
            Format-TcpkVerifyHint `
                -What "Reads the executable's UAC manifest (the privilege level it asks Windows for)." `
                -Run "Test-TcpkUacManifest -Path '$f'" `
                -Vulnerable "autoElevate=true or level=requireAdministrator (any bug in the app becomes elevation-of-privilege)." `
                -Ok "level = asInvoker (runs with the caller's privileges)." `
                -Tool "PowerShell"
        }
        '^wmi\.' {
            Format-TcpkVerifyHint `
                -What "Looks for permanent WMI event subscriptions, a common stealth persistence technique." `
                -Run "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer; Get-CimInstance -Namespace root/subscription -ClassName __EventFilter" `
                -Vulnerable "an EventConsumer runs code on a trigger and is undocumented." `
                -Ok "there are none, or only a documented product subscription." `
                -Tool "PowerShell"
        }
        '^dpapi\.' {
            Format-TcpkVerifyHint `
                -What "Tests whether a DPAPI-protected blob can be decrypted in the current user's context (i.e. recovered with no master password). Run on a TEST machine only." `
                -Run "[Reflection.Assembly]::LoadWithPartialName('System.Security'); [Security.Cryptography.ProtectedData]::Unprotect((Get-Content '$f' -Encoding Byte),`$null,'CurrentUser')" `
                -Vulnerable "it DECRYPTS and returns bytes - the secret is recoverable in the user context." `
                -Ok "it throws an error, or the blob uses machine scope plus extra entropy." `
                -Note "only run this against data you are authorized to test, on a non-production machine." `
                -Tool "PowerShell"
        }
        '^cve\.' {
            Format-TcpkVerifyHint `
                -What "Reads the shipped file's version so you can compare it against the CVE's fixed version." `
                -Run "(Get-Item '$f').VersionInfo.FileVersion" `
                -Vulnerable "the printed version is BELOW the fixed version listed in the advisory." `
                -Ok "the printed version is greater than or equal to the fixed version." `
                -Note "cross-check the full match list: Get-TcpkCveMatches -Path '$dir'" `
                -Tool "PowerShell"
        }
        '^(log\.|pii\.|telemetry|etw\.)' {
            Format-TcpkVerifyHint `
                -What "Inspects the app's log and telemetry files for sensitive data." `
                -Run "Test-TcpkLogFiles -Path '$dir'; Test-TcpkPiiInLogs -Path '$dir'" `
                -Vulnerable "the logs or telemetry payloads contain secrets, tokens, or personal data (PII)." `
                -Ok "they are sanitized / contain no sensitive values." `
                -Note "open the reported log and telemetry files and read the payloads yourself to confirm." `
                -Tool "PowerShell"
        }
        '^named-object\.' {
            Format-TcpkVerifyHint `
                -What "Checks named kernel objects (events, mutexes, sections) for predictable names that another process could squat." `
                -Manual @('Open Sysinternals WinObj as administrator.', 'Browse to \BaseNamedObjects and find the named object.') `
                -Vulnerable "a Global\ object has a predictable name and a default DACL (squattable for denial-of-service or a race condition)." `
                -Ok "the name is randomized, or the DACL is restrictive." `
                -Tool "Sysinternals WinObj"
        }
        '^(antidebug\.|integrity\.|timing\.|antiinjection)' {
            Format-TcpkVerifyHint `
                -What "These are anti-tamper / hardening signals, not vulnerabilities by themselves." `
                -Manual @('Decompile the flagged routine in a .NET or native decompiler.', 'Check whether the anti-debug / integrity check actually gates execution.') `
                -Info "Informational. It is GOOD if the check genuinely stops execution when triggered; it is WEAK (but still not a vuln) if the check is present but never enforced." `
                -Tool "a .NET / native decompiler"
        }
        '^(wer\.|pagefile\.|mem\.)' {
            Format-TcpkVerifyHint `
                -What "Checks crash-dump and pagefile settings that could leak secrets to disk." `
                -Run "reg query `"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting`"" `
                -Vulnerable "full crash dumps are enabled, or the pagefile is not cleared at shutdown (in-memory secrets can reach disk)." `
                -Ok "crash dumps are minidump-only AND ClearPageFileAtShutdown = 1." `
                -Tool "reg.exe / PowerShell"
        }
        '^window\.exists' {
            Format-TcpkVerifyHint `
                -What "Checks whether the app exposes a top-level window that accepts inter-process window messages." `
                -Manual @('Run the app.', 'Inspect its windows with Spy++ or WinSpy.') `
                -Vulnerable "a window handles WM_COPYDATA or custom messages without validating the sender or the payload." `
                -Ok "messages are validated, or those messages are not handled." `
                -Tool "Spy++ / WinSpy"
        }
        '^wcf\.' {
            Format-TcpkVerifyHint `
                -What "Checks the app's WCF / ServiceModel bindings for weak transport security." `
                -Manual @("Open the app's .config file and find the <system.serviceModel> bindings.") `
                -Vulnerable "it uses basicHttpBinding (clear-text) or security mode = None." `
                -Ok "it uses a TLS transport binding with a real authentication mode." `
                -Tool "any text editor"
        }
        '^entropy\.' {
            Format-TcpkVerifyHint `
                -What "Surfaces long high-entropy strings in the file that might be embedded secrets." `
                -Run "Select-String -Path '$f' -Pattern '[A-Za-z0-9+/_-]{24,}' -AllMatches | ForEach-Object { `$_.Matches.Value }" `
                -Vulnerable "a printed high-entropy string turns out to be a live key or secret." `
                -Ok "the strings are hashes, cache-busters, or asset IDs." `
                -Tool "PowerShell"
        }
        '^crypto\.' {
            Format-TcpkVerifyHint `
                -What "Checks how the app uses cryptography - looking for hardcoded keys or weak modes." `
                -Manual @('Decompile the crypto routine that references this file/value.') `
                -Vulnerable "a hardcoded key/IV is used, or PaddingMode.None / PasswordDeriveBytes appears." `
                -Ok "keys are derived per-user (PBKDF2 / Argon2) with a random salt, using AES-GCM." `
                -Tool "a .NET decompiler"
        }
        '^jwt\.' {
            Format-TcpkVerifyHint `
                -What "Decodes the payload of the flagged JWT so you can read its claims." `
                -Run "`$p=('$Evidence' -split '\.'); [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((`$p[1]+'===').Substring(0,(`$p[1].Length+3) -band -4).Replace('-','+').Replace('_','/')))" `
                -Vulnerable "alg = none, or the token is unexpired / carries sensitive claims." `
                -Ok "it is an expired sample token with no secrets." `
                -Note "you can also paste the token into an OFFLINE jwt decoder (never a live online one)." `
                -Tool "PowerShell (alternative: an offline jwt decoder)"
        }
        '^keymaterial\.' {
            Format-TcpkVerifyHint `
                -What "Tests whether a shipped key/cert file contains a usable PRIVATE key." `
                -Run "Get-PfxData -FilePath '$f' -ErrorAction SilentlyContinue; Get-Content '$f' -TotalCount 2" `
                -Vulnerable "a private key loads with no password / an empty password (enables server impersonation or code signing)." `
                -Ok "it is encrypted with a password that is not shipped, or only public certificates are present." `
                -Tool "PowerShell"
        }
        '^truststore\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether the app installed its own root CA into the Windows trust store." `
                -Run "Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { `$_.Subject -match '<vendor>' }" `
                -Vulnerable "a custom ROOT CA is present (it can MITM TLS, or sign code trusted machine-wide)." `
                -Ok "no app-owned root CA is installed." `
                -Note "replace <vendor> with the app's publisher name." `
                -Tool "PowerShell (alternative: certlm.msc)"
        }
        '^selfhost\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether the app runs its own local HTTP/socket server, and whether that server needs authentication." `
                -Run "Get-NetTCPConnection -State Listen -OwningProcess (Get-Process '<process>').Id" `
                -Vulnerable "it binds 0.0.0.0 / all interfaces and serves data without auth (e.g. curl http://localhost:<port>/ returns content)." `
                -Ok "it binds 127.0.0.1 and requires authentication." `
                -Note "run the app first; replace <process> with its process name." `
                -Tool "PowerShell + curl"
        }
        '^zipslip\.' {
            Format-TcpkVerifyHint `
                -What "Checks an archive-extraction routine for path-traversal (the 'Zip Slip' bug)." `
                -Manual @('Decompile the extraction loop.') `
                -Vulnerable "it writes Path.Combine(dest, entry.FullName) without checking the resolved path stays under dest (test with an entry named ..\..\evil)." `
                -Ok "it canonicalizes the path and verifies it StartsWith(dest) before writing." `
                -Tool "a .NET decompiler"
        }
        '^debugflags\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether a debug / feature flag can be toggled to disable a security control." `
                -Run "Select-String -Path '$f' -Pattern '$Evidence'" `
                -Vulnerable "the flag is reachable via config / environment / argument and disables a control (test by setting it and observing)." `
                -Ok "it is dead code or compile-time only." `
                -Tool "PowerShell + a decompiler"
        }
        '^firewall\.' {
            Format-TcpkVerifyHint `
                -What "Lists the inbound firewall allow-rules the app created." `
                -Run "Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object DisplayName -match '<vendor>' | Get-NetFirewallPortFilter" `
                -Vulnerable "an inbound allow rule exposes an unauthenticated listener (especially 'Any' remote address or the Public profile)." `
                -Ok "the rules are scoped/removed, or the listener authenticates." `
                -Note "replace <vendor> with the app's name." `
                -Tool "PowerShell"
        }
        '^avexclusion\.' {
            Format-TcpkVerifyHint `
                -What "Checks for Microsoft Defender exclusions that cover the app (malware placed there would run unscanned)." `
                -Run "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension" `
                -Vulnerable "the app's own path, process, or extension is excluded from scanning." `
                -Ok "no app-owned exclusion exists." `
                -Note "run PowerShell elevated (as administrator) to read these settings." `
                -Tool "PowerShell (elevated)"
        }
        '^(servicebin|taskbin)\.' {
            Format-TcpkVerifyHint `
                -What "Checks whether a service/task binary (or its folder) can be replaced by a normal user." `
                -Run "(Get-Acl '$f').Access | Format-Table IdentityReference,FileSystemRights,AccessControlType" `
                -Vulnerable "Users or Everyone can Write/Modify the binary or its folder (replace it and it runs as the service account)." `
                -Ok "only administrators can write." `
                -Note "for a quick one-line view: icacls '$f'" `
                -Tool "PowerShell (alternative: icacls)"
        }
        '^process\.dacl' {
            Format-TcpkVerifyHint `
                -What "Checks the running process's security descriptor for weak access rights." `
                -Manual @('Run the app.', 'In Process Hacker: right-click the process -> Properties -> Security -> Permissions.') `
                -Vulnerable "Users or Everyone have Write / CreateThread / AllAccess (you could inject code into an elevated process)." `
                -Ok "the process keeps a default, restrictive DACL." `
                -Note "command-line alternative: accesschk -p -accepteula <process>" `
                -Tool "Process Hacker / Sysinternals accesschk"
        }
        '^(memsecret\.|env\.secret)' {
            Format-TcpkVerifyHint `
                -What "Searches the running process's heap and environment block for live secrets." `
                -Run "Test-TcpkMemorySecrets -ProcessName '<process>'; Test-TcpkProcessEnvSecrets -ProcessName '<process>'" `
                -Vulnerable "a live secret / token / password is recoverable from the heap or the environment." `
                -Ok "nothing is found (secrets are protected in memory and cleared after use)." `
                -Note "the app must be running; replace <process> with its process name." `
                -Tool "TCPK (alternative: Process Hacker memory search)"
        }
        '^attacksurface\.' {
            Format-TcpkVerifyHint `
                -What "A map of the entry points TCPK found - protocols, pipes, COM, RPC, ports, listeners." `
                -Manual @('Open attack-surface.json in the output folder.', 'Triage each entry point for authentication and input validation.') `
                -Info "Informational map, not a vulnerability by itself. Use it to decide what to test next." `
                -Tool "TCPK"
        }
        '^chain\.' {
            Format-TcpkVerifyHint `
                -What "This is a CORRELATED finding - TCPK combined several lower-severity findings into one exploit chain. Confirm each link, then prove the end-to-end path." `
                -Manual @(
                    'Re-read the "Contributing conditions" in this finding''s Description.',
                    'Open each contributing finding (listed in this finding''s Evidence) and confirm it on its own.',
                    'Then prove the chain end-to-end on a TEST machine (e.g. plant the payload / craft the link, trigger the update or activation, observe code execution or privilege gain).'
                ) `
                -Vulnerable "every link confirms AND the end-to-end path runs attacker-controlled code or elevates privilege." `
                -Ok "any single link is a false positive or not actually reachable - that breaks the chain." `
                -Tool "TCPK (the contributing checks) + manual end-to-end validation"
        }
        '^protocol\.sink-reachable' {
            Format-TcpkVerifyHint `
                -What "Checks whether URI/file activation input in this binary can flow into a dangerous sink (process launch, deserialization, or path/file write)." `
                -Run "Test-TcpkCallsites -Path '$f'" `
                -Vulnerable "decompiling the activation handler shows the URI / file argument reaching Process.Start / ShellExecute / a deserializer / a built file path with no validation." `
                -Ok "the argument is validated or allow-listed before any sink, or the sink uses a constant value (not the activation input)." `
                -Note "open the activation handler (OnActivated / ProtocolActivatedEventArgs) in ILSpy or dnSpy and trace the Uri/file value to each sink listed in the Evidence." `
                -Tool "PowerShell + a .NET decompiler (ILSpy / dnSpy)"
        }
        '^msix\.alias-shadowing' {
            # the alias name is the finding Evidence -- fill it in so the command runs as-is
            $alias = if ($Evidence) { $Evidence } else { '<alias>' }
            Format-TcpkVerifyHint `
                -What "Checks whether an appExecutionAlias registers a name that shadows a common command on PATH." `
                -Run "where.exe $alias; Get-Command $alias -All -ErrorAction SilentlyContinue | Select-Object Source" `
                -Vulnerable "the WindowsApps alias resolves BEFORE the real tool (where.exe lists the %LOCALAPPDATA%\Microsoft\WindowsApps stub first), so typing the command runs the app, not the tool." `
                -Ok "no collision, or the real tool resolves first / the alias name is unique to this app." `
                -Note "alias stubs live in %LOCALAPPDATA%\Microsoft\WindowsApps (a per-user, user-writable PATH dir)." `
                -Tool "PowerShell (where.exe / Get-Command)"
        }
        default {
            Format-TcpkVerifyHint `
                -What "Re-validate this finding using its reported File and Evidence values." `
                -Manual @("Re-run the TCPK check for rule '$RuleId'.", "Inspect the reported File and Evidence; use the Evidence value as a search term.") `
                -Vulnerable "the Evidence value is real, reachable, and does what the finding describes." `
                -Ok "the Evidence is a false positive (a placeholder, dead code, or unreachable)." `
                -Tool "TCPK / PowerShell"
        }
    }
    return [string](@($h) | Select-Object -First 1)
}
