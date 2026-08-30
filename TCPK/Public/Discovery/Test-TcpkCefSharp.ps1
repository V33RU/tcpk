function Test-TcpkCefSharp {
<#
.SYNOPSIS
    A52. CefSharp / CEF JavaScript-to-native bridge and browser-security misconfiguration.

.DESCRIPTION
    Windows industrial and engineering software very commonly embeds Chromium via CefSharp
    (.NET), CEF (C++), or ChromiumFX. The class of bug that matters here is the same one
    Android calls addJavascriptInterface: if the client registers a .NET object as a global
    JavaScript name, any code that ends up in the renderer (a loaded page, an XSS, a Blink
    zero-day) can call every method on that object with the app's process privileges.

    Detected here, in one pass over each PE:

      cef.js-bridge-registered   HIGH Inferred  The literal string RegisterJsObject or
                                       JavascriptObjectRepository appears in the assembly. That
                                       is textual evidence of the API reference; a proven call
                                       site requires an IL check that this rule does not run,
                                       so Confidence is Inferred not Confirmed.

      cef.remote-debugging-enabled  HIGH   CefSettings.RemoteDebuggingPort is set. DevTools is
                                       reachable on localhost with no authentication, so any
                                       local user can attach, execute JavaScript in the app's
                                       context, and reach the same bridge.

      cef.web-security-disabled  HIGH  WebSecurityDisabled = true. Same-origin policy is off,
                                       so a page loaded from any origin can read another and
                                       reach the bridge.

      cef.file-access-enabled    MEDIUM  --allow-file-access-from-files or the equivalent
                                       CefSharp setting. file:// pages get to read every
                                       file:// they can path to, including installed
                                       Chromium resources.

      cef.uses-cefsharp          INFO   Assembly references CefSharp but none of the flags
                                       above matched. Scoping only.

    This is INFERENCE. String presence in an assembly proves the assembly REFERENCES the type,
    not that the call is reached at runtime. Every rule here emits Confidence = Inferred; an
    IL check that traces from the type reference to an actual call site would justify
    Confirmed, and it is not run here. The static Confirmed grade is reserved for facts the
    file alone proves (a shipped firmware image existing on disk, a user-writable DACL); a
    call-graph reachability claim is not one of those.

.PARAMETER Path
    Install directory or a single .NET assembly.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Deduplicate at the finding level, since a big install can carry the same reference in
    # ten binaries and reporting it ten times swamps the report.
    $seen = [System.Collections.Generic.HashSet[string]]::new()

    $items = @()
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        try { $items = @(Get-TcpkPeFiles -Path $Path) } catch { return }
    } else {
        try { $items = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { return }
    }

    foreach ($pe in $items) {
        # First-party skip; the CefSharp assemblies themselves define these names.
        if ($pe.Name -imatch '^CefSharp') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        # A bare 'CefSharp' string as-is is enough to know this is a CEF-embedding host, since
        # every code path below assumes CefSharp is in play.
        $usesCef = ($text -match '(?<![A-Za-z0-9_])CefSharp(?:Settings)?(?![A-Za-z0-9_])') -or
                   ($text -match '(?<![A-Za-z0-9_])CefSettings(?![A-Za-z0-9_])') -or
                   ($text -match '(?<![A-Za-z0-9_])ChromiumWebBrowser(?![A-Za-z0-9_])')
        if (-not $usesCef) { continue }
        $fileHadHigher = $false

        # HIGH: the JS-to-native bridge is registered
        foreach ($api in 'RegisterJsObject', 'RegisterAsyncJsObject', 'JavascriptObjectRepository', 'Bind') {
            # Bind() is the modern async form on IJavascriptObjectRepository; the name is common
            # so also require a nearby JavascriptObjectRepository reference
            if ($api -eq 'Bind') {
                if (-not ($text -match 'JavascriptObjectRepository')) { continue }
            }
            if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])' + [regex]::Escape($api) + '(?![A-Za-z0-9_])')) {
                $key = "cef.js-bridge-registered|$($pe.FullName)|$api"
                if (-not $seen.Add($key)) { continue }
                $fileHadHigher = $true
                New-TcpkFinding -Module 'discovery' -RuleId 'cef.js-bridge-registered' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($pe.Name) references the CefSharp JS-to-native bridge API ($api)" `
                    -File $pe.FullName -Evidence "api=$api (string reference in the PE; call site not traced)" `
                    -Cwe @('CWE-749') `
                    -Description ('The assembly REFERENCES the CefSharp bridge that exposes .NET objects to ' +
                        'the embedded browser. The literal API name (' + $api + ') is present in the PE, so ' +
                        'the type is imported. This rule does NOT prove that the call is reached at runtime; ' +
                        'that would require an IL call-graph trace. Confidence is Inferred until that IL check ' +
                        'runs. If the call IS reached, every method on the registered bridge object becomes ' +
                        'callable from any JavaScript the renderer processes: a documentation iframe, a login ' +
                        'redirect back from an IdP, an XSS in vendor content, all reach process-privileged .NET.') `
                    -Fix ('Confirm the call site with an IL decompiler (Invoke-TcpkDecompile) or the AI-verify ' +
                        'layer, then: prefer JavascriptObjectRepository with async bindings and NameConverter ' +
                        'set to a strict subset; register a purpose-built bridge with only the methods you want ' +
                        'to expose, not a domain type; consider CEF ExtensionSettings and process-per-site so ' +
                        'a compromised renderer is contained.')
                break
            }
        }

        # HIGH: remote debugging on
        # RemoteDebuggingPort typically appears as a property assignment; string presence alone
        # is a strong signal since it is not a name used elsewhere.
        if ($text -match '(?<![A-Za-z0-9_])RemoteDebuggingPort(?![A-Za-z0-9_])') {
            $key = "cef.remote-debugging-enabled|$($pe.FullName)"
            if ($seen.Add($key)) {
                $fileHadHigher = $true
                New-TcpkFinding -Module 'discovery' -RuleId 'cef.remote-debugging-enabled' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($pe.Name) references CefSettings.RemoteDebuggingPort" `
                    -File $pe.FullName -Evidence 'symbol=RemoteDebuggingPort' `
                    -Cwe @('CWE-489') `
                    -Description ('The assembly references the Chromium remote-debugging-port setting. When ' +
                        'a value is assigned at runtime, DevTools is reachable on localhost with no ' +
                        'authentication, so any process running as the local user can attach and execute ' +
                        'JavaScript in the app - reaching whatever JS bridges the client has registered. ' +
                        'A capture with netstat during a session confirms the exposure.') `
                    -Fix ('Do not set RemoteDebuggingPort in a shipped build. Gate it behind a debug flag ' +
                        'that is not compiled into the release binary.')
            }
        }

        # HIGH: web security disabled
        if ($text -match '(?<![A-Za-z0-9_])WebSecurityDisabled(?![A-Za-z0-9_])' -or
            $text -match '--disable-web-security') {
            $key = "cef.web-security-disabled|$($pe.FullName)"
            if ($seen.Add($key)) {
                $fileHadHigher = $true
                New-TcpkFinding -Module 'discovery' -RuleId 'cef.web-security-disabled' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($pe.Name) references WebSecurityDisabled / --disable-web-security" `
                    -File $pe.FullName -Evidence 'flag=WebSecurityDisabled' `
                    -Cwe @('CWE-346') `
                    -Description ('Same-origin policy is off, so a document from any origin can read another ' +
                        'and reach any registered JS bridge. Combined with cef.js-bridge-registered this is ' +
                        'the standard cross-origin escape to native.') `
                    -Fix 'Never ship with web security disabled. If the app needs cross-origin data, expose a scoped IPC method on the bridge instead.'
            }
        }

        # MEDIUM: file:// access
        if ($text -match '--allow-file-access-from-files' -or
            $text -match '(?<![A-Za-z0-9_])UniversalAccessFromFileUrls(?![A-Za-z0-9_])' -or
            $text -match '(?<![A-Za-z0-9_])FileAccessFromFileUrls(?![A-Za-z0-9_])') {
            $key = "cef.file-access-enabled|$($pe.FullName)"
            if ($seen.Add($key)) {
                $fileHadHigher = $true
                New-TcpkFinding -Module 'discovery' -RuleId 'cef.file-access-enabled' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "$($pe.Name) enables file-scheme cross-access" `
                    -File $pe.FullName -Evidence 'flag=FileAccessFromFileUrls / --allow-file-access-from-files' `
                    -Cwe @('CWE-346') `
                    -Description ('A file:// page in this app can read every other file:// resource it can ' +
                        'reach, including installed Chromium resources and any bundled HTML. If any of that ' +
                        'HTML is user-influenced (help topic loaded from disk, printable report, exported ' +
                        'invoice) it is a local exfil primitive.') `
                    -Fix 'Do not enable file-scheme cross-access. Load in-app UI from a custom scheme with a scheme handler instead.'
            }
        }

        # INFO: nothing above matched, but the assembly does reference CefSharp. Report once
        # per file, for scope only.
        if (-not $fileHadHigher) {
            $key = "cef.uses-cefsharp|$($pe.FullName)"
            if ($seen.Add($key)) {
                New-TcpkFinding -Module 'discovery' -RuleId 'cef.uses-cefsharp' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) embeds Chromium via CefSharp" `
                    -File $pe.FullName -Evidence 'ref=CefSharp' `
                    -Description ('Scope only. The assembly hosts CefSharp / CEF. Combined with any XSS in ' +
                        'loaded pages, an insecure IPC surface, or a bridge object registration, the browser ' +
                        'is the pivot into managed code.') `
                    -Fix 'No fix required from this rule alone. See related cef.* findings if any fired.'
            }
        }
    }
}
