function Test-TcpkWv2Sideload {
<#
.SYNOPSIS
    Detect WebView2 DLL sideloading opportunities.

.DESCRIPTION
    Microsoft Edge WebView2 embeds Chromium inside thick-client apps via
    msedgewebview2.exe -- a signed Microsoft binary.  When an application
    ships a "fixed version" of the WebView2 runtime (rather than using the
    evergreen installer), the entire runtime lives in the application tree.
    If that tree is user-writable, an attacker can plant a proxy DLL and
    achieve code execution under the signed Edge process.

    Known sideload targets specific to WebView2:
      - domain_actions.dll (Black Hills InfoSec 2025)
      - EmbeddedBrowserWebView.dll, msedge_elf.dll
      - Various Chromium support DLLs loaded at startup

    Checks:
      1. Whether the app uses WebView2 (PE imports / references).
      2. Whether a fixed-version runtime is shipped in the app dir.
      3. Whether the fixed-version dir is user-writable (HIGH).
      4. Whether known sideload target DLLs are absent from the runtime dir.

    MITRE ATT&CK T1574.002 (DLL Side-Loading).

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $usesWv2 = $false
    $wv2Markers = @('WebView2Loader.dll', 'Microsoft.Web.WebView2.Core.dll',
                     'Microsoft.Web.WebView2.WinForms.dll', 'Microsoft.Web.WebView2.Wpf.dll')

    $appFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            [void]$appFiles.Add($_.Name)
            if ($_.Name -in $wv2Markers) { $usesWv2 = $true }
        }

    if (-not $usesWv2) {
        foreach ($pe in Get-TcpkPeFiles -Path $Path) {
            if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
            $text = Read-TcpkAllText -Path $pe.FullName
            if ($text -and ($text.Contains('CoreWebView2') -or $text.Contains('WebView2'))) {
                $usesWv2 = $true
                break
            }
        }
    }

    if (-not $usesWv2) { return }

    $fixedDirs = @(Get-ChildItem -LiteralPath $root -Recurse -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)^(Microsoft\.WebView2\.FixedVersionRuntime|EBWebView)$' -or
                       (Test-Path -LiteralPath (Join-Path $_.FullName 'msedgewebview2.exe')) })

    $wv2SideloadTargets = @(
        'domain_actions.dll', 'EmbeddedBrowserWebView.dll', 'msedge_elf.dll',
        'chrome_elf.dll', 'libEGL.dll', 'libGLESv2.dll', 'd3dcompiler_47.dll',
        'vk_swiftshader.dll', 'vulkan-1.dll', 'eventlog_provider.dll'
    )
    $sideloadSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $wv2SideloadTargets) { [void]$sideloadSet.Add($s) }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'

    foreach ($fd in $fixedDirs) {
        $dirWritable = $false
        try {
            $acl = Get-Acl -LiteralPath $fd.FullName -ErrorAction Stop
            $bad = $acl.Access | Where-Object {
                $_.IdentityReference.Value -match $userPrincipals -and
                $_.FileSystemRights -match $writeRights -and
                $_.AccessControlType -eq 'Allow'
            }
            $dirWritable = ($null -ne $bad -and @($bad).Count -gt 0)
        } catch {}

        $relDir = $fd.FullName
        if ($relDir.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relDir = $relDir.Substring($root.Length).TrimStart('\')
        }

        if ($dirWritable) {
            $ev = @($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
            New-TcpkFinding -Module 'static' -RuleId 'wv2.fixed-version-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WebView2 fixed-version dir is user-writable: $relDir" `
                -File $fd.FullName `
                -Evidence $ev.Substring(0, [Math]::Min(200, $ev.Length)) `
                -Cwe @('CWE-427','CWE-732') `
                -Description ('The application ships a fixed-version WebView2 runtime in a directory ' +
                    'that is writable by non-admin users. An attacker can plant a proxy DLL ' +
                    '(e.g. domain_actions.dll) that executes under the signed msedgewebview2.exe ' +
                    'process, bypassing application allowlisting. (ATT&CK T1574.002)') `
                -Fix 'Install the fixed-version runtime in a directory with admin-only write ACLs, or use the evergreen WebView2 installer.'
        }

        $runtimeFiles = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        Get-ChildItem -LiteralPath $fd.FullName -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$runtimeFiles.Add($_.Name) }

        $missing = @($wv2SideloadTargets | Where-Object { -not $runtimeFiles.Contains($_) })
        if ($missing.Count -gt 0 -and $dirWritable) {
            New-TcpkFinding -Module 'static' -RuleId 'wv2.sideload-surface' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WebView2 sideload targets plantable in writable dir: $relDir" `
                -File $fd.FullName `
                -Evidence "missing: $(($missing | Select-Object -First 5) -join ', ')" `
                -Cwe @('CWE-427') `
                -Description ('Known WebView2 sideload-target DLLs are not present in the runtime ' +
                    'directory AND the directory is user-writable. An attacker can plant these DLLs ' +
                    'to achieve code execution under msedgewebview2.exe (a signed Microsoft binary). ' +
                    'Ref: Black Hills InfoSec 2025 domain_actions.dll sideload.') `
                -Fix 'Lock down the runtime directory ACL to admin-only, or bundle all required DLLs.'
        }
    }

    if ($fixedDirs.Count -eq 0) {
        $udFolder = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
        if (-not (Test-Path -LiteralPath $udFolder)) {
            $udFolder = Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\User Data'
        }
        if (Test-Path -LiteralPath $udFolder) {
            try {
                $acl = Get-Acl -LiteralPath $udFolder -ErrorAction Stop
                $bad = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -match $userPrincipals -and
                    $_.FileSystemRights -match $writeRights -and
                    $_.AccessControlType -eq 'Allow'
                }
                if ($null -ne $bad -and @($bad).Count -gt 0) {
                    New-TcpkFinding -Module 'os' -RuleId 'wv2.user-data-writable' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title 'WebView2 user data folder has broad write access' `
                        -File $udFolder `
                        -Evidence (@($bad | ForEach-Object { "$($_.IdentityReference)" }) -join ', ') `
                        -Cwe @('CWE-732') `
                        -Description ('The WebView2 user data folder (cache, cookies, profile) is ' +
                            'writable by non-admin users beyond the current user. Another local user ' +
                            'can tamper with cached resources or inject malicious extensions.') `
                        -Fix 'Verify the user data folder ACL restricts write access to the owning user and SYSTEM.'
                }
            } catch {}
        }
    }
}
