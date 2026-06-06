function Test-TcpkUiLeakSurface {
<#
.SYNOPSIS
    A37. UI data-leak surface: screen-capture protection and clipboard-history hygiene.

.DESCRIPTION
    Two OWASP Desktop / TASVS UI-security controls that are statically detectable on
    Windows but that most thick-client checks ignore:

      * Screen-capture protection -- a sensitive window should call
        SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) so screenshots / screen
        recorders / remote-desktop capture cannot read it. If the app handles
        passwords / secret input (PasswordBox, SecureString, PasswordChar, ...) but
        never references SetWindowDisplayAffinity, the sensitive screens are
        capturable.

      * Clipboard history / cloud clipboard -- Clipboard.SetText / SetDataObject /
        SetClipboardData copies land in the Windows Clipboard History (Win+V) and
        roam to other devices via Cloud Clipboard unless the copy is tagged
        "ExcludeClipboardContentFromMonitorProcessing" / CanIncludeInClipboardHistory
        = false. Copying a password / token without that tag leaks it.

    First-party binaries only (framework files skipped). Findings are Inferred
    (a reference is not proof the sensitive path uses it); decompile to confirm.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $captureApi   = @('SetWindowDisplayAffinity')
    $clipWrite    = @('SetDataObject', 'SetClipboardData', 'Windows.ApplicationModel.DataTransfer', 'DataPackage')
    $clipExclude  = @('ExcludeClipboardContentFromMonitorProcessing', 'CanIncludeInClipboardHistory', 'IsRoamable')
    $sensitive    = @('PasswordBox', 'SecureString', 'UseSystemPasswordChar', 'PasswordChar', 'ProtectedData')
    $guiMarkers   = @('PresentationFramework', 'System.Windows.Forms', 'Microsoft.UI.Xaml', 'PresentationCore')

    $hasCapture = $false; $hasClipWrite = $false; $hasClipExclude = $false
    $hasSensitive = $false; $hasGui = $false
    $clipFiles = New-Object System.Collections.Generic.List[string]
    $sensFiles = New-Object System.Collections.Generic.List[string]

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        if ($captureApi  | Where-Object { $text.Contains($_) }) { $hasCapture = $true }
        if ($clipExclude | Where-Object { $text.Contains($_) }) { $hasClipExclude = $true }
        if ($guiMarkers  | Where-Object { $text.Contains($_) }) { $hasGui = $true }
        $cw = @($clipWrite | Where-Object { $text.Contains($_) })
        if ($cw.Count) { $hasClipWrite = $true; $clipFiles.Add($pe.Name) }
        $sm = @($sensitive | Where-Object { $text.Contains($_) })
        if ($sm.Count) { $hasSensitive = $true; $sensFiles.Add($pe.Name) }
    }

    # Clipboard copies without a history/roaming exclusion tag.
    if ($hasClipWrite -and -not $hasClipExclude) {
        New-TcpkFinding -Module 'static' -RuleId 'ui.clipboard-no-history-exclusion' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'Clipboard writes without history / cloud-clipboard exclusion' `
            -File (($clipFiles | Select-Object -Unique) -join ', ') `
            -Evidence ("clipboard-write APIs referenced; no ExcludeClipboardContentFromMonitorProcessing / CanIncludeInClipboardHistory marker found") `
            -Cwe @('CWE-200') `
            -Description 'The app copies data to the clipboard but never tags a copy to be excluded from Windows Clipboard History (Win+V) or Cloud Clipboard. Any sensitive value copied (password, token, account number) persists in history and can roam to the user other devices.' `
            -Fix 'For sensitive copies, set the DataObject/DataPackage property "ExcludeClipboardContentFromMonitorProcessing"=true (and CanIncludeInClipboardHistory=false / IsRoamable=false on WinRT), and consider clearing the clipboard after a timeout.'
    }

    # Sensitive-input GUI app with no screen-capture protection.
    if ($hasGui -and $hasSensitive -and -not $hasCapture) {
        New-TcpkFinding -Module 'static' -RuleId 'ui.no-screen-capture-protection' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Sensitive-input UI with no screen-capture protection' `
            -File (($sensFiles | Select-Object -Unique) -join ', ') `
            -Evidence 'password / secret-input markers present; SetWindowDisplayAffinity not referenced' `
            -Cwe @('CWE-200') `
            -Description 'The app collects secret input (password box / SecureString / masked field) but no window calls SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE). Screenshots, screen recorders, and remote-desktop / screen-share tools can capture the sensitive screen.' `
            -Fix 'Call SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) on windows that display secrets so they render blank to screen capture.'
    }
}
