function Test-TcpkGuiInspector {
<#
.SYNOPSIS
    E17. Live GUI object inspection (UI Automation) -- hidden/disabled controls
    and password fields on the RUNNING app.

.DESCRIPTION
    Uses Windows UI Automation (the engine behind WinSpy/Accessibility Insights)
    to walk the target's windows and surface client-side GUI weaknesses:
      - DISABLED controls (buttons/menu items) named like admin/advanced/debug/
        license features -- often re-enableable to unlock gated functionality.
      - OFFSCREEN / hidden elements with sensitive names.
      - PASSWORD fields -- candidates for unmasking (set Password=false / read value).

    Requires the app to be RUNNING. Returns nothing if the process isn't found.

.PARAMETER ProcessName
    Process name (no .exe), e.g. 'YourApp'.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProcessName)

    if (-not (Assert-TcpkWindows 'Test-TcpkGuiInspector')) { return }
    $procs = Get-TcpkProcess -ProcessName $ProcessName
    if (-not $procs) { return }   # app not running -> nothing to inspect

    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes  -ErrorAction Stop
    } catch {
        New-TcpkFinding -Module 'runtime' -RuleId 'gui.uia-unavailable' -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'UI Automation assemblies unavailable -- GUI inspection skipped' -File $ProcessName -Evidence $_.Exception.Message
        return
    }

    $AE = [System.Windows.Automation.AutomationElement]
    $TS = [System.Windows.Automation.TreeScope]
    $CT = [System.Windows.Automation.ControlType]
    $sensitive = '(?i)(admin|advanced|debug|develop|license|activat|unlock|premium|pro\b|hidden|internal|diagnostic|backdoor|root|superuser|bypass|engineer|factory|service\s*mode|maintenance)'

    foreach ($p in $procs) {
        $root = $AE::RootElement
        $cond = New-Object System.Windows.Automation.PropertyCondition($AE::ProcessIdProperty, $p.Id)
        $windows = $null
        try { $windows = $root.FindAll($TS::Children, $cond) } catch { continue }
        if (-not $windows) { continue }

        foreach ($w in $windows) {
            # --- password fields ---
            try {
                $editCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::Edit)
                foreach ($e in $w.FindAll($TS::Descendants, $editCond)) {
                    $isPwd = $false
                    try { $isPwd = [bool]$e.GetCurrentPropertyValue($AE::IsPasswordProperty) } catch { }
                    if ($isPwd) {
                        $nm = try { $e.Current.Name } catch { '' }
                        New-TcpkFinding -Module 'runtime' -RuleId 'gui.password-field' -Severity 'LOW' -Confidence 'Confirmed' `
                            -Title "Password field present: '$nm'" -File "$($p.Name) (PID $($p.Id))" `
                            -Evidence "AutomationId=$(try{$e.Current.AutomationId}catch{''})" -Cwe @('CWE-549') `
                            -Description 'A masked password field. Via UI Automation / WinSpy you can often set Password=false (or read the ValuePattern) to reveal typed credentials. Confirm the field does not expose the plaintext.'
                    }
                }
            } catch { }

            # --- disabled controls with sensitive names ---
            try {
                $disCond = New-Object System.Windows.Automation.PropertyCondition($AE::IsEnabledProperty, $false)
                $cnt = 0
                foreach ($d in $w.FindAll($TS::Descendants, $disCond)) {
                    if ($cnt -ge 60) { break }
                    $nm = try { $d.Current.Name } catch { '' }
                    if (-not $nm) { continue }
                    if ($nm -match $sensitive) {
                        $cnt++
                        New-TcpkFinding -Module 'runtime' -RuleId 'gui.disabled-privileged-control' -Severity 'MEDIUM' -Confidence 'Inferred' `
                            -Title "Disabled privileged control: '$nm'" -File "$($p.Name) (PID $($p.Id))" `
                            -Evidence "ControlType=$(try{$d.Current.ControlType.ProgrammaticName}catch{''})" -Cwe @('CWE-602') `
                            -Description 'A disabled control whose name suggests privileged/hidden functionality. Try re-enabling it via UI Automation (set IsEnabled / send the invoke pattern) -- if the action runs, access control is client-side only.' `
                            -Fix 'Enforce authorization server-side; do not rely on a disabled control to protect a privileged action.'
                    }
                }
            } catch { }

            # --- offscreen/hidden elements with sensitive names ---
            try {
                $offCond = New-Object System.Windows.Automation.PropertyCondition($AE::IsOffscreenProperty, $true)
                $cnt = 0
                foreach ($o in $w.FindAll($TS::Descendants, $offCond)) {
                    if ($cnt -ge 40) { break }
                    $nm = try { $o.Current.Name } catch { '' }
                    if ($nm -and $nm -match $sensitive) {
                        $cnt++
                        New-TcpkFinding -Module 'runtime' -RuleId 'gui.hidden-privileged-element' -Severity 'MEDIUM' -Confidence 'Inferred' `
                            -Title "Hidden/offscreen privileged element: '$nm'" -File "$($p.Name) (PID $($p.Id))" `
                            -Evidence "ControlType=$(try{$o.Current.ControlType.ProgrammaticName}catch{''})" -Cwe @('CWE-602') `
                            -Description 'A hidden/offscreen UI element with a sensitive name. Make it visible (UI Automation) and confirm the gated functionality is not reachable without proper authorization.'
                    }
                }
            } catch { }
        }
    }
}
