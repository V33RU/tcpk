function Test-TcpkWmiPersistence {
<#
.SYNOPSIS
    C16. WMI permanent event subscriptions (persistence mechanism).

.DESCRIPTION
    A WMI permanent event subscription (__EventFilter + an EventConsumer +
    __FilterToConsumerBinding in root\subscription) runs code as SYSTEM when a
    trigger fires and survives reboots. It is a well-known APT persistence and
    privilege-execution technique that few legitimate desktop apps need.

    Reports any filter / consumer / binding whose name or payload matches the
    product. CommandLine/ActiveScript consumers are HIGH (they run code);
    others are MEDIUM.

.PARAMETER NameLike
    Vendor/product substring to match.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkWmiPersistence')) { return }

    $ns = 'root/subscription'
    function _match($s) { return ("$s" -match [regex]::Escape($NameLike)) }

    # Consumers (the code-execution end)
    foreach ($cls in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
        $items = $null
        try { $items = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction Stop } catch { continue }
        foreach ($c in $items) {
            $payload = "$($c.Name) $($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText) $($c.ScriptFileName)"
            if (-not (_match $payload)) { continue }
            $detail = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptFileName) { $c.ScriptFileName } else { $c.ScriptText }
            New-TcpkFinding -Module 'os' -RuleId 'wmi.event-consumer' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WMI $cls persistence: $($c.Name)" `
                -File "${ns}:${cls}.Name=$($c.Name)" -Evidence "$detail" -Cwe @('CWE-506','CWE-269') `
                -Description 'A WMI permanent event consumer executes code (as SYSTEM) when its bound filter fires, and persists across reboots. This is a classic persistence/EoP technique. Confirm it is an intentional, documented product behavior and not attacker-planted.' `
                -Fix 'If not required, remove the subscription. If required, document it and lock down who can modify root\subscription.'
        }
    }

    # Filters (the trigger end) -- MEDIUM
    $filters = $null
    try { $filters = Get-CimInstance -Namespace $ns -ClassName '__EventFilter' -ErrorAction Stop } catch { }
    foreach ($flt in $filters) {
        if (-not (_match "$($flt.Name) $($flt.Query)")) { continue }
        New-TcpkFinding -Module 'os' -RuleId 'wmi.event-filter' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "WMI event filter: $($flt.Name)" `
            -File "${ns}:__EventFilter.Name=$($flt.Name)" -Evidence "$($flt.Query)" -Cwe @('CWE-506') `
            -Description 'WMI event filter associated with the product. Inspect its bound consumer to determine what runs when it triggers.'
    }
}
