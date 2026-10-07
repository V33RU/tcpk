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
    param([string[]]$NameLike, [string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkWmiPersistence')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $ns = 'root/subscription'
    function _match($s) { return (Test-TcpkTermMatch -Text "$s" -Terms $terms) }

    # Consumers (the code-execution end)
    foreach ($cls in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
        # root/subscription is the most provider-fragile namespace on the box; the wrapper
        # bounds it and records the gap so an unreachable namespace does not read as
        # "no WMI persistence found".
        $items = @(Get-TcpkCimSafe -ClassName $cls -Namespace $ns)
        if (-not $items.Count) { continue }
        foreach ($c in $items) {
            $payload = "$($c.Name) $($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText) $($c.ScriptFileName)"
            if (-not (_match $payload)) { continue }
            $detail = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ScriptFileName) { $c.ScriptFileName } else { $c.ScriptText }
            $sa = Resolve-TcpkHostStateBasis -ImagePath $detail -TargetRoot $Path -ActionableSeverity 'HIGH' -Subject "${ns}:${cls}.Name=$($c.Name)" -MatchDetail "WMI $cls consumer '$($c.Name)' matched target term"
            New-TcpkFinding -Module 'os' -RuleId 'wmi.event-consumer' `
                -Severity $sa.Severity -Confidence 'Confirmed' `
                -Title "WMI $cls persistence: $($c.Name)" `
                -File "${ns}:${cls}.Name=$($c.Name)" -Evidence "$detail" -Cwe @('CWE-506','CWE-269') `
                -Description 'A WMI permanent event consumer executes code (as SYSTEM) when its bound filter fires, and persists across reboots. This is a classic persistence/EoP technique. Confirm it is an intentional, documented product behavior and not attacker-planted.' `
                -AttributionBasis $sa.Basis -Subject $sa.Subject `
                -Fix 'If not required, remove the subscription. If required, document it and lock down who can modify root\subscription.'
        }
    }

    # Filters (the trigger end) -- MEDIUM
    $filters = @(Get-TcpkCimSafe -ClassName '__EventFilter' -Namespace $ns)
    foreach ($flt in $filters) {
        if (-not (_match "$($flt.Name) $($flt.Query)")) { continue }
        # A WMI __EventFilter carries only a WQL query, no filesystem path, so attribution to
        # the target can never be established here; it resolves to name-match-only (AMBIENT/INFO).
        $sa = Resolve-TcpkHostStateBasis -ImagePath '' -TargetRoot $Path -ActionableSeverity 'MEDIUM' -Subject "${ns}:__EventFilter.Name=$($flt.Name)" -MatchDetail "WMI event filter '$($flt.Name)' matched target term"
        New-TcpkFinding -Module 'os' -RuleId 'wmi.event-filter' `
            -Severity $sa.Severity -Confidence 'Confirmed' `
            -Title "WMI event filter: $($flt.Name)" `
            -File "${ns}:__EventFilter.Name=$($flt.Name)" -Evidence "$($flt.Query)" -Cwe @('CWE-506') `
            -AttributionBasis $sa.Basis -Subject $sa.Subject `
            -Description 'WMI event filter associated with the product. Inspect its bound consumer to determine what runs when it triggers.'
    }
}
