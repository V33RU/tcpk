# Private helpers for the autonomous lead-triage agent (Invoke-TcpkTriageAgent).
# Kept out of the Public cmdlet file so the module's one-cmdlet-per-file export convention holds.

# A lead is still a lead if a confirmer has not moved it out of 'Inferred'/'Unverified'.
function Test-TcpkIsLead {
    [CmdletBinding()] param([Parameter(Mandatory)]$Finding)
    return ("$($Finding.Confidence)" -match '^(Inferred|Unverified)$')
}

# Narrate a triage step using the confirmer's OWN annotation, never an invented reason. Both the
# IL confirmer and the LLM skeptic append a bracketed note ("[TCPK IL: ...]" / "[TCPK LLM: ...]")
# to the Description; the last bracketed note is the verdict's reason. Empty when none was added.
function Get-TcpkTriageReason {
    [CmdletBinding()] param([Parameter(Mandatory)]$Finding)
    $desc = "$($Finding.Description)"
    if (-not $desc) { return '' }
    $m = [regex]::Matches($desc, '\[[^\]]+\]')
    if ($m.Count) { return $m[$m.Count - 1].Value }
    return ''
}
