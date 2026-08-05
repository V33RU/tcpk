# C8 - Attribution: distinguish the target from its environment.
#
# The single largest false-positive class observed: five separate findings reported
# ambient host state as a property of the audited application - a certificate the
# app has no code to install, a COM CLSID belonging to an unrelated OS component,
# a handle to an OS registry key every process opens, an OS-default PATH directory,
# and a process-mitigation setting that is OFF for every process on the machine.
#
# Core question: WOULD THIS CONDITION EXIST IF THE TARGET WERE NOT INSTALLED?
#
# Attribution requires ONE of:
#   code-capability   - the target's code or installer can create this condition
#   install-footprint - the artifact is inside the target's install/data footprint
#   baseline-diff     - the condition differs from the host baseline
#
# A subject-name string match is NOT attribution.
# Attribution UNPROVEN -> demote to INFO; title the finding for the ambient condition.
# Explainability: every demotion records which evidence was missing.

# Known shared OS surfaces: conditions that exist on the host independent of the target.
# Normalized subject patterns (lowercase, forward-slash, as produced by Get-TcpkNormalizedSubject).
$script:TcpkSharedSurfaces = [ordered]@{
    'process-mitigation-policy' = @{
        NormPattern = 'hkey_local_machine/system/currentcontrolset/control/session manager/kernel'
        Ambient     = $true
        Description = 'OS kernel process-mitigation policy (HKLM Kernel); applies to every process on the machine, not just the target'
    }
    'system-environment-path' = @{
        NormPattern = 'hkey_local_machine/system/currentcontrolset/control/session manager/environment'
        Ambient     = $true
        Description = 'System-wide environment block (HKLM Environment); shared by all processes; a directory here is not a target artifact unless the target installer added it'
    }
    'machine-trust-store' = @{
        NormPattern = '^cert:/localmachine'
        Ambient     = $true
        Description = 'Machine-wide Windows certificate store (LocalMachine); managed by the OS; a certificate here was not necessarily installed by the target'
    }
    'system-com-clsid' = @{
        NormPattern = '^hkey_local_machine/software/classes/clsid'
        Ambient     = $true
        Description = 'System COM class registration (HKLM Classes); may belong to any installed component, not the audit target'
    }
    'system-com-wow64' = @{
        NormPattern = '^hkey_local_machine/software/wow6432node/classes/clsid'
        Ambient     = $true
        Description = 'System WOW64 COM class registration; same ambient status as HKLM Classes'
    }
    'per-user-trust-store' = @{
        NormPattern = '^cert:/currentuser'
        Ambient     = $false   # per-user; may be target-specific
        Description = 'Per-user certificate store (CurrentUser); may be installed by the target; requires footprint or code-capability evidence'
    }
    'per-user-com-clsid' = @{
        NormPattern = '^hkey_current_user/software/classes/clsid'
        Ambient     = $false
        Description = 'Per-user COM class registration (HKCU Classes); can be installed by the target per-user; requires footprint evidence'
    }
}

function Get-TcpkSharedSurfaceInfo {
<#
.SYNOPSIS
    C8 - Determine whether a subject falls on a known shared OS surface.

.OUTPUTS
    PSCustomObject {SurfaceType, Ambient, Description} or $null if not a known shared surface.
#>
    [CmdletBinding()]
    param([string]$NormalizedSubject)
    if (-not $NormalizedSubject) { return $null }
    foreach ($kv in $script:TcpkSharedSurfaces.GetEnumerator()) {
        if ($NormalizedSubject -match $kv.Value.NormPattern) {
            return [pscustomobject]@{
                SurfaceType = $kv.Key
                Ambient     = $kv.Value.Ambient
                Description = $kv.Value.Description
            }
        }
    }
    return $null
}

function New-TcpkAttributionEvidence {
<#
.SYNOPSIS
    C8 - Create an attribution evidence record.

.PARAMETER Type
    code-capability   - the target's code or installer has the capability to create this condition
    install-footprint - the artifact is under the target's install or data directory
    baseline-diff     - the measured value differs from the host baseline value for this surface
    name-match        - the only link is a name or string match (NOT attribution)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('code-capability','install-footprint','baseline-diff','name-match')]
        [string]$Type,
        [string]$Detail = ''
    )
    [pscustomobject]@{ Type=$Type; Detail=$Detail }
}

function Test-TcpkAttributionEstablished {
<#
.SYNOPSIS
    C8 - Evaluate attribution evidence and return a verdict.

.OUTPUTS
    PSCustomObject {Established, Basis, Explanation}
    Basis values: 'established-code' | 'established-footprint' | 'established-baseline-diff'
                  'name-match-only' | 'unproven'
#>
    [CmdletBinding()]
    param([object[]]$Evidence = @())

    $strong = @($Evidence | Where-Object { $_.Type -in 'code-capability','install-footprint','baseline-diff' })
    $nameOnly = @($Evidence | Where-Object { $_.Type -eq 'name-match' })

    if ($strong) {
        $best = $strong[0]
        $basis = switch ($best.Type) {
            'code-capability'  { 'established-code' }
            'install-footprint'{ 'established-footprint' }
            'baseline-diff'    { 'established-baseline-diff' }
        }
        return [pscustomobject]@{
            Established = $true
            Basis       = $basis
            Explanation = "Attribution established via $($best.Type): $($best.Detail)"
        }
    }
    if ($nameOnly) {
        return [pscustomobject]@{
            Established = $false
            Basis       = 'name-match-only'
            Explanation = "Only evidence is a name/string match ('$($nameOnly[0].Detail)'); this does not establish that the target created this condition"
        }
    }
    return [pscustomobject]@{
        Established = $false
        Basis       = 'unproven'
        Explanation = "No attribution evidence supplied; cannot determine whether the target created this condition"
    }
}

function Invoke-TcpkAttributionFilter {
<#
.SYNOPSIS
    C8 - Pipeline filter: demote findings with unproven attribution at report assembly.

.DESCRIPTION
    For each finding:
    - AttributionBasis='name-match-only' or 'unproven': demote to INFO/Unverified,
      prepend "AMBIENT: " to title (marks it as ambient host state, not a target finding),
      append CAP8: entry to AdjustmentLog.
    - AttributionBasis='': not yet migrated; pass through with a warning annotation only
      if the subject falls on a known Ambient=true shared surface.
    - AttributionBasis='established-*': no action.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings
    )
    begin { $buf = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { if ($f) { $buf.Add($f) } } }
    end {
        foreach ($f in $buf) {
            $basis = "$($f.AttributionBasis)".Trim()

            if ($basis -in 'name-match-only','unproven') {
                $oldSev = $f.Severity
                $reason = if ($basis -eq 'name-match-only') {
                    "Only evidence linking this condition to the target is a name/string match. C8: a name match is not attribution."
                } else {
                    "No attribution evidence was established. C8: cannot determine whether the target created this condition."
                }
                $f.Severity    = 'INFO'
                $f.Confidence  = 'Unverified'
                if (-not $f.Title.StartsWith('AMBIENT: ')) { $f.Title = "AMBIENT: $($f.Title)" }
                $entry = "CAP8: ${oldSev}->INFO; AttributionBasis=$basis; $reason"
                $f.AdjustmentLog = @($f.AdjustmentLog) + @($entry)
                $f
                continue
            }

            if (-not $basis) {
                # Un-migrated rule; warn only if subject is on a known Ambient surface
                $subj = Get-TcpkNormalizedSubject "$($f.Subject)"
                $surface = Get-TcpkSharedSurfaceInfo -NormalizedSubject $subj
                if ($surface -and $surface.Ambient) {
                    $warn = "CAP8: WARNING - subject '$subj' is on shared OS surface '$($surface.SurfaceType)' ($($surface.Description)); attribution not verified by this rule (AttributionBasis not set)"
                    $f.AdjustmentLog = @($f.AdjustmentLog) + @($warn)
                }
            }

            $f
        }
    }
}
