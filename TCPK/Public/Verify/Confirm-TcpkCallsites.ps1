function Confirm-TcpkCallsites {
<#
.SYNOPSIS
    Phase-2 confirmation for dangerous-API callsite findings.

.DESCRIPTION
    Test-TcpkCallsites emits Confidence 'Inferred' because a substring match proves
    a dangerous API NAME is present in the binary, not that the API is constructed
    or called (the string could sit in a comment, a resource, or a dependency name).

    This cmdlet reads the finding's Evidence (the matched pattern fragments, e.g.
    'MD5CryptoServiceProvider', 'SHA1Managed') and uses the Mono.Cecil bridge
    (Get-TcpkCallSites) to look for an actual call / callvirt / newobj instruction
    targeting that type. If a real call site exists the finding is promoted to
    Confidence 'Confirmed' and the sites are written to Evidence. Fragments that are
    enum fields or constants (e.g. a CipherMode.ECB value) have no call site and
    correctly leave the finding 'Inferred'.

    Requires Mono.Cecil (ships with ILSpy).

.PARAMETER Finding
    One or more [TcpkFinding] objects (pipeline). Non callsites.* findings pass through.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [TcpkFinding[]] $Finding
    )

    process {
        foreach ($f in $Finding) {
            if ($f.RuleId -notlike 'callsites.*' -or [string]::IsNullOrEmpty($f.File) -or -not (Test-Path -LiteralPath $f.File)) {
                $f
                continue
            }

            # Evidence is the comma-joined list of matched API fragments.
            $fragments = @()
            if ($f.Evidence) { $fragments = $f.Evidence -split '\s*,\s*' | Where-Object { $_ } }
            if ($fragments.Count -eq 0) { $f; continue }

            $hits = New-Object 'System.Collections.Generic.List[object]'
            $cecil = $true
            foreach ($frag in $fragments) {
                $sites = Get-TcpkCallSites -DllPath $f.File -TypeFragment $frag
                if ($null -eq $sites -and -not (Test-TcpkCecilAvailable)) { $cecil = $false; break }
                foreach ($s in @($sites)) { if ($s) { $hits.Add($s) } }
            }

            if (-not $cecil) {
                $f.Description = "$($f.Description) [TCPK confirm: Mono.Cecil unavailable; confidence left at $($f.Confidence).]"
                $f
                continue
            }

            if ($hits.Count -gt 0) {
                $where = (($hits | Select-Object -First 5) | ForEach-Object { "$($_.Type)::$($_.Method) ($($_.Op) -> $($_.Target))" }) -join '; '
                $f.Confidence = 'Confirmed'
                $f.Evidence   = $where
                $f.Description = "$($f.Description) [TCPK confirmed via IL: API is invoked at $where.]"
            } else {
                $f.Description = "$($f.Description) [TCPK confirm: API name is present but no call/newobj site was found (likely a constant, enum value, or dependency reference); confidence left at $($f.Confidence).]"
            }
            $f
        }
    }
}
