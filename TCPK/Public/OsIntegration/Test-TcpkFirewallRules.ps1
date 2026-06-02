function Test-TcpkFirewallRules {
<#
.SYNOPSIS
    C16. Windows Firewall rules created by the app (overly-broad inbound).

.DESCRIPTION
    Parses the firewall rule registry (fast, no CIM) and flags INBOUND ALLOW
    rules attributable to this app (App path or rule Name matches -NameLike /
    -Path). An inbound allow with no remote-address restriction -- especially on
    the Public profile -- exposes a local service to the whole network.

    Severity:
      * inbound allow, remote = Any (or Public profile)  -> HIGH
      * inbound allow, restricted remote                 -> MEDIUM
      * outbound / informational                         -> INFO

.PARAMETER NameLike
    Vendor/package substring.

.PARAMETER Path
    Optional install dir to match the rule's App= executable path.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string[]]$NameLike = @(),
        [string]$Path
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkFirewallRules')) { return }
    $terms = Get-TcpkNameTerms -NameLike $NameLike

    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    $props = $null
    try { $props = Get-ItemProperty -Path $key -ErrorAction Stop } catch { return }
    if (-not $props) { return }

    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name.StartsWith('PS')) { continue }
        $data = "$($p.Value)"
        if (-not $data) { continue }

        # parse 'k=v|k=v|...' (first token is the version, no '=')
        $h = @{}
        foreach ($tok in ($data -split '\|')) {
            $i = $tok.IndexOf('=')
            if ($i -gt 0) { $h[$tok.Substring(0,$i)] = $tok.Substring($i+1) }
        }

        $app  = "$($h['App'])"
        $name = "$($h['Name'])"
        $dir  = "$($h['Dir'])"
        $act  = "$($h['Action'])"

        # attribute to this app
        $match = $false
        if ($terms.Count) {
            if ((Test-TcpkTermMatch -Text $app -Terms $terms) -or (Test-TcpkTermMatch -Text $name -Terms $terms)) { $match = $true }
        }
        if ($Path -and $app -and $app -like "$Path*") { $match = $true }
        if (-not $match) { continue }
        if ($act -ne 'Allow') { continue }

        if ($dir -eq 'In') {
            $remoteRestricted = $h.ContainsKey('RA4') -or $h.ContainsKey('RA6') -or $h.ContainsKey('RA42') -or $h.ContainsKey('RA62')
            $profile = "$($h['Profile'])"   # may be empty = all profiles
            $broad = (-not $remoteRestricted) -or ($profile -eq '' -or $profile -match 'Public')
            $sev = if ($broad) { 'HIGH' } else { 'MEDIUM' }
            $ev = "Dir=In Action=Allow App=$app LPort=$($h['LPort']) Protocol=$($h['Protocol']) Profile=$(if($profile){$profile}else{'All'}) Remote=$(if($remoteRestricted){'restricted'}else{'Any'})"
            New-TcpkFinding -Module 'os' -RuleId 'firewall.inbound-allow' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Inbound firewall allow rule: $name" `
                -File $key -Evidence $ev -Cwe @('CWE-284') `
                -Description 'The app installs an inbound allow rule. Combined with an unauthenticated local service/listener this exposes the app to the network; a broad (Any remote / Public profile) rule widens that to the whole LAN.' `
                -Fix 'Scope inbound rules to the minimum required port, the Private/Domain profile, and a restricted remote address. Remove the rule if the listener is local-only.'
        }
        # Outbound/allow rules are not emitted -- they are not a vulnerability and
        # only add noise. Inbound allow is the security-relevant case above.
    }
}
