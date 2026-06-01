function Test-TcpkMsixProtocols {
<#
.SYNOPSIS
    B03. URI scheme handlers declared in AppxManifest.xml.

.DESCRIPTION
    Every <uap:Extension Category="windows.protocol"> registers a URI scheme
    the OS will hand to this app. That makes any input parsing in the app's
    protocol-activation handler an attacker-reachable code path -- e.g. via
    a crafted "myapp://..." link in a browser or doc.

.PARAMETER Path
    MSIX file or extracted directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $expanded = Expand-TcpkMsix -Path $Path
    $m = Read-TcpkAppxManifest -ExpandedPath $expanded
    if (-not $m) { return }
    $nsm = Get-TcpkAppxNsMgr -Manifest $m
    if (-not $nsm) { return }

    $schemes = @()
    foreach ($node in $m.DocumentElement.SelectNodes('//uap:Extension[@Category="windows.protocol"]', $nsm)) {
        $scheme = if ($node.Protocol) { $node.Protocol.Name } else { '(unknown)' }
        $schemes += $scheme
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.protocol-handler' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "URI scheme handler declared: ${scheme}://" `
            -File $Path -Evidence $scheme `
            -Cwe @('CWE-20','CWE-94') `
            -Description "The OS will deliver ${scheme}:// URIs to this app's activation handler. Treat the URI string as attacker-controlled input." `
            -Fix 'Validate the scheme, host, and arguments strictly; reject anything not on an allow-list.'
    }

    # Depth pass: a declared handler is only remotely dangerous if the activation
    # input can reach a sink. Scan first-party binaries for the combination and,
    # when found, emit a HIGH 'protocol.sink-reachable' finding -- which the chain
    # correlator (Get-TcpkExploitChains) elevates to CRITICAL alongside the handler.
    if ($schemes.Count -gt 0) {
        $hint = ($schemes | Select-Object -First 1)
        foreach ($s in (Get-TcpkUriActivationSink -Path $expanded)) {
            $bn = [IO.Path]::GetFileName($s.File)
            New-TcpkFinding -Module 'manifest' -RuleId 'protocol.sink-reachable' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Activation input may reach a dangerous sink in $bn" `
                -File $s.File `
                -Evidence ("activation: " + ($s.Activation -join ', ') + "  |  sinks: " + ($s.Sinks -join ', ')) `
                -Cwe @('CWE-20','CWE-94') `
                -Description "This binary BOTH handles activation arguments ($($s.Activation -join ', ')) AND references dangerous sinks ($($s.Sinks -join ', ')). If a ${hint}:// URI (or an associated file path) reaches one of those sinks without validation, a crafted link delivers code execution. Decompile the activation handler to confirm the data flow." `
                -Fix 'Trace the activation argument to each sink; validate / allow-list scheme, host, arguments, and any derived path before any process launch, deserialization, or filesystem operation.'
        }
    }
}
