function Invoke-TcpkDynamicConfirm {
<#
.SYNOPSIS
    GATED, observation-only dynamic confirmation: does the target app TRUST a
    command-line / deep-link session override at runtime? (Dynamic harness, slice 1.)

.DESCRIPTION
    The static check electron.argv-session-override is INFERRED -- it sees the app parse
    --host / --token from the command line, but cannot prove the app FOLLOWS them. This
    proves it, without exploitation:

      1. TCPK starts a loopback TCP listener on a random port.
      2. It launches the target with  <HostArg> 127.0.0.1:<port>  <TokenArg> <SENTINEL>.
      3. It observes whether the app CONNECTS to that listener (and whether it forwards
         the sentinel token).

    A connection demonstrates the app follows an attacker-supplied connection target from
    the command line -- reachable via a crafted shortcut, a file-association launch, or a
    forwarded second-instance argument. The finding is then 'Confirmed (dynamic)'.

    BENIGN BY DESIGN: the only "payload" is a loopback connection and a random sentinel
    string. No code execution, no real credentials, nothing destructive. The target is
    launched minimized and killed when the probe ends.

    GATED: run Enable-TcpkExploit -Acknowledge first, AND pass -ConfirmDynamic. Use only
    on software you are authorized to test.

.PARAMETER Target
    Path to the application executable to launch.

.PARAMETER ConfirmDynamic
    Required. Acknowledges that this LAUNCHES the target (dynamic, not static).

.PARAMETER HostArg
    The host-override flag the app accepts (default '--host'). Filled with TCPK's listener.

.PARAMETER TokenArg
    The token-override flag (default '--token'). Filled with a generated sentinel.

.PARAMETER ExtraArgs
    Extra launch arguments the app needs (e.g. a project file to open).

.PARAMETER TimeoutSec
    Seconds to wait for the app to connect (default 12).

.OUTPUTS
    [TcpkFinding] -- 'Confirmed (dynamic)' if the app connected, else an INFO note.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [switch]$ConfirmDynamic,
        [string]$HostArg = '--host',
        [string]$TokenArg = '--token',
        [string[]]$ExtraArgs = @(),
        [int]$TimeoutSec = 12
    )

    Assert-TcpkExploitEnabled 'Invoke-TcpkDynamicConfirm'
    if (-not (Assert-TcpkWindows 'Invoke-TcpkDynamicConfirm')) { return }
    if (-not $ConfirmDynamic) {
        throw "Invoke-TcpkDynamicConfirm LAUNCHES the target application. Re-run with -ConfirmDynamic to acknowledge (authorized targets only)."
    }
    if (-not (Test-Path -LiteralPath $Target)) { throw "Target not found: $Target" }

    $sentinel  = 'TCPKDYN' + ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $listener  = $null; $proc = $null; $connected = $false; $received = ''; $remote = ''
    try {
        $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
        $listener.Start()
        $port    = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $hostval = "127.0.0.1:$port"
        $argList = @($HostArg, $hostval, $TokenArg, $sentinel) + @($ExtraArgs)

        Write-TcpkInfo "[dynamic] launching $(Split-Path $Target -Leaf) $HostArg $hostval $TokenArg <sentinel> (loopback observe, ${TimeoutSec}s)"
        $proc = Start-Process -FilePath $Target -ArgumentList $argList -PassThru -WindowStyle Minimized -ErrorAction Stop

        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $deadline) {
            if ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                $connected = $true
                try { $remote = "$($client.Client.RemoteEndPoint)" } catch { }
                try {
                    $client.ReceiveTimeout = 800
                    $ns = $client.GetStream()
                    Start-Sleep -Milliseconds 300
                    if ($ns.CanRead -and $ns.DataAvailable) {
                        $buf = New-Object byte[] 4096
                        $n = $ns.Read($buf, 0, 4096)
                        if ($n -gt 0) { $received = [Text.Encoding]::ASCII.GetString($buf, 0, $n) }
                    }
                } catch { }
                try { $client.Close() } catch { }
                break
            }
            Start-Sleep -Milliseconds 200
        }
    } finally {
        if ($listener) { try { $listener.Stop() } catch { } }
        if ($proc -and -not $proc.HasExited) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { } }
    }

    $echoed = $received -and ($received -match [regex]::Escape($sentinel))
    if ($connected) {
        $ev = "app connected to the CLI-supplied host ($remote)"
        if ($echoed) { $ev += "; sentinel token observed on the wire" }
        New-TcpkFinding -Module 'runtime' -RuleId 'dynamic.argv-session-override' `
            -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
            -Title 'Command-line host/token override is followed at runtime' `
            -File $Target -Evidence $ev -Cwe @('CWE-88','CWE-20') `
            -Description ("Launched with $HostArg 127.0.0.1:<tcpk-listener> $TokenArg <sentinel>, the app connected to the TCPK-controlled host" + $(if ($echoed) { ' and forwarded the sentinel token' } else { '' }) + ". This DEMONSTRATES the app trusts a command-line / deep-link supplied connection target: a crafted shortcut, file-association launch, or forwarded second-instance argument can redirect the session to attacker infrastructure (and, where a token is forwarded, leak or substitute it). Delivery requires user interaction (opening the crafted link/file). Upgrades the static electron.argv-session-override finding from Inferred to demonstrated.") `
            -Fix 'Treat command-line / deep-link host and token values as untrusted: require explicit user confirmation before connecting to a CLI-supplied host or applying a CLI-supplied credential; pin/allow-list expected hosts.'
    } else {
        New-TcpkFinding -Module 'runtime' -RuleId 'dynamic.argv-session-override' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Command-line override probe inconclusive' `
            -File $Target -Evidence "no connection to the CLI-supplied host within ${TimeoutSec}s" -Cwe @('CWE-88') `
            -Description "The app did not connect to the TCPK-supplied host within the timeout. It may not honour $HostArg, may require a project/file argument (pass -ExtraArgs), or may connect only after further interaction. The static electron.argv-session-override finding stands as Inferred." `
            -Fix 'Re-test with the correct launch arguments (-ExtraArgs), or review the argv-parsing data flow manually.'
    }
}
