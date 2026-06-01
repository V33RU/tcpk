# Get-TcpkUriActivationSink - static reachability heuristic for protocol/file
# activation. A binary is interesting only when it BOTH receives activation input
# (a URI / file the OS hands the app) AND references a dangerous sink that input
# could flow into. Either alone is benign; together they form a remote entry point.
#
# Private helper. Used by Test-TcpkMsixProtocols (and reusable by file-assoc checks).

function Get-TcpkUriActivationSink {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # markers that the binary consumes activation arguments (URI / launch / file)
    $activation = @(
        'ProtocolActivatedEventArgs','FileActivatedEventArgs','IProtocolActivatedEventArgs',
        'OnActivated','GetActivatedEventArgs','LaunchActivatedEventArgs',
        'Windows.ApplicationModel.Activation','ActivationKind','AppInstance.GetActivatedEventArgs'
    )
    # dangerous sinks attacker-controlled activation input could reach
    $sinks = @(
        'Process.Start','ProcessStartInfo','ShellExecute','CreateProcess',
        'BinaryFormatter','NetDataContractSerializer','LosFormatter','SoapFormatter','JavaScriptSerializer',
        'Path.Combine','File.WriteAllBytes','File.WriteAllText','File.Copy',
        'LoadLibrary','Assembly.Load','Assembly.LoadFrom','Assembly.LoadFile'
    )

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $aHit = @($activation | Where-Object { $text.Contains($_) })
        if ($aHit.Count -eq 0) { continue }
        $sHit = @($sinks | Where-Object { $text.Contains($_) })
        if ($sHit.Count -eq 0) { continue }
        $out.Add([pscustomobject]@{
            File       = $pe.FullName
            Activation = $aHit
            Sinks      = $sHit
        })
    }
    $out
}
