function Test-TcpkAiInferenceServer {
<#
.SYNOPSIS
    F13. Does the target ship a local LLM inference server, and how is it bound?

.DESCRIPTION
    Some thick clients ship a local LLM inference server: an HTTP listener for a model API
    (OpenAI-compatible /v1/... routes or an engine's own routes). This static check reads
    the shipped files and reports that listener and its bind posture.

    It separates three roles and reports only the first as a weakness:

      server          a listener for a model API           -> aiserver.bind-all-interfaces (HIGH)
                                                               aiserver.local-server       (MEDIUM)
      engine library  in-process tensor / model runtime     -> aiserver.engine-library      (INFO)
      client          holds the address of a separately     -> aiserver.local-llm-client    (INFO)
                      installed inference server

    A server is established per file by one of: a known engine server binary (file name);
    in a launcher or classic configuration file (.bat, .cmd, .ps1, .env, .ini, .yaml,
    .config, .xml ...), the engine's host variable assigned an all-interfaces address or the
    engine's server on a command line with its host / port flag, written as an assignment
    or a command and not quoted inside a sentence; two or more model API routes matched as
    whole tokens together with an engine marker and a router-side path parameter; a route
    registration call with a model API route as its argument; in a compiled .NET assembly,
    a route-mapping member together with two or more model API routes held as string
    literals. A product name alone establishes nothing, and it does not tie a bind on 1234,
    1337, 3001 or 4891 to a model API either: those are also ordinary development ports. A
    route a client would also hold establishes nothing. The rules, and the reason for each,
    are in Private\_AiServer.ps1.

    TEXT IS NOT A SETTING. In a script bundle, a JSON file or a compiled file the same
    characters can be a help screen, a locale string or a message, so there:
      * NAME=value or an engine command line held as one whole string literal is shown in
        Evidence and never rated, and never establishes a server;
      * a key with a separately quoted value, an argument array, or a command string passed
        to a process-start call counts only when that engine's server binary is under the
        scan root;
      * an address written as text (http://0.0.0.0:11434, 0.0.0.0:11434) is never rated.
        In a configuration file it counts only when a server on that port is established
        elsewhere under the scan root.

    LIMITS. This check does not see: a model API server written with attribute-routed
    controllers or a raw HttpListener in a compiled assembly, or with a renamed receiver in
    a minified script bundle (the generic listener is still reported by
    Test-TcpkSelfHostedServer); a bind whose host flag and engine executable are on
    different lines or in variables; a target that starts an inference server it does not
    ship. A compiled client that both maps its own routes and calls a remote model API can
    be read as a server by the route-mapping rule. Treat a MEDIUM here as a lead and settle
    it with Confirm-TcpkAiInferenceServer.

    What is read: PE files (.exe / .dll / .node), first-party JavaScript (.asar archives and
    loose .js outside node_modules, which covers an unpacked app tree), and configuration /
    launcher files (.json, .jsonc, .env, .yaml, .toml, .ini, .cfg, .conf, .config, .xml,
    .properties, .bat, .cmd, .ps1). Electron and Tauri products keep the server in script
    and configuration, not in a PE. Comments, templates and test files are not read as
    configuration.

    Output is ONE server finding per scan root, with Evidence that names the files and the
    signals in each, plus at most one inventory finding for engine libraries and, only when
    no server was found, at most one for a client endpoint.

    Severity:
      * HIGH    an all-interfaces bind that is a setting for the server: the engine's
                host variable or host flag in a launcher or configuration file (or in
                structured code next to that engine's server binary), a configuration
                value on a port the server is established on, or an all-interfaces address
                passed to the listen call of the code that registers the model API routes
      * MEDIUM  the server role is established and no such bind was recognised. Address
                text that is not rated is listed in Evidence; a listen call that passes no
                address is stated as that, and the Description then makes no loopback
                assumption.

    Everything here is a string signal, so Confidence is Inferred. Whether the server is
    started, which address it binds at run time, and whether the API asks for a credential
    are observed by Confirm-TcpkAiInferenceServer against the running endpoint.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $rootItem = $null
    try { $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return }
    if (-not $rootItem) { return }

    $scan = $null
    try { $scan = New-TcpkAiScanState -Root $rootItem } catch { return }
    $rootLeaf = "$($rootItem.Name)"

    # Both enumerators are consumed through the pipeline, one file at a time, so their
    # per-check budget test and heartbeat run between files. A foreach statement would
    # collect the whole sequence first and spend the budget tests before reading anything.
    # Nothing in either loop may throw: the audit runner discards a check's whole output if
    # it does.
    try {
        Get-TcpkPeFiles -Path $Path | ForEach-Object {
            try { Add-TcpkAiFileEvidence -File $_ -Kind 'pe' -Scan $scan } catch { }
        }
    } catch { }
    try {
        Get-TcpkAiTextFiles -Path $Path | ForEach-Object {
            try { Add-TcpkAiFileEvidence -File $_.File -Kind $_.Kind -Scan $scan } catch { }
        }
    } catch { }

    try {
        # ---- server: one finding per scan root ----
        $servers = @(Complete-TcpkAiScan -Scan $scan)

        if ($servers.Count -gt 0) {
            $primary  = $servers[0]
            $evidence = Format-TcpkAiServerEvidence -Files $servers
            $affected = [string[]]@($servers | Select-Object -First 25 | ForEach-Object { "$($_.Full)" })
            $binds    = @($servers | ForEach-Object { $_.AllInterfaces } | Where-Object { $_ })
            $staticNote = ' This is a static reading of shipped files. It does not show that the server is started, which address it binds at run time, or whether the API asks for a credential -- Confirm-TcpkAiInferenceServer probes the running endpoint and reports what it observes.'

            if ($binds.Count -gt 0) {
                $f = New-TcpkFinding -Module 'network' -RuleId 'aiserver.bind-all-interfaces' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Local LLM inference server with an all-interfaces bind in $rootLeaf" `
                    -File $primary.Full -Evidence $evidence `
                    -Cwe @('CWE-1327', 'CWE-306') `
                    -AttributionBasis 'established-footprint' -Subject $primary.Full `
                    -Dimension 'listener-bind' -ObsValue ('"' + $binds[0] + '"') -Basis 'Inferred' `
                    -Description ('The target ships a local LLM inference server (an HTTP listener for a model API) together with a bind for it that names every network interface. The Evidence shows the bind: an all-interfaces address on a known inference port, the engine''s own host setting, or an all-interfaces address passed to the listen call of the code that registers the model API routes. A listener bound this way accepts connections from other hosts on the network, not only from this machine.' + $staticNote) `
                    -Fix 'Bind the inference server to 127.0.0.1 unless remote access is a requirement. If it must be reachable from the network, require a credential on every route and limit the listener with a firewall rule.'
                $f.Affected = $affected
                $f
            } else {
                $obs = 'not-stated'
                $sup = @($servers | ForEach-Object { $_.Support } | Where-Object { $_ })
                if ($sup.Count -gt 0) { $obs = "$($sup[0])" }

                # The Description must say what the Evidence says about the bind, no more.
                #   * a listen call with no address: the runtime default decides the
                #     interface, so no loopback bind is assumed;
                #   * an all-interfaces bind that could not be tied to the server: named as
                #     listed and not rated;
                #   * neither: the rating assumes a loopback bind, and says so.
                $noHost = (@($servers | Where-Object { $_.NoHostListen }).Count -gt 0)
                $untied = (@($servers | ForEach-Object { $_.OtherWild } | Where-Object { $_ }).Count -gt 0)
                $desc = 'The target ships a local LLM inference server (an HTTP listener for a model API). The Evidence names the files and the signals that establish it.'
                if ($noHost) {
                    $obs = 'listen-without-address'
                    $desc += ' A listen call in the Evidence passes no address, so the runtime default decides which interfaces the listener uses, and the shipped files do not show a loopback bind. No all-interfaces address is written in them either, which is why this is rated MEDIUM and not HIGH.'
                }
                if ($untied) {
                    $desc += ' The Evidence also lists all-interfaces address text found in a server file that this check does not rate: it is text in code or inside a string literal, or it is on a port no server is established on, so it could not be tied to the inference listener as a setting. It is listed for review and is not used for the rating.'
                }
                if (-not $noHost -and -not $untied) {
                    $desc += ' This check recognised no all-interfaces bind in the files it read. The bind address is therefore not established, and the rating assumes a loopback bind.'
                }
                $desc += ' On any bind, other local processes can reach the listener, and a web page can reach it through the browser if the API accepts cross-origin requests without a credential.'
                $desc += $staticNote
                $f = New-TcpkFinding -Module 'network' -RuleId 'aiserver.local-server' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "Local LLM inference server shipped in $rootLeaf" `
                    -File $primary.Full -Evidence $evidence `
                    -Cwe @('CWE-306') `
                    -AttributionBasis 'established-footprint' -Subject $primary.Full `
                    -Dimension 'listener-bind' -ObsValue ('"' + $obs + '"') -Basis 'Inferred' `
                    -Description $desc `
                    -Fix 'Keep the listener on 127.0.0.1, require a credential on every route, and check the Origin and Host headers against an allow-list. Verify the live posture with Confirm-TcpkAiInferenceServer.'
                $f.Affected = $affected
                $f
            }
        }

        # ---- engine libraries: one inventory finding per scan root ----
        $libs = @($scan.Libraries.ToArray() | Sort-Object Rel)
        if ($libs.Count -gt 0) {
            # Select-Object -Unique is case-sensitive; file names on Windows are not.
            $seenName = @{}
            $names = New-Object 'System.Collections.Generic.List[string]'
            foreach ($l in $libs) {
                $k = "$($l.Name)".ToLowerInvariant()
                if ($seenName.ContainsKey($k)) { continue }
                $seenName[$k] = $true
                $names.Add("$($l.Name)")
            }
            $shownNames = @($names.ToArray() | Select-Object -First 6)
            $ev = "$($libs.Count) file(s): " + ($shownNames -join ', ')
            if ($names.Count -gt $shownNames.Count) { $ev += " (+$($names.Count - $shownNames.Count) more name(s))" }
            $ev += ' | identified by tensor / model-runtime API symbol names (ggml_, gguf_, llama_) in the file'
            $f = New-TcpkFinding -Module 'network' -RuleId 'aiserver.engine-library' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "In-process inference engine libraries shipped in $rootLeaf ($($libs.Count) file(s))" `
                -File $libs[0].Full -Evidence $ev `
                -AttributionBasis 'established-footprint' -Subject $libs[0].Full `
                -Description 'The target ships in-process inference engine libraries: tensor and model-runtime code that an application loads into its own process. A library of this kind opens no socket and is listed for inventory only. A separate aiserver finding is raised when the target also ships a listener for a model API.'
            $f.Affected = [string[]]@($libs | Select-Object -First 25 | ForEach-Object { "$($_.Full)" })
            $f
        }

        # ---- client: only when no server was found, and only for a concrete endpoint ----
        $clients = @($scan.Clients.ToArray() | Sort-Object Rel)
        if ($servers.Count -eq 0 -and $clients.Count -gt 0) {
            $parts = New-Object 'System.Collections.Generic.List[string]'
            $parts.Add("loopback inference endpoint in $($clients.Count) file(s)")
            foreach ($c in @($clients | Select-Object -First 4)) {
                $parts.Add("$($c.Rel): " + (@($c.Client | Select-Object -First 3) -join '; '))
            }
            if ($clients.Count -gt 4) { $parts.Add("(+$($clients.Count - 4) more file(s))") }
            $parts.Add('no server binary, bind setting or route registration found under the scan root')
            $ev = Get-TcpkRedact ($parts.ToArray() -join ' | ')
            # The link between the target and an inference server is a string in a shipped
            # file. The server it points at is not part of the target, so by the attribution
            # rules this is a name / string match, not attribution.
            $f = New-TcpkFinding -Module 'network' -RuleId 'aiserver.local-llm-client' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "Loopback LLM inference endpoint referenced in $rootLeaf (no bundled server found)" `
                -File $clients[0].Full -Evidence $ev `
                -AttributionBasis 'name-match-only' -Subject $clients[0].Full `
                -Description 'A shipped file holds the address of a model API on this machine: a loopback host with a known inference port. No server binary, bind setting or route registration for such a server was found under the scan root, so the target appears to be a client of an inference server that is installed separately. That server is not part of the audited target. Listed for context only.'
            $f.Affected = [string[]]@($clients | Select-Object -First 25 | ForEach-Object { "$($_.Full)" })
            $f
        }
    } catch { }
}
