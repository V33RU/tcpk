function Confirm-TcpkAiInferenceServer {
<#
.SYNOPSIS
    Live probe of a local LLM inference server: is its model list answering without a
    credential, does it accept a foreign Origin or Host header, and (only when the
    server is proven to be Ollama) is its version below a known fixed release.

.DESCRIPTION
    Active network probe. Requires: Enable-TcpkExploit -Acknowledge.

    WHAT IS SENT. For each endpoint the cmdlet opens a TCP connection and then sends
    HTTP GET requests, with no credential, no cookie and no automatic logon, to these
    four paths on the host and port being probed (the one the caller named, or a
    default loopback port in a sweep), and to nothing else:

        /api/tags      always
        /v1/models     always
        /              only after /api/tags returned a models array, or /v1/models
                       returned a model list
        /api/version   only after a model list was counted

    GET / and GET /api/version do two jobs: they carry Ollama's banner and version,
    and they are two more routes on which the server can ask for a credential.

    After a model list was counted and no probed route asked for a credential, that
    one GET is repeated twice with a single header changed: once with a foreign
    Origin header and once with a foreign Host header. That is at most six requests
    per endpoint. Redirects are never followed, no proxy is used, and no generate,
    chat, pull, push, create or delete route is ever requested. A host name is
    resolved once and every request goes to the address that accepted the TCP
    connection. A response is read to the end or not used at all: one that is larger
    than 1 MB, or not complete within -TimeoutMs, is reported as no complete
    response, with no status code.

    WHAT COUNTS AS PROOF.
      * aiserver.unauth-reachable: a request with no credential returned HTTP 200 and
        a JSON body of the expected shape (/api/tags an object with a models array,
        /v1/models an object with a data array), and no probed route asked for a
        credential. An HTML page, an empty body, a redirect or any other JSON is not
        a model list. On a server proven to be Ollama this is an unauthenticated
        model API: MEDIUM when the connected address is loopback, HIGH otherwise. On
        a product that was not identified it is LOW, a model list that is readable
        without a credential and nothing more: the inference routes are never
        requested, and some servers keep the model list public while they ask for a
        key on every other route. A probed route that answered 403 without
        WWW-Authenticate is neither a credential check nor the lack of one: the
        finding is still reported, and its Description names that route.
      * aiserver.origin-unchecked: the repeat with a foreign Host header returned the
        model list, or the repeat with a foreign Origin header returned it together
        with a permissive Access-Control-Allow-Origin (a wildcard, or the foreign
        origin itself). HIGH on a proven Ollama, LOW on a product that was not
        identified, where the model list is all that is shown to be reachable that
        way. A foreign Origin answered without such a header is written into the
        Evidence of aiserver.unauth-reachable and is not a finding: a page on
        another site cannot read that answer.
      * aiserver.ollama-probllama-version: the endpoint is proven to be Ollama (its
        models array on /api/tags together with its banner on /) and /api/version
        returned a plain x.y.z version, not 0.0.0, that is below 0.1.34. The port
        number is never used as identity. The vulnerable route is not requested.
      * aiserver.reachable-authed (INFO): a probed route answered 401, or 403 carrying
        WWW-Authenticate. A server whose model list is readable while another probed
        route asks for a credential is recorded here, with both facts in the Title,
        and not as an unauthenticated API.
      * aiserver.port-open-unidentified (INFO): the port is open but no model list
        was returned. A 3xx and a 403 without WWW-Authenticate are reported here as
        what they are, with no posture implied.

    A refused connection means nothing is listening: no finding, no error.

    ATTRIBUTION. Without -Endpoint the cmdlet sweeps the default loopback ports. The
    operator's own machine may run an inference server on one of them (TCPK's own
    triage backend defaults to port 11434), so a listener found by the sweep is
    reported at an actionable severity only when the image of the process that owns
    the port is under -Path. Otherwise it is INFO, AttributionBasis 'unproven', and
    worded as a local inference server on this host (a listener, when it returned
    no model list) that is not shown to belong to the audited target.

    An endpoint passed with -Endpoint is the operator's own statement of scope and
    keeps its severity, with one exception: when -Path is given as well and the image
    of the process that owns the port is found to be outside it, the measurement
    outranks the statement. The records are then INFO and 'unproven', as in a sweep,
    and a warning says so. Run again without -Path to report such an endpoint on the
    operator's statement alone.

    The owning process is looked up on Windows and printed in Evidence in both
    modes. An owner that cannot be resolved never attributes a swept listener, and
    never takes a named endpoint out of scope.

    Probing a non-loopback -Endpoint is active testing of that host and needs
    authorization for it.

.PARAMETER Endpoint
    One or more endpoints: host:port, [ipv6]:port, a bare port (loopback), or a URL
    such as http://127.0.0.1:11434/ (the scheme and path are dropped). When omitted,
    127.0.0.1 is swept on ports 11434, 1234, 1337, 4891 and 3001.

.PARAMETER Path
    Install root of the audited target (a file is taken as its folder). Used only
    for attribution: is the image of the process that owns the listening port under
    this folder.

.PARAMETER TimeoutMs
    Bound, in milliseconds, for each TCP connect and for each whole HTTP exchange
    including the body. 100 to 120000. Default 3000.

.PARAMETER Finding
    Findings from the pipeline are passed through unchanged, so the cmdlet can sit
    after Test-TcpkAiInferenceServer. A static lead is not rewritten: the live
    findings are separate records about the listener that was probed.

.EXAMPLE
    Enable-TcpkExploit -Acknowledge
    Confirm-TcpkAiInferenceServer -Endpoint 127.0.0.1:11434 -Path 'C:\Program Files\App'

.EXAMPLE
    Test-TcpkAiInferenceServer -Path .\App | Confirm-TcpkAiInferenceServer -Path .\App

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string[]]$Endpoint,
        [ValidateRange(100, 120000)][int]$TimeoutMs = 3000,
        [string]$Path,
        [Parameter(ValueFromPipeline)][TcpkFinding[]]$Finding
    )

    begin {
        Assert-TcpkExploitEnabled 'Confirm-TcpkAiInferenceServer'
    }

    process {
        foreach ($lead in $Finding) { if ($null -ne $lead) { $lead } }
    }

    end {
        $fn = 'Confirm-TcpkAiInferenceServer'
        $forms = 'Accepted forms: host:port, [ipv6]:port, a port number, or a URL such as http://host:port/'
        $notCalled = 'No generate, chat, pull, push, create or delete route was requested.'

        # ----- target root for attribution -------------------------------------------------
        # Resolved against the PowerShell location here: the footprint test below resolves
        # against the process directory, which is not the same thing for a relative path.
        $root = ''
        if ($Path) {
            $root = $Path
            try {
                if (Test-Path -LiteralPath $Path) {
                    $full = "$((Resolve-Path -LiteralPath $Path -ErrorAction Stop | Select-Object -First 1).ProviderPath)"
                    if ($full -and (Test-Path -LiteralPath $full -PathType Leaf)) { $full = Split-Path -Parent $full }
                    if ($full) { $root = $full }
                } else {
                    Write-Warning "${fn}: -Path '$Path' does not exist, so no listener can be attributed to it."
                }
            } catch { }
        }

        # ----- endpoint list ---------------------------------------------------------------
        # -Endpoint given = the operator named the scope. Omitted = a sweep of this machine.
        $explicit = $PSBoundParameters.ContainsKey('Endpoint')
        $rawList = @()
        if ($explicit) {
            $rawList = @($Endpoint | Where-Object { $null -ne $_ -and "$_".Trim() })
            if ($rawList.Count -eq 0) {
                Write-Warning "${fn}: -Endpoint was supplied but holds no value. Nothing was probed. Omit -Endpoint to sweep the default loopback ports."
                return
            }
        } else {
            $rawList = @(Get-TcpkAiDefaultEndpoint)
        }

        $seen = @{}
        foreach ($rawEp in $rawList) {
            # What the warnings print: never the part of the value that can hold a password.
            $shown = Get-TcpkAiEndpointLabel -Text "$rawEp"
            try {
                $ep = ConvertTo-TcpkAiEndpoint -Text "$rawEp"
                if (-not $ep.Ok) {
                    Write-Warning "${fn}: endpoint '$shown' was not probed: $($ep.Reason). $forms"
                    continue
                }
                if ($ep.Note) { Write-Warning "${fn}: endpoint '$shown': $($ep.Note)." }

                $obs = Invoke-TcpkAiProbe -EndpointHost $ep.Host -Port $ep.Port -TimeoutMs $TimeoutMs -AlreadyProbed $seen

                if ($obs.State -eq 'refused') {
                    Write-Verbose "${fn}: $shown refused the connection (nothing listening)."
                    continue
                }
                if ($obs.State -eq 'duplicate') {
                    # The same listener named a second way: nothing more is sent to it.
                    Write-Verbose "${fn}: $shown connects to $($obs.HostPort), which was already probed."
                    continue
                }
                if ($obs.State -ne 'connected') {
                    # A sweep of closed loopback ports stays quiet; a named endpoint that could
                    # not be reached is said out loud so an empty result is not read as clean.
                    $why = $obs.Detail
                    if (-not $why) { $why = $obs.State }
                    if ($explicit -or $obs.State -ne 'timeout') {
                        Write-Warning "${fn}: endpoint '$shown' was not probed: $why."
                    } else {
                        Write-Verbose "${fn}: $shown did not answer ($why)."
                    }
                    continue
                }

                $hostport = $obs.HostPort
                $seen[$hostport] = $true
                $addrText = $obs.Address.ToString()

                # ----- attribution ---------------------------------------------------------
                $owner = $null
                if (Test-TcpkAiLocalAddress -Address $obs.Address) {
                    $owner = Get-TcpkAiListenerOwner -Port $ep.Port -Address $obs.Address
                }
                $ownerImage = ''
                if ($owner -and $owner.Resolved) { $ownerImage = "$($owner.ImagePath)" }

                # Footprint is the only link this cmdlet can measure: the owning image under -Path.
                # The image path is passed quoted: it is one path, not a command line, and the
                # helper would otherwise cut an unquoted value at the first ".exe" it sees.
                $imageArg = ''
                if ($ownerImage) { $imageArg = '"' + $ownerImage + '"' }
                $hs = Resolve-TcpkHostStateBasis -ImagePath $imageArg -TargetRoot $root -Subject $hostport
                $underPath = [bool]$hs.Established

                # Strongest evidence first:
                #   owning image under -Path            -> measured footprint, in both modes
                #   named endpoint, image outside -Path -> measured against the target: the
                #                                          measurement outranks the statement
                #   named endpoint, nothing measured    -> the operator's statement of scope,
                #                                          the convention of the other active
                #                                          probes that take an operator-named
                #                                          target
                #   swept listener, anything else       -> unproven
                $actionable = $false
                $basis = 'unproven'
                $outside = $false
                if ($underPath) {
                    $actionable = $true
                    $basis = "$($hs.Basis)"
                } elseif ($explicit) {
                    if ($root -and $ownerImage) {
                        $outside = $true
                        Write-Warning "${fn}: the process that owns $hostport runs from '$ownerImage', which is not under -Path. Its records are reported as INFO and not attributed to the target. Run again without -Path to report this endpoint on your own statement of scope."
                    } else {
                        $actionable = $true
                        $basis = 'established-code'
                    }
                }

                $ownerText = 'listener owner: not looked up (the address is not on this machine)'
                if ($owner) {
                    if ($owner.Resolved) {
                        $ownerText = "listener owner: PID $($owner.ProcessId)"
                        if ($owner.ProcessName) { $ownerText += " ($($owner.ProcessName))" }
                        $ownerText += " $ownerImage"
                        if (-not $root)      { $ownerText += '; -Path not given' }
                        elseif ($underPath)  { $ownerText += '; image is under -Path' }
                        else                 { $ownerText += '; image is not under -Path' }
                    } else {
                        $ownerText = "listener owner: not resolved ($($owner.Note))"
                    }
                }
                $scopeText = 'scope: default loopback port sweep'
                if ($explicit) { $scopeText = 'scope: endpoint named with -Endpoint' }

                $loopText = 'not loopback'
                if ($obs.IsLoopback) { $loopText = 'loopback' }
                $ctxParts = @("connected address $addrText ($loopText)")
                $namedAs = "$($ep.Host)".Trim()
                if ($namedAs -and $namedAs -ne $addrText) { $ctxParts += "endpoint given as $(Get-TcpkAiSafeText -Text $namedAs -Max 80):$($ep.Port)" }
                $ctxParts += $scopeText
                $ctxParts += $ownerText
                $ctx = $ctxParts -join ' | '

                # Wording for a listener that is not tied to the target.
                # $unattrDesc is for a listener that returned a model list; $unattrPlain is for one
                # that did not, which must not be called an inference server either.
                $unattrTitle = ''
                $unattrDesc  = ''
                $unattrPlain = ''
                if (-not $actionable) {
                    $unattrTitle = ' (not shown to belong to the audited target)'
                    if ($outside) {
                        # Named endpoint, owning image measured outside -Path.
                        $unattrHead = ' The endpoint was named with -Endpoint, but the process that owns the port runs from an image that is not under -Path. That measurement outranks the statement of scope, so this is reported as '
                        $unattrTail = ' and not as a finding about the audited target. To report the endpoint on the statement of scope alone, run again without -Path.'
                    } elseif ($root -and $ownerImage) {
                        # Swept listener, owning image measured outside -Path.
                        $unattrHead = ' This listener was found by sweeping the default loopback ports of the machine TCPK runs on, and the process that owns the port runs from an image that is not under -Path, so this is reported as '
                        $unattrTail = ' and not as a finding about the audited target. These are also the ports an inference server installed by the operator listens on.'
                    } else {
                        # Swept listener, nothing measured: no -Path, or the owner was not resolved.
                        $unattrHead = ' This listener was found by sweeping the default loopback ports of the machine TCPK runs on. The image of the process that owns the port was not shown to be under -Path, so this is reported as '
                        $unattrTail = ' and not as a finding about the audited target. These are also the ports an inference server installed by the operator listens on, so a listener here says nothing about the target by itself. To assert that the listener belongs to the target, pass its install root with -Path or name the endpoint with -Endpoint.'
                    }
                    $unattrDesc  = $unattrHead + 'a local inference server on this host' + $unattrTail
                    $unattrPlain = $unattrHead + 'a listener on this host' + $unattrTail
                }

                $tagsLine = Format-TcpkAiRouteEvidence -Path '/api/tags'  -Response $obs.Tags -List $obs.TagsList
                $v1Line   = Format-TcpkAiRouteEvidence -Path '/v1/models' -Response $obs.V1   -List $obs.V1List
                $base     = "http://$hostport"

                # GET / and GET /api/version, when they were sent. They go into every record of
                # this endpoint, so Evidence always lists each request that was made.
                $idLines = @()
                if ($obs.Root) {
                    if ($obs.Banner) { $idLines += 'GET / -> 200, Ollama banner' }
                    elseif ($obs.Root.Status -eq 200) { $idLines += 'GET / -> 200, no Ollama banner' }
                    else { $idLines += (Format-TcpkAiRouteEvidence -Path '/' -Response $obs.Root -List $null) }
                }
                if ($obs.Ver) {
                    if ($obs.Ver.Status -ne 200)  { $idLines += (Format-TcpkAiRouteEvidence -Path '/api/version' -Response $obs.Ver -List $null) }
                    elseif (-not $obs.Ollama)     { $idLines += 'GET /api/version -> 200, body not used (the server is not identified as Ollama)' }
                    elseif ($obs.Version -and $obs.VersionZero) { $idLines += "GET /api/version -> 200, version $($obs.Version) (unstamped build, not comparable)" }
                    elseif ($obs.Version)         { $idLines += "GET /api/version -> 200, version $($obs.Version)" }
                    elseif ($obs.VersionText)     { $idLines += "GET /api/version -> 200, version text '$($obs.VersionText)' is not a plain x.y.z number, not compared" }
                    else                          { $idLines += 'GET /api/version -> 200, no version field' }
                }

                # ===== a model list came back ===============================================
                if ($obs.ListSeen) {
                    $identified = [bool]$obs.Ollama
                    $countText = "$($obs.List.Total) entries"
                    if ($obs.List.Total -eq 1) { $countText = '1 entry' }
                    $listFact = "GET $($obs.Route) was sent with no credential and returned HTTP 200 with a JSON model list ($countText)."

                    if ($obs.Unauth) {
                        # ----- no probed route asked for a credential ---------------------------
                        # Identified Ollama: the listener serves the whole API, so this is rated
                        # as an unauthenticated model API. Anything else: only the model list was
                        # shown to be readable, and that is what is rated.
                        $sev = 'LOW'
                        if ($identified) {
                            $sev = 'HIGH'
                            if ($obs.IsLoopback) { $sev = 'MEDIUM' }
                        }
                        $cvss = ''
                        if (-not $actionable) { $sev = 'INFO' }
                        elseif ($obs.IsLoopback) {
                            # Proven loopback: the caller is a local process, so the vector is the
                            # local band for this severity, not the network band the rule family maps to.
                            try { $cvss = "$($script:TcpkCvssBandVector['local'][$sev])" } catch { $cvss = '' }
                        }

                        # The two header variants, exactly as answered. They go into this finding's
                        # Evidence whether or not they were accepted, so a rejection is on record too.
                        $originLine = Format-TcpkAiRouteEvidence -Path $obs.Route -Response $obs.OriginVar -List $obs.OriginList -Variant "Origin: $($script:TcpkAiForeignOrigin)"
                        if ($obs.OriginVar -and $obs.OriginVar.Status -ne 0) {
                            if ($obs.AcaoClass -eq 'none') { $originLine += ', no Access-Control-Allow-Origin' }
                            else { $originLine += ", Access-Control-Allow-Origin: $($obs.AcaoText)" }
                        }
                        $hostLine = Format-TcpkAiRouteEvidence -Path $obs.Route -Response $obs.HostVar -List $obs.HostList -Variant "Host: $($script:TcpkAiForeignHost):$($ep.Port)"
                        $permissive = ($obs.AcaoClass -eq 'wildcard' -or $obs.AcaoClass -eq 'echo')

                        # What gives a page on another site something: the list returned for a
                        # foreign Host, or returned for a foreign Origin with a header that lets
                        # that origin read it. A foreign Origin answered without such a header is
                        # an observation, kept in Evidence and in the Description below.
                        $hostHit   = [bool]$obs.HostAccepted
                        $originHit = ([bool]$obs.OriginAccepted -and $permissive)
                        $originBlind = ([bool]$obs.OriginAccepted -and -not $permissive)

                        $varNote = ''
                        if ($hostHit -or $originHit) {
                            $varNote = ' Cross-origin handling is reported separately under aiserver.origin-unchecked.'
                        } else {
                            if ($originBlind) { $varNote = ' The repeat of this request with a foreign Origin header returned the list as well, with no permissive Access-Control-Allow-Origin, which does not let a page on another site read the answer.' }
                            else              { $varNote = ' The repeat of this request with a foreign Origin header did not return the list.' }
                            $varNote += ' The repeat with a foreign Host header did not return the list.'
                        }

                        $reach = 'A process that can reach this address can read the model list without authenticating.'
                        if ($obs.IsLoopback) { $reach = 'The connected address is loopback, so this shows that a local process can read the model list without authenticating.' }

                        # A probed route that answered 403 with no WWW-Authenticate header is not
                        # a credential check and not the lack of one. It is said in so many words,
                        # so the Description does not pass over an answer the Evidence shows.
                        $refusedNote = ''
                        $refusedOn = @($obs.ForbiddenRoutes | Where-Object { $_ } | ForEach-Object { "GET $_" })
                        if ($refusedOn.Count -gt 0) {
                            $refusedVerb = 'was'
                            if ($refusedOn.Count -gt 1) { $refusedVerb = 'were' }
                            $refusedNote = " $(Join-TcpkAiWord -Items $refusedOn) $refusedVerb answered with 403 and no WWW-Authenticate header. The cause of that was not established: it can be an access rule, or an authentication scheme that does not announce itself, so it is counted neither as a credential check nor as the lack of one."
                        }

                        if ($identified) {
                            $title = "Ollama model API on $hostport answers without authentication"
                            if (-not $actionable) { $title = "Local Ollama server on this host answers without authentication on $hostport$unattrTitle" }
                            $cwe  = @('CWE-306')
                            $desc = "$listFact $reach The server is identified as Ollama by its models array on /api/tags together with its banner on GET /. The rating rests on that identification and on what was seen: Ollama serves its generate, chat and model-management routes from this same listener, and no probed route asked for a credential.$refusedNote $notCalled$varNote$unattrDesc"
                            $fix  = 'Put the API behind a local proxy that requires a credential, or restrict which processes can reach the port. Keep the listener on a loopback address unless remote access is intended.'
                        } else {
                            $title = "Model list on $hostport is readable without a credential (product not identified)"
                            if (-not $actionable) { $title = "Model list of a local inference server on this host ($hostport) is readable without a credential$unattrTitle" }
                            $cwe  = @('CWE-200')
                            $desc = "$listFact $reach The product behind the API was not identified, and no probed route asked for a credential.$refusedNote This is rated as a model list that is readable without a credential and nothing more: some inference servers keep the model list public while they ask for a key on their other routes, and this probe never requests an inference route, so whether those routes need a credential is not known. $notCalled$varNote$unattrDesc"
                            $fix  = 'Check, with authorization for the target, whether the inference routes of this server ask for a credential. If they do not, require one on every route or put the API behind a local proxy that does. Require it on the model-list route as well if the model names are not meant to be public.'
                        }

                        $ev = @("$base (no credential sent)", $tagsLine, $v1Line) + $idLines + @($originLine, $hostLine, $ctx)
                        $p = @{
                            Module = 'network'; RuleId = 'aiserver.unauth-reachable'
                            Severity = $sev; Confidence = 'Confirmed (dynamic)'
                            Title = $title
                            File = $hostport; Evidence = (Get-TcpkRedact -Text ($ev -join ' | '))
                            Cwe = $cwe
                            AttributionBasis = $basis; Subject = $hostport
                            Description = $desc
                            Fix = $fix
                        }
                        if ($cvss) { $p.Cvss = $cvss }
                        New-TcpkFinding @p

                        # ----- cross-origin handling, as observed -------------------------------
                        if ($hostHit -or $originHit) {
                            # Never above what the list finding itself stands for: on a product
                            # that was not identified, the model list is all that is shown to be
                            # reachable from another site.
                            $oSev = 'LOW'
                            if ($identified) { $oSev = 'HIGH' }
                            if (-not $actionable) { $oSev = 'INFO' }

                            $seenWhat = @()
                            $means    = @()
                            $fixParts = @()
                            $oCwe     = @('CWE-346')
                            if ($hostHit) {
                                $seenWhat += 'a foreign Host header'
                                $means += 'The request that carried a Host header naming another site returned the model list, so the server does not tie requests to its own name. That check is what stops a page using DNS rebinding from reaching a loopback service.'
                                $fixParts += 'Reject requests whose Host header is not the listener''s own name or address.'
                            }
                            if ($originHit) {
                                $seenWhat += 'a foreign Origin, answered with a permissive Access-Control-Allow-Origin'
                                $means += "The request that carried a foreign Origin returned the model list together with Access-Control-Allow-Origin: $($obs.AcaoText), which lets a script on another site read the response."
                                $fixParts += 'Answer cross-origin requests only for an explicit list of allowed origins, and do not return a wildcard or a reflected Access-Control-Allow-Origin.'
                                $oCwe += 'CWE-942'
                            } elseif ($originBlind) {
                                $means += 'The request that carried a foreign Origin returned the model list as well, with no permissive Access-Control-Allow-Origin. That alone does not let a page on another site read the answer and is not part of this finding.'
                            }
                            $what = 'Model-list route'
                            if ($identified) { $what = 'Ollama model API' }
                            $oTitle = "$what on $hostport accepts $($seenWhat -join ' and ')"
                            if (-not $actionable) {
                                $localWhat = 'Model-list route of a local inference server'
                                if ($identified) { $localWhat = 'Local Ollama server' }
                                $oTitle = "$localWhat on this host ($hostport) accepts $($seenWhat -join ' and ')$unattrTitle"
                            }
                            $scopeNote = ''
                            if (-not $identified) { $scopeNote = ' What a page on another site is shown to reach this way is the model list. The product was not identified and its other routes were not requested, so this is rated no higher than the model-list finding.' }

                            New-TcpkFinding -Module 'network' -RuleId 'aiserver.origin-unchecked' `
                                -Severity $oSev -Confidence 'Confirmed (dynamic)' `
                                -Title $oTitle `
                                -File $hostport `
                                -Evidence (Get-TcpkRedact -Text (@("$base (no credential sent)", $originLine, $hostLine, $ctx) -join ' | ')) `
                                -Cwe $oCwe `
                                -AttributionBasis $basis -Subject $hostport `
                                -Description ("After the model list was confirmed, the same GET $($obs.Route) was repeated twice with one header changed. " + ($means -join ' ') + "$scopeNote This records how the server handled the headers. No browser was driven and no rebinding was performed.$unattrDesc") `
                                -Fix ($fixParts -join ' ')
                        }
                    } else {
                        # ----- the list is readable, and another probed route asks for a credential
                        # The server has an authentication mechanism and uses it. A model list left
                        # public beside it is recorded, not rated, and no header variant was sent.
                        $askedOn = Join-TcpkAiWord -Items @($obs.AuthRoutes | ForEach-Object { "GET $_" })
                        $verb = 'was'
                        if (@($obs.AuthRoutes).Count -gt 1) { $verb = 'were' }
                        $authCodes = @()
                        foreach ($probed in @($obs.Tags, $obs.V1, $obs.Root, $obs.Ver)) {
                            if (Test-TcpkAiAuthAsked -Response $probed) { $authCodes += [int]$probed.Status }
                        }
                        $askedHow = '401'
                        if ($authCodes -notcontains 401)  { $askedHow = '403 together with a WWW-Authenticate header' }
                        elseif ($authCodes -contains 403) { $askedHow = '401, or with 403 together with a WWW-Authenticate header' }
                        $ev = @("$base (no credential sent)", $tagsLine, $v1Line) + $idLines + @('header variants: not sent (a probed route asked for a credential)', $ctx)
                        New-TcpkFinding -Module 'network' -RuleId 'aiserver.reachable-authed' `
                            -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                            -Title "Listener on $hostport asks for a credential on $(Join-TcpkAiWord -Items @($obs.AuthRoutes)); its model list on $($obs.Route) is readable without one$unattrTitle" `
                            -File $hostport -Evidence (Get-TcpkRedact -Text ($ev -join ' | ')) `
                            -AttributionBasis $basis -Subject $hostport `
                            -Description "$listFact $askedOn, sent the same way to the same listener, $verb answered with $askedHow. So the server has an authentication mechanism and applies it to at least one probed route, while its model list stays readable without it. Some inference servers leave the model list public by design. This is not reported as an API without authentication, and the two header variants were not sent. $notCalled$unattrDesc" `
                            -Fix 'No change is indicated by this probe. If the model names are not meant to be public, require the credential on the model-list route as well.'
                    }

                    # ===== known-vulnerable version: identity AND version both proven ===========
                    if ($obs.Ollama -and $obs.Version -and -not $obs.VersionZero) {
                        $below = $false
                        try { $below = [bool](Test-TcpkSemVerLt -A $obs.Version -B '0.1.34') } catch { $below = $false }
                        if ($below) {
                            $vSev = 'HIGH'
                            if (-not $actionable) { $vSev = 'INFO' }
                            $vTitle = "Ollama $($obs.Version) on $hostport is below 0.1.34, the release that fixed CVE-2024-37032"
                            if (-not $actionable) { $vTitle = "Local Ollama $($obs.Version) on this host ($hostport) is below 0.1.34, the release that fixed CVE-2024-37032$unattrTitle" }
                            New-TcpkFinding -Module 'network' -RuleId 'aiserver.ollama-probllama-version' `
                                -Severity $vSev -Confidence 'Confirmed (dynamic)' `
                                -Title $vTitle `
                                -File $hostport `
                                -Evidence (Get-TcpkRedact -Text (@("$base (no credential sent)", 'identity: GET / -> 200, Ollama banner', "identity: $tagsLine", "GET /api/version -> 200, version $($obs.Version)", "$($obs.Version) is below 0.1.34", 'the affected route was not requested', $ctx) -join ' | ')) `
                                -Cwe @('CWE-22') `
                                -AttributionBasis $basis -Subject $hostport `
                                -Description "The endpoint is identified as Ollama by two of its own answers (the models array on /api/tags and the banner on GET /), and /api/version returned $($obs.Version). Ollama releases before 0.1.34 are affected by CVE-2024-37032: the digest in a pulled model manifest is not validated, which allows a path traversal and an arbitrary file write. This is a version comparison against a live, identified server. The pull route was not requested and nothing was written. Score the finding from the advisory for that CVE.$unattrDesc" `
                                -Fix 'Upgrade Ollama to 0.1.34 or later, then run this probe again to confirm the reported version.'
                        }
                    }
                    continue
                }

                # ===== no model list: say what was seen, imply nothing more =====================
                $resps = @(@($obs.Tags, $obs.V1) | Where-Object { $null -ne $_ })
                $authResp   = @($resps | Where-Object { Test-TcpkAiAuthAsked -Response $_ })
                $bare403    = @($resps | Where-Object { Test-TcpkAiBareForbidden -Response $_ })
                $redirected = @($resps | Where-Object { $_.Status -ge 300 -and $_.Status -lt 400 })

                $evParts = @("TCP connect to $hostport succeeded", "$base (no credential sent)", $tagsLine, $v1Line) + $idLines
                if ($obs.Detail) { $evParts += "probe stopped early: $($obs.Detail)" }
                $evParts += $ctx
                $evText = Get-TcpkRedact -Text ($evParts -join ' | ')

                if ($authResp.Count -gt 0) {
                    $sawWhat = '401'
                    if (@($authResp | Where-Object { $_.Status -eq 401 }).Count -eq 0) { $sawWhat = '403 together with a WWW-Authenticate header' }
                    New-TcpkFinding -Module 'network' -RuleId 'aiserver.reachable-authed' `
                        -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                        -Title "Listener on $hostport asks for a credential on the model-list routes$unattrTitle" `
                        -File $hostport -Evidence $evText `
                        -AttributionBasis $basis -Subject $hostport `
                        -Description "A request sent with no credential was answered with $sawWhat. The listener is reachable and asks for authentication on the probed route. No model list was returned, so the service is not identified as an inference API and nothing else about it was tested.$unattrPlain" `
                        -Fix 'No change is indicated by this probe. Routes other than the two probed were not tested.'
                    continue
                }

                $uTitle = "Port $($ep.Port) open on ${addrText}: no model-list API identified"
                $uMore  = ''
                if ($bare403.Count -gt 0) {
                    $uTitle = "Port $($ep.Port) open on ${addrText}: model-list routes answer 403 (forbidden), cause not established"
                    $uMore  = ' A route answered 403 without a WWW-Authenticate header. That can be an access rule, a Host or Origin filter, or an authentication scheme that does not announce itself. The cause was not established and no posture is implied.'
                } elseif ($redirected.Count -gt 0) {
                    $uTitle = "Port $($ep.Port) open on ${addrText}: model-list routes redirect, not followed"
                    $uMore  = ' A route answered with a redirect. Redirects are never followed, so whatever the redirect points at (for example a login page, or another host) was not requested.'
                }
                New-TcpkFinding -Module 'network' -RuleId 'aiserver.port-open-unidentified' `
                    -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                    -Title "$uTitle$unattrTitle" `
                    -File $hostport -Evidence $evText `
                    -AttributionBasis $basis -Subject $hostport `
                    -Description "A TCP listener accepted the connection, but neither /api/tags nor /v1/models returned a JSON model list, so the service is not identified as an inference API.$uMore$unattrPlain" `
                    -Fix "Identify the process that owns the port before drawing a conclusion from it: Get-NetTCPConnection -State Listen -LocalPort $($ep.Port)."
            } catch {
                # One endpoint must never take the others down with it.
                Write-Warning "${fn}: probe of '$shown' stopped: $(Get-TcpkAiErrorText $_.Exception)"
            }
        }
    }
}
