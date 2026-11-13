function Test-TcpkMcpHostConfig {
<#
.SYNOPSIS
    C47. Static audit of MCP host config files found in the audited artifact tree.

.DESCRIPTION
    An MCP (Model Context Protocol) host config tells an AI client which servers to start
    or connect to. Each entry is a command line the host runs for the user, or a remote
    endpoint it talks to, so a config an application ships (or a project commits) decides
    what code runs and which credentials are handed to it.

    SCOPE. Like every TCPK check this reads the SHIPPED ARTIFACT: config files inside the
    tree given by -Path. It does not read the operator's own user profile; that would be
    host state, not the target's. Every finding is 'Inferred' (the config declares the
    behaviour; nothing is launched) and carries AttributionBasis 'established-footprint'
    (the file is inside the audited tree).

    DISCOVERY. File names only MCP hosts use are parsed directly: claude_desktop_config,
    mcp / .mcp, *-mcp, mcp_config, mcp-config, mcp_settings, *_mcp_settings, mcp_servers,
    *_mcp_servers, each as .json or .jsonc, with an optional .example / .sample style
    infix. Generic names (settings.json, config.json, .claude.json, opencode.json) are
    parsed only after a cheap content probe for an MCP key. A file whose only signal is a
    bare "servers" key is accepted only when an entry has the MCP shape (a command, or a
    url with an sse / http style transport), so an API description or an application
    settings file produces nothing. In a file whose name is not an MCP config name, a bare
    "servers" key counts only next to an MCP-only key and with an MCP-only transport name,
    and a flat "mcp" map only when an entry has a command or "type": "remote". TOML and
    YAML configs are not parsed.

    RULES (RuleId, severity):
      mcp.server-inventory        INFO    every declared server
      mcp.inline-download-exec    HIGH    a shell / interpreter inline script, an encoded command or a
                                          script-host launcher that downloads content and runs it
      mcp.shell-inline-command    LOW     a shell / interpreter given an inline script string
      mcp.secret-in-config        HIGH    provider-shaped token, JSON Web Token, private key,
                                          user:password URL
                                  MEDIUM  credential-named key holding a literal, a Bearer / Basic
                                          literal, a JSON Web Token whose exp claim is in the past
      mcp.unpinned-package        MEDIUM  a fetch-and-run launcher with no exact version / digest
      mcp.user-writable-launch    MEDIUM  the launched program or script is in a profile or temp folder
      mcp.broad-filesystem-scope  MEDIUM  a filesystem-type server granted a drive root or a whole home
      mcp.cleartext-endpoint      MEDIUM  http:// or ws:// to a non-loopback host
      mcp.config-unparsed         INFO    an MCP config that could not be read or parsed

    A disabled entry gets the inventory row and, when it holds one, the credential finding:
    the host does not start it, so the launch and endpoint rules are not applied to it.

    The Windows wrapper "cmd /c <program> <args...>" is not a finding: it is unwrapped and
    the inner command is analysed. Shell metacharacters are only ever looked at inside a
    script string handed to a shell or interpreter. Such a script string is split into its
    simple commands, and the package, launch-target, filesystem-scope, endpoint and
    credential rules are applied to each of them, so a launcher written as
    bash -c "..." or cmd /c "set X=1 && npx ..." is audited like the direct form.

    Evidence is default deny. Of a server's command line only the program, option names,
    paths, package / image references, plain words and URLs reduced to scheme, host, port
    and path are printed. Every other argument value is replaced by its length, and a
    script string by its length and the names of the programs it starts, so a credential
    in a form no rule lists is not printed either. The inventory and launcher findings
    start with that display string; a credential finding shows the location and a mask
    label only. A JSON Web Token whose role claim is "anon" is a publishable client key
    and is not reported.

    A config that is an example file (.example, .sample, .template, .default, .dist) or
    sits inside a bundled dependency (node_modules, site-packages, vendor) is not what a
    host starts: its servers are inventoried and its credentials reported, and the launch
    and endpoint rules are not applied to it.

    LIMITS. Credential detection covers the listed locations and shapes (env, args,
    headers, url parts, connection URLs, key blocks, script strings); a credential in
    another entry field or in a form of its own is masked in Evidence but not reported.
    Launchers other than those named above are not parsed for an unpinned package.

    COST. Every pattern has a short match timeout, long tokens are shown as a head and a
    length, and the check budget is tested for every server entry.

    Each Description states the rule in general terms and each Evidence holds the detail of
    the one entry, because report aggregation keeps a single Description for all the
    entries a rule fired on.

.PARAMETER Path
    A directory to search for MCP host configs, or a single .json / .jsonc file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # File names only MCP hosts use: parsed without a probe.
    $rxKnownName = '^(?:claude_desktop_config|\.?mcp|mcp[_-]?servers?|mcp[._-]?config|mcp[_-]?settings|.+[_.-]mcp(?:[_-]?(?:servers?|settings|config))?)(?:\.(?:example|sample|template|default|dist|local))?\.jsonc?$'
    # Names several hosts share with unrelated tools: parsed only if the text mentions an MCP key.
    $rxGenericName = '^(?:settings(?:\.local)?|config|[A-Za-z0-9_-]*\.claude|opencode)(?:\.(?:example|sample|template|default|dist))?\.jsonc?$'
    $rxProbe = '"(?:(?:[A-Za-z0-9_-]+\.)?mcpServers|mcp\.servers|context_servers|modelContextProtocolServers|mcp)"\s*:'
    # Keys that only ever mean MCP servers. A bare "mcp" key is enough to try a parse, but
    # not enough to call an unparseable file an MCP config.
    $rxProbeStrong = '"(?:(?:[A-Za-z0-9_-]+\.)?mcpServers|mcp\.servers|context_servers|modelContextProtocolServers)"\s*:'
    $maxBytes = 5242880
    $ic = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $basis = 'established-footprint'

    $descInventory = 'This MCP host config declares the server entry shown in Evidence: what the host is configured to start or connect to. An entry the config marks disabled is listed for completeness; the launch and endpoint rules are not applied to it, because the host does not start it, but a credential stored in it is still reported. Listed for triage; not a weakness by itself.'
    $descUnparsed  = 'This file has the name or the keys of an MCP host config, but it could not be read, parsed or fully analysed (the reason is in Evidence; comments and trailing commas are tolerated). Some or all of its server entries were therefore not audited. Review it by hand.'
    $descDownload  = 'This server entry does not start a fixed program. As written in the config, its launcher is an inline script, an encoded command or a script-host program that obtains content from a remote location and evaluates it, or saves a file from a remote location and runs or names that file in a later command (Evidence states which construct was found). What runs is therefore whatever that location serves when the host starts the server, under the account of the user running the host. Nothing was executed by this check.'
    $descInline    = 'This server entry hands a script string or an encoded command to a shell or interpreter instead of naming a program and its arguments (Evidence names the interpreter and the option). The interpreter parses that string, so what runs depends on its quoting and operators, and the entry cannot be reviewed or allow-listed as a fixed program path. No related download-and-run construct was found in it. Hardening note.'
    $descUnpinned  = 'This server entry starts through a launcher that resolves a package or a container image when the host starts the server (npx, uvx, pipx, a dlx-style runner, deno, a container run and similar), either directly or from inside its inline script. The config names a package without an exact version, or an image without a digest; Evidence lists each one. What runs is therefore whatever the registry, the source repository or the image repository serves under that name at that moment, so a new or replaced release runs without any change to this config. A copy already in the launcher cache, the local project or the local image store is used when it satisfies the request.'
    $descWritable  = 'The program or script this server entry starts is in a per-user or temp location (Evidence names the path and the kind of location). Files in a user profile, a per-user AppData folder or the per-user temp folder can be replaced without elevation by any process running as that user. A shared temp folder or the Public profile may also be writable by other local users. A host that loads this config starts whatever is at that path.'
    $descBroadFs   = 'This filesystem-type server is granted a drive root, the Users folder, a whole user home or a home shorthand (Evidence lists what). Such a server exposes file access under the directories it is given, so with this scope the assistant using it, and any instructions injected into what the assistant reads, can reach every file the user can under that root rather than one project folder.'
    $descCleartext = 'This server entry reaches a host other than the local machine over http:// or ws://, with no transport encryption (Evidence shows the endpoint). Anything on the network path can read the traffic, including any credential sent with it, and can change the tool results the assistant receives.'
    $descSecretHigh = 'This MCP server entry holds a credential in the config file itself: a provider-shaped token, a JSON Web Token, a private key block, or a password inside a user:password URL (Evidence names the location and the kind; the value is masked). Anyone who can read this file, or a copy of it in an installer, a backup or a repository, obtains the credential.'
    $descSecretMed  = 'This MCP server entry holds a literal value where a credential goes: under a credential-style name (an env key, a flag, a header, a URL parameter, or a key inside a JSON value or a script), as the password of a connection string or of a user:password pair given to an option, as a token-shaped URL userinfo, after a Bearer or Basic scheme word, or as a JSON Web Token whose exp claim is in the past. It is not a reference such as ${VAR} or %VAR%, not a placeholder, and not a path, a file name or a URL (Evidence names the location and the kind; the value is masked). If it is a live credential, anyone who can read this file, or a copy of it in an installer, a backup or a repository, obtains it.'

    $item = $null
    try { $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return }
    if (-not $item) { return }

    $single = -not $item.PSIsContainer
    $rootDir = ''
    $cands = New-Object 'System.Collections.Generic.List[object]'
    if ($single) {
        $known = [regex]::IsMatch("$($item.Name)", $rxKnownName, $ic)
        if ($known -or "$($item.Name)" -match '\.jsonc?$') {
            $cands.Add([pscustomobject]@{ File = $item; Known = $known; Probe = $false })
        }
    } else {
        $rootDir = "$($item.FullName)".TrimEnd('\', '/')
        $files = @()
        try { $files = @(Get-TcpkChildItemSafe -Path $Path -File) } catch { $files = @() }
        foreach ($f in $files) {
            $nm = "$($f.Name)"
            if ([regex]::IsMatch($nm, $rxKnownName, $ic)) {
                $cands.Add([pscustomobject]@{ File = $f; Known = $true; Probe = $false })
            } elseif ([regex]::IsMatch($nm, $rxGenericName, $ic)) {
                $cands.Add([pscustomobject]@{ File = $f; Known = $false; Probe = $true })
            }
        }
    }

    $stopped = $false
    foreach ($cand in $cands) {
        if (-not $stopped) {
            try { $stopped = [bool](Test-TcpkCheckBudgetExpired) } catch { $stopped = $false }
        }
        if ($stopped) { break }

        $cfg = $cand.File
        $full = "$($cfg.FullName)"
        $rel = "$($cfg.Name)"
        if ($rootDir -and $full.Length -gt ($rootDir.Length + 1) -and $full.StartsWith($rootDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $full.Substring($rootDir.Length).TrimStart('\', '/')
        }

        # One INFO record for a config that is recognisably an MCP config but could not be
        # audited. Never silent: a skipped config is indistinguishable from no config.
        # $What is the part of the Title after the colon, so two records for one file (a
        # bad map and a bad entry) stay distinct through the report dedupe.
        $unparsed = {
            param([string]$Reason, [string]$What = '')
            try { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath $full } catch { }
            $title = "MCP config could not be parsed: $rel"
            if ($What) { $title = "MCP config could not be fully analysed: $What" }
            New-TcpkFinding -Module 'os' -RuleId 'mcp.config-unparsed' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title $title `
                -File $full -Evidence $Reason `
                -AttributionBasis $basis -Subject $full `
                -Description $descUnparsed `
                -Fix 'Correct the file so that it parses, or review its server entries manually.'
        }

        try {
            $size = 0
            try { $size = [long]$cfg.Length } catch { $size = 0 }
            if ($size -gt $maxBytes) {
                if ($cand.Known) { & $unparsed "file is $size bytes, above the $maxBytes byte limit for this check, and was not read" }
                continue
            }

            $raw = Read-TcpkMcpConfigText -Path $full
            if ($null -eq $raw) {
                if ($cand.Known) { & $unparsed 'file could not be read' }
                continue
            }
            $looksMcp = ($cand.Known -or [regex]::IsMatch($raw, $rxProbe))
            if ($cand.Probe -and -not $looksMcp) { continue }

            $parsed = ConvertFrom-TcpkMcpJson -Text $raw
            if (-not $parsed.Ok) {
                if ($cand.Known -or [regex]::IsMatch($raw, $rxProbeStrong)) {
                    # The parser message is NOT printed: on Windows PowerShell 5.1 it embeds the
                    # whole input text, secrets included. Only the position is taken from it.
                    $reason = 'JSON parse error'
                    $pm = [regex]::Match("$($parsed.Error)", 'line (\d+), position (\d+)')
                    if ($pm.Success) { $reason = "JSON parse error at line $($pm.Groups[1].Value), position $($pm.Groups[2].Value)" }
                    else {
                        $pm = [regex]::Match("$($parsed.Error)", '\((\d+)\):')
                        if ($pm.Success) { $reason = "JSON parse error at character $($pm.Groups[1].Value)" }
                    }
                    & $unparsed $reason
                }
                continue
            }
            if ($null -eq $parsed.Value) { continue }       # empty file: declares nothing

            $set = Get-TcpkMcpServers -Root $parsed.Value -NameKnown ([bool]$cand.Known) -SingleFile $single
            if ($cand.Known) {
                $bn = 0
                foreach ($b in $set.BadMaps) {
                    $bn++
                    & $unparsed "$b, so no server entry could be read from it" "$rel (server map $bn)"
                }
            }

            # An example file, or a config inside a bundled dependency, is not what a host
            # starts. Its servers are listed and its credentials reported; the launch and
            # endpoint rules say nothing about it.
            $notLive = ''
            if ("$($cfg.Name)" -match '\.(example|sample|template|default|dist)\.jsonc?$') { $notLive = 'example file' }
            elseif ($full -match '[\\/](node_modules|site-packages|vendor|bower_components)[\\/]') { $notLive = 'inside a bundled dependency' }

            # Hosts read server names case-sensitively, so 'GitHub' and 'github' are two servers.
            # The report pipeline dedupes titles case-insensitively, so a locator that differs
            # from an earlier one only by case gets a suffix; otherwise one of the two is lost.
            $seenLoc = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($srv in $set.Servers) {
                # The budget is tested per entry as well: one file can hold many entries.
                try { $stopped = [bool](Test-TcpkCheckBudgetExpired) } catch { $stopped = $false }
                if ($stopped) { break }

                # The name is a JSON key: keep it on one line and bounded before it goes into a Title.
                $sname = ("$($srv.Name)" -replace '[\x00-\x1F]+', ' ')
                if ($sname.Length -gt 80) { $sname = $sname.Substring(0, 80) + '...' }
                $loc = "$rel -> '$sname'"
                if ($srv.Nested) {
                    # the label of a nested map is a JSON key too (a project path)
                    $ml = ("$($srv.MapLabel)" -replace '[\x00-\x1F]+', ' ')
                    if ($ml.Length -gt 120) { $ml = $ml.Substring(0, 120) + '...' }
                    $loc = "$rel [$ml] -> '$sname'"
                }
                if ($seenLoc.ContainsKey($loc)) {
                    $seenLoc[$loc] = $seenLoc[$loc] + 1
                    $loc = "$loc (entry $($seenLoc[$loc]))"
                } else { $seenLoc[$loc] = 1 }
                $subject = "$full -> server '$sname'"
                try {
                    $launcher = $null
                    if ($srv.Command) { $launcher = Resolve-TcpkMcpLauncher -Command $srv.Command -Arguments $srv.Args }

                    # Secrets first: the display string masks exactly the characters they point at.
                    $secretHits = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($h in (Get-TcpkMcpSecretHits -Server $srv -Launcher $launcher)) { $secretHits.Add($h) }
                    $display = Get-TcpkMcpDisplay -Server $srv -Hits $secretHits.ToArray()

                    $units = New-Object 'System.Collections.Generic.List[object]'
                    if ($null -ne $launcher) {
                        $pkg = Get-TcpkMcpPackageInfo -Leaf $launcher.Leaf -Argv $launcher.Args
                        $units.Add([pscustomobject]@{ Launcher = $launcher; Package = $pkg; Inner = $false })
                        # commands found inside an inline script string
                        foreach ($seg in $launcher.Segments) { $units.Add($seg) }
                        # a credential inside an encoded command is in the file all the same
                        if ($null -ne $launcher.Inline -and $launcher.Inline.Encoded -and $launcher.Inline.Script) {
                            foreach ($h in (Get-TcpkMcpTextHits -Text $launcher.Inline.Script -Where 'encoded command (decoded)' -Prefix 'encoded command')) { $secretHits.Add($h) }
                        }
                    }

                    # ---- secrets (one finding per location); also emitted for a disabled entry ----
                    # Grouped case-sensitively: env keys Path and PATH are two locations.
                    $evPrefix = ''
                    if ($srv.Disabled) { $evPrefix = 'disabled entry; ' }
                    $emitSecrets = {
                        $order = New-Object 'System.Collections.Generic.List[string]'
                        $byWhere = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
                        foreach ($h in $secretHits) {
                            $hw = "$($h.Where)"
                            if (-not $byWhere.ContainsKey($hw)) { $byWhere[$hw] = New-Object 'System.Collections.Generic.List[object]'; $order.Add($hw) }
                            $byWhere[$hw].Add($h)
                        }
                        $seenWhere = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
                        foreach ($w in $order) {
                            $wTitle = $w
                            if ($seenWhere.ContainsKey($w)) {
                                $seenWhere[$w] = $seenWhere[$w] + 1
                                $wTitle = "$w, entry $($seenWhere[$w])"
                            } else { $seenWhere[$w] = 1 }
                            $sev = 'MEDIUM'
                            $hasKey = $false
                            $labels = New-Object 'System.Collections.Generic.List[string]'
                            foreach ($h in $byWhere[$w]) {
                                if ($h.Severity -ceq 'HIGH') { $sev = 'HIGH' }
                                if ($h.Kind -ceq 'private-key') { $hasKey = $true }
                                $lb = Format-TcpkMcpMask -Value $h.Value -Label $h.Label
                                if (-not $labels.Contains($lb)) { $labels.Add($lb) }
                            }
                            $cwe = @('CWE-798', 'CWE-312')
                            if ($hasKey) { $cwe = @('CWE-798', 'CWE-312', 'CWE-321') }
                            $desc = $descSecretMed
                            if ($sev -ceq 'HIGH') { $desc = $descSecretHigh }
                            # A location name is a JSON key or an argument: keep it bounded and on one line.
                            $wShown = Get-TcpkMcpSafeText -Text $wTitle -MaxLength 80
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.secret-in-config' `
                                -Severity $sev -Confidence 'Inferred' `
                                -Title "Credential in MCP server config: $loc ($wShown)" `
                                -File $full -Evidence "$evPrefix$wShown = $($labels.ToArray() -join '; ')" `
                                -Cwe $cwe `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $desc `
                                -Fix 'Remove the credential from the file. Reference it from the environment or the OS credential store, and rotate the exposed value.'
                        }
                    }

                    # ---- a config no host starts: inventory and credentials only ----
                    if ($notLive -and -not $srv.Disabled) {
                        New-TcpkFinding -Module 'os' -RuleId 'mcp.server-inventory' `
                            -Severity 'INFO' -Confidence 'Inferred' `
                            -Title "MCP server declared: $loc ($notLive)" `
                            -File $full -Evidence "$notLive; $display" `
                            -AttributionBasis $basis -Subject $subject `
                            -Description $descInventory
                        & $emitSecrets
                        continue
                    }

                    # ---- inventory (every server) ----
                    if ($srv.Disabled) {
                        New-TcpkFinding -Module 'os' -RuleId 'mcp.server-inventory' `
                            -Severity 'INFO' -Confidence 'Inferred' `
                            -Title "MCP server declared: $loc (disabled)" `
                            -File $full -Evidence "disabled; $display" `
                            -AttributionBasis $basis -Subject $subject `
                            -Description $descInventory
                        # The host does not start a disabled entry, so the launch and endpoint
                        # rules say nothing about it. A credential in it is in the file all the same.
                        & $emitSecrets
                        continue
                    }
                    New-TcpkFinding -Module 'os' -RuleId 'mcp.server-inventory' `
                        -Severity 'INFO' -Confidence 'Inferred' `
                        -Title "MCP server declared: $loc" `
                        -File $full -Evidence $display `
                        -AttributionBasis $basis -Subject $subject `
                        -Description $descInventory

                    if ($null -ne $launcher) {
                        # ---- launcher: download-and-run (the only HIGH launcher rule) ----
                        if ($launcher.DownloadExec) {
                            $why = Get-TcpkMcpMaskedFragment -Text $launcher.DownloadWhy -MaxLength 240
                            $ev = "$display | $why"
                            if ($null -ne $launcher.Inline -and $launcher.Inline.Encoded -and $launcher.Inline.Script) {
                                $ev = "$ev | decoded: $(Get-TcpkMcpShownScript -Text $launcher.Inline.Script)"
                            }
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.inline-download-exec' `
                                -Severity 'HIGH' -Confidence 'Inferred' `
                                -Title "MCP server launcher downloads and executes remote content: $loc" `
                                -File $full -Evidence $ev `
                                -Cwe @('CWE-494', 'CWE-829') `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $descDownload `
                                -Fix 'Start the server from a fixed program, or a package pinned to an exact version, with an argument list. Do not download and run content at launch.'
                        }
                        # ---- launcher: inline script string (hardening note) ----
                        elseif ($null -ne $launcher.Inline) {
                            $il = $launcher.Inline
                            $ev = "$display | inline script passed to $($il.Shell) ($($il.Option))"
                            if ($il.Encoded) {
                                $ev = "$display | encoded command passed to $($il.Shell) ($($il.Option))"
                                if ($il.Script) {
                                    $ev = "$ev | decoded: $(Get-TcpkMcpShownScript -Text $il.Script)"
                                } else { $ev = "$ev | (the encoded command could not be decoded)" }
                            }
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.shell-inline-command' `
                                -Severity 'LOW' -Confidence 'Inferred' `
                                -Title "MCP server is started through an inline script string: $loc" `
                                -File $full -Evidence $ev `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $descInline `
                                -Fix 'Name the program in "command" and pass its parameters as separate "args" entries. On Windows, "cmd" with "/c" followed by the program and its arguments as separate entries is fine.'
                        }

                        # The rules below look at the entry's own launcher and at every command
                        # found inside its inline script string.

                        # ---- unpinned fetch-and-run package ----
                        $unp = New-Object 'System.Collections.Generic.List[string]'
                        $unpBy = New-Object 'System.Collections.Generic.List[string]'
                        foreach ($unit in $units) {
                            $upk = $unit.Package
                            if ($null -eq $upk -or -not $upk.Launcher) { continue }
                            foreach ($ref in $upk.Refs) {
                                if ($ref.Pinned) { continue }
                                if ($ref.Kind -cne 'registry' -and $ref.Kind -cne 'git' -and $ref.Kind -cne 'image') { continue }
                                $one = "$($ref.Spec) ($($ref.Why))"
                                if (-not $unp.Contains($one)) { $unp.Add($one) }
                                if (-not $unpBy.Contains("$($upk.Launcher)")) { $unpBy.Add("$($upk.Launcher)") }
                            }
                        }
                        if ($unp.Count -gt 0) {
                            $specs = Get-TcpkMcpMaskedFragment -Text ($unp.ToArray() -join '; ') -MaxLength 300
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.unpinned-package' `
                                -Severity 'MEDIUM' -Confidence 'Inferred' `
                                -Title "MCP server runs a package with no pinned version: $loc" `
                                -File $full -Evidence "$display | unpinned: $specs | resolved by $($unpBy.ToArray() -join ', ') at launch" `
                                -Cwe @('CWE-1357', 'CWE-829') `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $descUnpinned `
                                -Fix 'Pin an exact version (name@1.2.3 or name==1.2.3; for a git source a commit; for a container image a digest, image@sha256:...), or ship the server with the application instead of fetching it at launch.'
                        }

                        # ---- launch target in a user-writable location ----
                        $hitTargets = New-Object 'System.Collections.Generic.List[string]'
                        $sharedTarget = $false
                        foreach ($unit in $units) {
                            # a command inside a script string runs where the script last changed to
                            $ucwd = $srv.Cwd
                            if ($unit.Inner -and $unit.Cwd) { $ucwd = Join-TcpkMcpPath -Base $srv.Cwd -Child $unit.Cwd }
                            foreach ($t in (Get-TcpkMcpLaunchTargets -Launcher $unit.Launcher -Package $unit.Package -Cwd $ucwd)) {
                                $cls = Get-TcpkMcpWritableClass $t
                                if (-not $cls) { continue }
                                $one = "$t ($cls)"
                                if (-not $hitTargets.Contains($one)) { $hitTargets.Add($one) }
                                if ($cls -match 'shared') { $sharedTarget = $true }
                            }
                        }
                        if ($hitTargets.Count -gt 0) {
                            $tg = Get-TcpkMcpMaskedFragment -Text ($hitTargets.ToArray() -join '; ') -MaxLength 300
                            # A shared location (a shared temp folder, the Public profile) can
                            # be written by OTHER local users: that crosses an account boundary.
                            # A per-user location can only be written by the same user, who can
                            # already run code, so there it is a persistence note, not elevation.
                            $wsev = 'LOW'
                            if ($sharedTarget) { $wsev = 'MEDIUM' }
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.user-writable-launch' `
                                -Severity $wsev -Confidence 'Inferred' `
                                -Title "MCP server launch target is in a user-writable location: $loc" `
                                -File $full -Evidence "$display | launch target: $tg" `
                                -Cwe @('CWE-732', 'CWE-427') `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $descWritable `
                                -Fix 'Install the server under a directory that only administrators can write, for example under Program Files, and reference it from there.'
                        }

                        # ---- filesystem-type server granted a broad root ----
                        $roots = New-Object 'System.Collections.Generic.List[string]'
                        foreach ($unit in $units) {
                            $fs = Get-TcpkMcpBroadRoots -Launcher $unit.Launcher -Package $unit.Package
                            if (-not $fs.IsFs) { continue }
                            foreach ($one in $fs.Roots) { if (-not $roots.Contains("$one")) { $roots.Add("$one") } }
                        }
                        if ($roots.Count -gt 0) {
                            $rt = Get-TcpkMcpMaskedFragment -Text ($roots.ToArray() -join '; ') -MaxLength 300
                            New-TcpkFinding -Module 'os' -RuleId 'mcp.broad-filesystem-scope' `
                                -Severity 'MEDIUM' -Confidence 'Inferred' `
                                -Title "MCP filesystem server is granted a broad root: $loc" `
                                -File $full -Evidence "$display | granted: $rt" `
                                -Cwe @('CWE-668') `
                                -AttributionBasis $basis -Subject $subject `
                                -Description $descBroadFs `
                                -Fix 'Grant only the specific project or data directories the server needs. Do not grant a drive root, the Users folder or a whole user home.'
                        }
                    }

                    # ---- cleartext endpoint ----
                    $clear = Get-TcpkMcpCleartext -Server $srv -Units $units.ToArray()
                    if ($clear.Count -gt 0) {
                        $cl = New-Object 'System.Collections.Generic.List[string]'
                        foreach ($c in $clear) { $cl.Add("$($c.Field): $(Get-TcpkMcpShownUrl (Get-TcpkMcpMaskedFragment -Text $c.Url -MaxLength 400))") }
                        $ev = Get-TcpkMcpSafeText -Text ($cl.ToArray() -join '; ') -MaxLength 300
                        New-TcpkFinding -Module 'os' -RuleId 'mcp.cleartext-endpoint' `
                            -Severity 'MEDIUM' -Confidence 'Inferred' `
                            -Title "MCP server endpoint uses cleartext transport: $loc" `
                            -File $full -Evidence $ev `
                            -Cwe @('CWE-319') `
                            -AttributionBasis $basis -Subject $subject `
                            -Description $descCleartext `
                            -Fix 'Use https:// or wss:// for every endpoint that is not on the local machine.'
                    }

                    & $emitSecrets
                } catch {
                    & $unparsed "server entry '$sname' could not be analysed ($($_.Exception.GetType().Name))" $loc
                }
            }
        } catch {
            & $unparsed "analysis stopped ($($_.Exception.GetType().Name))" "$rel (analysis stopped)"
        }
    }
    if ($stopped) {
        try { Add-TcpkScanSkip -Kind 'BudgetStopped' -ItemPath 'Test-TcpkMcpHostConfig' } catch { }
    }
}
