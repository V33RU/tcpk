function Get-TcpkTargetProfile {
<#
.SYNOPSIS
    R00. Recon / fingerprint pass. Builds a target-application profile for the
    report header (app identity, tech stack, attack surface).

.DESCRIPTION
    Non-destructive reconnaissance over the target install. Produces a single
    profile object describing:
      R01 App-type fingerprint   (MSIX / Win32 / Electron / Java / Python / ClickOnce)
      R02 UI framework           (WPF / WinForms / WinUI3 / Qt / MFC / MAUI / Avalonia)
      R03 Runtime / language      (.NET Fwk / .NET 5+ / native C++ / Java / Python)
      R04 Third-party SDK inventory (publisher + version of shipped DLLs)
      R05 Update mechanism        (Squirrel / ClickOnce / Store / NSIS / in-app HTTP)
      R06 Network protocol profile (REST / WCF / gRPC / SignalR / WebSocket)
      R07 Privilege model         (asInvoker / requireAdministrator / autoElevate)
      R08 Code-signing identity   (subject / issuer / expiry / key size)
      R09 Attack-surface counts   (DLLs / COM / pipes / services / ports / handlers)
      R10 Electron / CEF detection

    This is a triage aid. It emits NO findings -- it returns metadata only.
    Counts for runtime surface (COM/pipes/services/ports/handlers/assoc) are
    derived from the -Findings already collected by the audit, so they reflect
    exactly what TCPK actually observed.

.PARAMETER Path
    Extracted install directory (or MSIX file). Profiling reads the loose
    files, so pass the expanded directory when available.

.PARAMETER Findings
    Optional. The findings already collected this audit. Used only to compute
    attack-surface counts (COM objects, pipes, services, ports, handlers,
    file-assoc) from what was actually observed.

.OUTPUTS
    [pscustomobject] -- the target profile (not a [TcpkFinding]).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [TcpkFinding[]]$Findings = @()
    )

    # ---------- resolve a directory to scan ----------
    $dir = $Path
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (-not $item.PSIsContainer) {
            # MSIX file: expand it so we can read loose DLLs
            $dir = try { Expand-TcpkMsix -Path $Path } catch { Split-Path -Parent $Path }
        }
    } catch { }

    # ---------- gather shipped PEs once ----------
    $pes = @()
    try { $pes = @(Get-TcpkPeFiles -Path $dir) } catch { }
    $peNames = @($pes | ForEach-Object { $_.Name.ToLowerInvariant() })
    $peSet   = [System.Collections.Generic.HashSet[string]]::new([string[]]$peNames, [System.StringComparer]::OrdinalIgnoreCase)

    function _Has([string]$name) { return $peSet.Contains($name.ToLowerInvariant()) }
    function _AnyLike([string]$pattern) {
        foreach ($n in $peNames) { if ($n -like $pattern) { return $true } }
        return $false
    }
    # any loose file (not just PE) matching a pattern, anywhere under dir
    function _FileLike([string]$pattern) {
        try { return [bool](Get-ChildItem -LiteralPath $dir -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue | Select-Object -First 1) }
        catch { return $false }
    }

    # Native import union across the app's binaries. The main exe is often a thin launcher, so the
    # real networking / UI lives in sibling DLLs/exes -- scan the set (bounded) for imported system
    # DLLs so native (non-.NET) apps are not reported as "unknown / not determined".
    $imports = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ip in ($pes | Select-Object -First 60)) {
        try { $ipe = Read-TcpkPe -Path $ip.FullName; foreach ($imp in @($ipe.Imports)) { if ($imp) { [void]$imports.Add("$imp") } } } catch { }
    }
    function _Imp([string]$rx) { foreach ($i in $imports) { if ($i -match $rx) { return $true } } return $false }

    $dllCount = @($pes | Where-Object { $_.Extension -ieq '.dll' }).Count
    $exeCount = @($pes | Where-Object { $_.Extension -ieq '.exe' }).Count
    $sysCount = @($pes | Where-Object { $_.Extension -ieq '.sys' }).Count

    # ---------- MSIX manifest (identity) ----------
    $manifest = $null
    try { $manifest = Read-TcpkAppxManifest -ExpandedPath $dir } catch { }

    $name = $null; $version = $null; $publisher = $null; $pkgFullName = $null; $mainExe = $null
    $isMsix = $false
    if ($manifest) {
        $isMsix = $true
        try {
            $nsm = Get-TcpkAppxNsMgr -Manifest $manifest
            $idNode  = $manifest.DocumentElement.SelectSingleNode('//d:Identity', $nsm)
            $propName = $manifest.DocumentElement.SelectSingleNode('//d:Properties/d:DisplayName', $nsm)
            $propPub  = $manifest.DocumentElement.SelectSingleNode('//d:Properties/d:PublisherDisplayName', $nsm)
            $appNode  = $manifest.DocumentElement.SelectSingleNode('//d:Applications/d:Application', $nsm)
            if ($idNode) {
                $version   = $idNode.GetAttribute('Version')
                $pkgFullName = $idNode.GetAttribute('Name')
                if (-not $publisher) { $publisher = $idNode.GetAttribute('Publisher') }
            }
            if ($propName -and $propName.InnerText) { $name = $propName.InnerText }
            if ($propPub  -and $propPub.InnerText)  { $publisher = $propPub.InnerText }
            if ($appNode) {
                $exeAttr = $appNode.GetAttribute('Executable')
                if ($exeAttr) { $mainExe = $exeAttr }
            }
        } catch { }
    }

    # ---------- choose a main executable when not from manifest ----------
    $mainExePath = $null
    if ($mainExe) {
        $cand = Join-Path $dir $mainExe
        if (Test-Path -LiteralPath $cand) { $mainExePath = $cand }
    }
    if (-not $mainExePath) {
        # heuristic: largest .exe whose name is not an installer/updater/helper
        $exes = @($pes | Where-Object { $_.Extension -ieq '.exe' })
        $primary = $exes |
            Where-Object { $_.BaseName -notmatch '(?i)(setup|install|uninstall|update|crashpad|helper|vc_redist|squirrel)' } |
            Sort-Object Length -Descending | Select-Object -First 1
        if (-not $primary) { $primary = $exes | Sort-Object Length -Descending | Select-Object -First 1 }
        if ($primary) { $mainExePath = $primary.FullName }
    }

    # ---------- version info from main exe ----------
    if ($mainExePath) {
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($mainExePath)
            if (-not $name      -and $vi.ProductName)   { $name = $vi.ProductName }
            if (-not $name      -and $vi.FileDescription){ $name = $vi.FileDescription }
            if (-not $version   -and $vi.ProductVersion){ $version = $vi.ProductVersion }
            if (-not $publisher -and $vi.CompanyName)   { $publisher = $vi.CompanyName }
        } catch { }
    }
    if (-not $name) { $name = Split-Path -Leaf $Path }

    # ---------- architecture (from main exe PE machine) ----------
    $arch = 'unknown'
    if ($mainExePath) {
        $pe = Read-TcpkPe -Path $mainExePath
        if ($pe) {
            switch ($pe.Machine) {
                0x8664  { $arch = 'x64' }
                0x14C   { $arch = 'x86' }
                0xAA64  { $arch = 'ARM64' }
                0x1C0   { $arch = 'ARM' }
                0x1C4   { $arch = 'ARM' }
                default { $arch = ('0x{0:X}' -f $pe.Machine) }
            }
        }
    }

    # ---------- R10 Electron / CEF ----------
    $isCef      = (_Has 'libcef.dll') -or (_FileLike 'cef.pak')
    $isElectron = (_Has 'electron.exe') -or (_FileLike 'app.asar') -or (_Has 'ffmpeg.dll' -and $isCef)
    $isNwjs     = (_Has 'nw.exe') -or (_Has 'nw.dll')

    # ---------- R10b Tauri / Flutter (newer cross-platform desktop frameworks) ----------
    # Tauri ships the Rust exe + WebView2Loader (no wry.dll -- WRY is statically linked),
    # so confirm via tauri.conf.json (dev/source builds) or Tauri runtime markers in the exe.
    $isTauri = $false
    if (_FileLike 'tauri.conf.json') { $isTauri = $true }
    elseif ((_Has 'webview2loader.dll') -and $mainExePath) {
        $mt = Read-TcpkAllText -Path $mainExePath
        if ($mt -and ($mt.Contains('__TAURI') -or $mt.Contains('tauri://') -or $mt.Contains('ipc://localhost'))) { $isTauri = $true }
    }
    # Flutter desktop ships flutter_windows.dll + data\flutter_assets\ (kernel_blob.bin / app.so).
    $isFlutter = (_Has 'flutter_windows.dll') -or (_FileLike 'kernel_blob.bin')

    # ---------- R03 runtime / language ----------
    $runtime = $null; $runtimeDetail = $null
    $hasManagedMarker = (_Has 'system.private.corelib.dll') -or (_Has 'mscorlib.dll') -or (_AnyLike 'system.*.dll')
    $rcfg = $null
    try { $rcfg = Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.runtimeconfig.json' -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { }
    $isJava   = (_Has 'jvm.dll') -or (_FileLike '*.jar') -or (_FileLike 'java.exe')
    $isPython = (_AnyLike 'python3*.dll') -or (_FileLike '*.pyd') -or (_FileLike 'base_library.zip')

    if ($rcfg) {
        $runtime = '.NET (Core/5+)'
        try {
            $rc = Get-Content -LiteralPath $rcfg.FullName -Raw | ConvertFrom-Json
            $fw = $null
            if ($rc.runtimeOptions.framework.version)        { $fw = $rc.runtimeOptions.framework.version }
            elseif ($rc.runtimeOptions.frameworks)           { $fw = ($rc.runtimeOptions.frameworks | Select-Object -First 1).version }
            $tfm = $rc.runtimeOptions.tfm
            if ($tfm)     { $runtimeDetail = "tfm=$tfm" }
            if ($fw)      { $runtime = ".NET $($fw.Split('.')[0]).$($fw.Split('.')[1])"; $runtimeDetail = "framework $fw" }
        } catch { }
    }
    elseif ($isElectron -or $isNwjs) { $runtime = 'Chromium + Node.js (Electron)'; if ($isNwjs) { $runtime = 'Chromium + Node.js (NW.js)' } }
    elseif ($isJava)                 { $runtime = 'Java (JVM)' }
    elseif ($isPython)               { $runtime = 'Python (bundled)' }
    elseif ((_Has 'mscoree.dll') -or $hasManagedMarker) {
        $runtime = '.NET Framework 4.x'
        # confirm via app.config supportedRuntime if present
        if ($mainExePath -and (Test-Path -LiteralPath "$mainExePath.config")) {
            try {
                $cfgTxt = Get-Content -LiteralPath "$mainExePath.config" -Raw
                if ($cfgTxt -match 'supportedRuntime\s+version="v([0-9.]+)"') { $runtimeDetail = "CLR v$($matches[1])" }
            } catch { }
        }
    }
    elseif ($isTauri)                { $runtime = 'Rust + System WebView (Tauri)' }
    elseif ($isFlutter)              { $runtime = 'Flutter (Dart)' }
    else { $runtime = 'Native (C/C++)' }

    # ---------- R02 UI framework ----------
    $ui = New-Object 'System.Collections.Generic.List[string]'
    if ((_Has 'presentationframework.dll') -or (_Has 'presentationcore.dll')) { $ui.Add('WPF') }
    if (_Has 'system.windows.forms.dll')                                       { $ui.Add('WinForms') }
    if ((_AnyLike 'microsoft.ui.xaml*.dll') -or (_AnyLike 'microsoft.winui*.dll')) { $ui.Add('WinUI3') }
    if (_AnyLike 'microsoft.maui*.dll')                                        { $ui.Add('.NET MAUI') }
    if (_AnyLike 'avalonia*.dll')                                              { $ui.Add('Avalonia') }
    if (_AnyLike 'qt5*.dll' -or (_AnyLike 'qt6*.dll'))                         { $ui.Add('Qt') }
    if (_AnyLike 'mfc*.dll')                                                   { $ui.Add('MFC') }
    if ($isTauri)                                                              { $ui.Add('Tauri (WebView)') }
    if ($isFlutter)                                                            { $ui.Add('Flutter') }
    if ($isElectron -or $isCef -or $isNwjs)                                    { $ui.Add('Chromium/WebView') }
    if ((_AnyLike 'microsoft.web.webview2*.dll'))                              { $ui.Add('WebView2') }
    # native UI (no managed framework matched) -- from imported system DLLs.
    if ($ui.Count -eq 0) {
        if (_Imp '(?i)^user32(\.dll)?$')       { $ui.Add('Win32 native (user32/gdi32)') }
        if (_Imp '(?i)^(d2d1|dwrite)(\.dll)?$') { $ui.Add('Direct2D/DirectWrite') }
        if (_Imp '(?i)^(d3d1[012]|dxgi)(\.dll)?$') { $ui.Add('Direct3D') }
    }
    if ($ui.Count -eq 0) { $ui.Add('unknown / custom') }

    # ---------- R06 network protocol profile ----------
    $net = New-Object 'System.Collections.Generic.List[string]'
    if (_AnyLike 'grpc.*.dll' -or (_Has 'grpc.core.dll'))   { $net.Add('gRPC') }
    if (_AnyLike 'system.servicemodel*.dll')                { $net.Add('WCF / SOAP') }
    if (_AnyLike '*signalr*.dll')                           { $net.Add('SignalR') }
    if (_Has 'google.protobuf.dll')                         { $net.Add('Protobuf') }
    if (_AnyLike 'mqttnet*.dll')                            { $net.Add('MQTT') }
    if (_AnyLike 'restsharp*.dll' -or (_AnyLike 'flurl*.dll')) { $net.Add('REST (lib)') }
    if ((_Has 'system.net.http.dll') -or (_AnyLike 'system.net.*.dll')) { $net.Add('HTTP/REST') }
    # native networking (no managed net lib matched) -- from imported system DLLs + bundled TLS.
    if (_Imp '(?i)^(ws2_32|wsock32|mswsock)(\.dll)?$') { $net.Add('Sockets (Winsock)') }
    if (_Imp '(?i)^winhttp(\.dll)?$')                  { $net.Add('WinHTTP') }
    if (_Imp '(?i)^wininet(\.dll)?$')                  { $net.Add('WinINet') }
    if (_Imp '(?i)^(secur32|sspicli|schannel)(\.dll)?$') { $net.Add('SChannel/SSPI (native TLS)') }
    if ((_AnyLike 'libssl*.dll') -or (_AnyLike 'libcrypto*.dll') -or (_AnyLike 'ssleay*.dll') -or (_AnyLike 'libeay*.dll')) { $net.Add('OpenSSL (TLS)') }
    if ($net.Count -eq 0) { $net.Add('not determined') }

    # ---------- R05 update mechanism ----------
    $upd = New-Object 'System.Collections.Generic.List[string]'
    if ((_Has 'squirrel.dll') -or (_Has 'update.exe'))      { $upd.Add('Squirrel') }
    if (_FileLike '*.application')                          { $upd.Add('ClickOnce') }
    if ($isMsix)                                            { $upd.Add('MSIX / Store / App Installer') }
    # in-app HTTP updater: scan main exe/dll for update keywords
    $mainBlob = ''
    if ($mainExePath) { $mainBlob = Read-TcpkAllText -Path $mainExePath }
    $mainDll = Join-Path $dir ([IO.Path]::GetFileNameWithoutExtension($mainExePath) + '.dll')
    if ($mainExePath -and (Test-Path -LiteralPath $mainDll)) { $mainBlob += "`n" + (Read-TcpkAllText -Path $mainDll) }
    if ($mainBlob -match '(?i)(CheckForUpdate|DownloadUpdate|UpdateManifest|update-manifest|LatestVersion)') { $upd.Add('in-app HTTP updater') }
    # a sibling updater binary (the main exe is often a thin launcher, so the updater lives elsewhere)
    if ((_AnyLike '*updater*.exe') -or (_AnyLike '*update.exe') -or (_AnyLike '*autoupdate*.exe') -or (_AnyLike '*upgrade*.exe')) { $upd.Add('updater binary present (verify)') }
    if ($upd.Count -eq 0) { $upd.Add('none detected') }

    # ---------- R07 privilege model ----------
    $priv = 'asInvoker (default)'
    if ($mainBlob -match 'requestedExecutionLevel[^>]*level="([^"]+)"') {
        $priv = $matches[1]
        if ($mainBlob -match 'autoElevate"?\s*[:=]\s*"?true') { $priv += ' + autoElevate' }
    } elseif ($manifest) {
        try {
            $nsm = Get-TcpkAppxNsMgr -Manifest $manifest
            $rft = $manifest.DocumentElement.SelectSingleNode("//rescap:Capability[@Name='runFullTrust']", $nsm)
            if ($rft) { $priv = 'runFullTrust (MSIX full-trust)' }
        } catch { }
    }

    # ---------- R08 code-signing identity ----------
    $sig = [pscustomobject]@{ Status='unknown'; Subject=$null; Issuer=$null; NotAfter=$null; KeySize=$null; Algorithm=$null; Note=$null }
    if ($isMsix) {
        # Inner PEs of an installed MSIX are NOT individually Authenticode-signed --
        # they are covered package-wide by AppxMetadata\CodeIntegrity.cat. Report at
        # the package level so the card is honest.
        $cat = Join-Path $dir 'AppxMetadata\CodeIntegrity.cat'
        if (Test-Path -LiteralPath $cat) {
            $sig.Status = 'MSIX catalog-signed'
            $sig.Note   = 'Package integrity enforced by AppxMetadata\CodeIntegrity.cat; inner PEs are not separately Authenticode-signed.'
            try {
                $ac = Get-AuthenticodeSignature -FilePath $cat -ErrorAction Stop
                if ($ac.SignerCertificate) {
                    $c = $ac.SignerCertificate
                    $sig.Subject  = $c.Subject
                    $sig.Issuer   = $c.Issuer
                    $sig.NotAfter = $c.NotAfter.ToString('yyyy-MM-dd')
                    try { $sig.KeySize   = $c.PublicKey.Key.KeySize } catch { }
                    try { $sig.Algorithm = $c.SignatureAlgorithm.FriendlyName } catch { }
                }
            } catch { }
        } else {
            $sig.Status = 'MSIX (no catalog found)'
            $sig.Note   = 'No AppxMetadata\CodeIntegrity.cat present in the extracted package.'
        }
    } else {
        $sigTarget = if ($mainExePath) { $mainExePath } else { $Path }
        try {
            $as = Get-AuthenticodeSignature -FilePath $sigTarget -ErrorAction Stop
            $sig.Status = "$($as.Status)"
            if ($as.SignerCertificate) {
                $c = $as.SignerCertificate
                $sig.Subject  = $c.Subject
                $sig.Issuer   = $c.Issuer
                $sig.NotAfter = $c.NotAfter.ToString('yyyy-MM-dd')
                try { $sig.KeySize   = $c.PublicKey.Key.KeySize } catch { }
                try { $sig.Algorithm = $c.SignatureAlgorithm.FriendlyName } catch { }
            }
        } catch { }
    }

    # ---------- R01 app-type ----------
    $appType =
        if ($isMsix)               { 'MSIX / AppX package' }
        elseif ($isElectron)       { 'Electron app' }
        elseif ($isNwjs)           { 'NW.js app' }
        elseif ($isJava)           { 'Java application' }
        elseif ($isPython)         { 'Python (bundled) application' }
        elseif ($isTauri)          { 'Tauri app' }
        elseif ($isFlutter)        { 'Flutter desktop app' }
        elseif (_FileLike '*.application') { 'ClickOnce application' }
        elseif ($exeCount -gt 0)   { 'Win32 application' }
        else                       { 'unknown' }

    # ---------- R04 third-party SDK inventory ----------
    $sdks = New-Object 'System.Collections.Generic.List[object]'
    $seenCompany = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ownVendor = if ($publisher) { ($publisher -replace '(?i),?\s*(inc|llc|ltd|corp|corporation|gmbh|co)\.?$','').Trim() } else { '' }
    foreach ($p in ($pes | Where-Object { $_.Extension -ieq '.dll' } | Sort-Object Length -Descending)) {
        if ($sdks.Count -ge 14) { break }
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p.FullName)
            $co = $vi.CompanyName
            if (-not $co) { continue }
            if ($co -match '(?i)microsoft') { continue }                       # framework noise
            if ($ownVendor -and $co -match [regex]::Escape($ownVendor)) { continue }  # first-party
            # Internal projects often set CompanyName = assembly name (namespace
            # style, no spaces). Treat "Company == file base name" as first-party noise.
            if ($co -ieq $p.BaseName) { continue }
            if ($co -notmatch '\s' -and $co -match '\.' -and $co -ieq $vi.ProductName) { continue }
            if ($seenCompany.Contains($co)) { continue }
            $seenCompany.Add($co) | Out-Null
            $sdks.Add([pscustomobject]@{
                Name    = if ($vi.ProductName) { $vi.ProductName } else { $p.BaseName }
                Company = $co
                Version = if ($vi.ProductVersion) { $vi.ProductVersion } else { $vi.FileVersion }
                File    = $p.Name
            })
        } catch { }
    }

    # ---------- R09 attack-surface: detailed recon lists (from observed findings) ----------
    # Precise rule-id matching -- the earlier loose 'port' regex wrongly matched
    # 'pe-imports.phantom' (imports contains 'port'). Anchor every pattern.
    function _Find([string]$regex) { return @($Findings | Where-Object { $_.RuleId -match $regex }) }
    function _Leaf($p) { if ($p) { return (Split-Path -Leaf $p) } return '' }

    # Network endpoints (backend hosts the app talks to) -- normalized + classified
    # (first-party / telemetry / cloud-storage / cdn / auth / update) with risk flags.
    # The classification is folded into Detail so existing report tables show it.
    $endpoints = _Find '^backend\.endpoint$' | ForEach-Object {
        $hostName = if ($_.Title -match 'Backend host:\s*([^\s(]+)') { $matches[1] } else { $_.Title }
        $info = Get-TcpkEndpointInfo -HostName $hostName -Raw "$($_.Evidence) $($_.Title)"
        $tag  = '[' + $info.Category + $(if ($info.Flags.Count) { '; ' + ($info.Flags -join ', ') } else { '' }) + ']'
        [pscustomobject]@{
            Host = $hostName; Detail = ("$($_.Evidence)  $tag").Trim(); File = (_Leaf $_.File)
            Category = $info.Category; Scheme = $info.Scheme; Cleartext = $info.Cleartext; Flags = $info.Flags
        }
    }
    $endpointMap = Get-TcpkEndpointMap -Endpoints @($endpoints)
    # Listening ports / UDP endpoints (live-process only)
    $listening = _Find '^ports\.(tcp-listening|udp-endpoint)$' | ForEach-Object {
        [pscustomobject]@{
            Endpoint = $_.Evidence
            Proto    = $(if ($_.RuleId -match 'udp') { 'UDP' } else { 'TCP' })
            Severity = $_.Severity
            Scope    = $(if ($_.Evidence -match '^(0\.0\.0\.0|::)') { 'ALL interfaces' } elseif ($_.Evidence -match '^(127\.0\.0\.1|::1)') { 'localhost' } else { 'specific iface' })
        }
    }
    # Protocol handlers (custom URI schemes)
    $protoHandlers = _Find '^(protocol-handler|msix\.protocol-handler)$' | ForEach-Object {
        [pscustomobject]@{ Title = $_.Title; Detail = $_.Evidence }
    }
    # COM servers
    $comServers = _Find '^(com\.|msix\.com-server$)' | ForEach-Object {
        [pscustomobject]@{ Title = $_.Title; Detail = $_.Evidence }
    }
    # Named pipes
    $namedPipes = _Find '^pipe\.exists$' | ForEach-Object {
        [pscustomobject]@{ Title = $_.Title; Detail = $_.Evidence }
    }
    # File-type associations
    $fileAssocs = _Find '^msix\.file-type-association$' | ForEach-Object {
        [pscustomobject]@{ Title = $_.Title; Detail = $_.Evidence }
    }
    # Update URLs
    $updateUrls = _Find '^update\.url-found$' | ForEach-Object { $_.Evidence }
    # Non-production endpoints
    $nonProd = _Find '^endpoints\.non-production$' | ForEach-Object { $_.Evidence }
    # TLS posture summary
    $tlsPosture = New-Object 'System.Collections.Generic.List[string]'
    if ((_Find '^tls\.pinning-present$').Count) { $tlsPosture.Add('certificate pinning: present') }
    elseif ((_Find '^tls\.pinning-absent$').Count) { $tlsPosture.Add('certificate pinning: ABSENT') }
    if ((_Find '^tls\.revocation-disabled$').Count) { $tlsPosture.Add('revocation checking: disabled') }
    if ((_Find '^wcf\.(basichttp-cleartext|no-auth)$').Count) { $tlsPosture.Add('WCF cleartext/no-auth binding present') }

    $counts = [pscustomobject]@{
        Dll             = $dllCount
        Exe             = $exeCount
        Sys             = $sysCount
        Endpoint        = @($endpoints).Count
        Port            = @($listening).Count
        Com             = @($comServers).Count
        Pipe            = @($namedPipes).Count
        Service         = (_Find '^service\.').Count
        ProtocolHandler = @($protoHandlers).Count
        FileAssoc       = @($fileAssocs).Count
    }

    # ---------- assemble profile ----------
    [pscustomobject]@{
        Name            = $name
        Version         = $version
        Publisher       = $publisher
        Architecture    = $arch
        InstallPath     = $Path
        AppType         = $appType
        PackageFullName = $pkgFullName
        MainExecutable  = if ($mainExePath) { Split-Path -Leaf $mainExePath } else { $null }
        Runtime         = $runtime
        RuntimeDetail   = $runtimeDetail
        UiFrameworks    = $ui.ToArray()
        NetworkProtocols= $net.ToArray()
        UpdateMechanism = $upd.ToArray()
        PrivilegeModel  = $priv
        IsElectron      = [bool]$isElectron
        IsCef           = [bool]$isCef
        IsTauri         = [bool]$isTauri
        IsFlutter       = [bool]$isFlutter
        Signature       = $sig
        ThirdPartySdks  = $sdks.ToArray()
        Counts          = $counts
        # ---- detailed recon (end-to-end attack surface) ----
        Endpoints        = @($endpoints)
        EndpointMap      = @($endpointMap)
        ListeningPorts   = @($listening)
        ProtocolHandlers = @($protoHandlers)
        ComServers       = @($comServers)
        NamedPipes       = @($namedPipes)
        FileAssociations = @($fileAssocs)
        UpdateUrls       = @($updateUrls)
        NonProdEndpoints = @($nonProd)
        TlsPosture       = $tlsPosture.ToArray()
    }
}
