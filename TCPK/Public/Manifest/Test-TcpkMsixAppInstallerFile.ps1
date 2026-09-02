function Test-TcpkMsixAppInstallerFile {
<#
.SYNOPSIS
    B10. Parse shipped .appinstaller XML files (main-package URI, dependencies, HotPath,
    UpdateSettings). Distinct from B05 Test-TcpkMsixAppInstaller which only reads the
    uap5:Extension pointer inside AppxManifest.xml.

.DESCRIPTION
    A .appinstaller file is the XML that Windows fetches from the update URL declared in
    an MSIX package's AppxManifest (or that ships alongside a sideloaded install). It
    controls: which .msix / .msixbundle / .appx to install, which dependency packages to
    pull, whether background updates are silent, and (in the 2021+ schema) whether the
    MSIX install directory is patched in-place via HotPath. Any of those URIs going
    plaintext, or pointing outside the vendor's own domain, downgrades the whole package's
    signature guarantee.

    Rules:
      msix.appinstaller.plaintext-uri            HIGH    Confirmed  Any Uri attribute in the
                                                                     .appinstaller resolves as
                                                                     http:// - a MITM can
                                                                     substitute the fetched
                                                                     package payload.
      msix.appinstaller.hotpath-uri              HIGH    Confirmed  HotPath / HotSource /
                                                                     SharedContentPath element
                                                                     present - Windows
                                                                     applies live-file
                                                                     patches from the URI.
      msix.appinstaller.force-update-any-version HIGH    Confirmed  <ForceUpdateFromAnyVersion>
                                                                     true</> allows downgrade
                                                                     to a known-vulnerable
                                                                     older release.
      msix.appinstaller.silent-update            MEDIUM  Confirmed  UpdateSettings.OnLaunch
                                                                     ShowPrompt="false" with
                                                                     UpdateBlocksActivation
                                                                     "false" - the user
                                                                     never sees the update.
      msix.appinstaller.dependency-cross-domain  MEDIUM  Confirmed  A Dependencies\Package
                                                                     Uri points at a host
                                                                     different from
                                                                     MainPackage / MainBundle.
      msix.appinstaller.self-uri-mismatch        MEDIUM  Confirmed  <AppInstaller Uri="..."> at
                                                                     the root has a different
                                                                     host from MainPackage /
                                                                     MainBundle.

.PARAMETER Path
    Install directory or a single .appinstaller file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $files = @()
    $item = Get-Item -LiteralPath $Path
    $maxBytes = 262144
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.appinstaller' -ErrorAction SilentlyContinue |
                       Where-Object { $_.Length -lt $maxBytes })
        } catch { return }
    } elseif ($item.Extension -ieq '.appinstaller' -and $item.Length -lt $maxBytes) {
        # Apply the same size cap on the single-file branch. A crafted deeply-nested XML
        # would otherwise blow the PS 5.1 call stack via _CollectUris recursion below.
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    # Microsoft framework CDN hosts that legitimately appear in <Dependencies>\<Package>
    # alongside a vendor MainPackage. Cross-domain dependency finding suppresses these
    # (VCLibs, .NET Native, WinUI2 all ship from Microsoft-owned endpoints).
    $msftFrameworkHostRx = '(?i)(^|\.)microsoft\.com$|^aka\.ms$|(^|\.)msftconnecttest\.com$|(^|\.)akadns\.net$|(^|\.)windows\.net$|(^|\.)azureedge\.net$|(^|\.)s-microsoft\.com$'

    function _HostOf([string]$uri) {
        if (-not $uri) { return $null }
        try { return ([Uri]$uri).Host } catch { return $null }
    }
    function _CollectUris($node, [int]$Depth = 0) {
        # Depth-first collect every Uri="..." attribute value under a node, tagged with
        # the element local name (so we can distinguish MainPackage vs Package vs HotPath).
        # Depth-capped at 64: a hostile .appinstaller with pathological nesting cannot
        # blow the PS 5.1 script recursion budget through this function.
        $out = @()
        if (-not $node -or $Depth -gt 64) { return $out }
        if ($node.Attributes) {
            foreach ($attr in $node.Attributes) {
                if ($attr.LocalName -eq 'Uri' -or $attr.LocalName -eq 'URI') {
                    $out += [pscustomobject]@{ Element = $node.LocalName; Uri = "$($attr.Value)" }
                }
            }
        }
        if ($node.ChildNodes) {
            foreach ($ch in $node.ChildNodes) {
                if ($ch.NodeType -eq 'Element') { $out += (_CollectUris $ch ($Depth + 1)) }
            }
        }
        return $out
    }

    foreach ($f in $files) {
        $doc = New-Object System.Xml.XmlDocument
        try { $doc.Load($f.FullName) } catch { continue }
        $root = $doc.DocumentElement
        if (-not $root -or $root.LocalName -ne 'AppInstaller') { continue }

        # Own root URI (the location this .appinstaller is fetched from) - not a finding by
        # itself but used to detect self-uri-mismatch later.
        $selfUri = "$($root.GetAttribute('Uri'))"

        # Enumerate every Uri= attribute anywhere in the tree, tagged with owning element.
        $uris = @(_CollectUris $root)

        # ---- msix.appinstaller.plaintext-uri (HIGH per hit) ------------------------
        foreach ($u in $uris) {
            if ($u.Uri -match '^(?i)http://') {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.plaintext-uri' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) <$($u.Element)> Uri is http:// : $($u.Uri)" `
                    -File $f.FullName -Evidence "<$($u.Element) Uri='$($u.Uri)'>" `
                    -Cwe @('CWE-319','CWE-494') `
                    -Description ("A URI inside the .appinstaller resolves as plain HTTP. Windows fetches " +
                        "the referenced package (MSIX / bundle / dependency) from this URL, and a network " +
                        "attacker on the path substitutes it. The MSIX package signature is checked AFTER " +
                        "the file is fetched, but a substituted unsigned package will simply be refused - " +
                        "for the HotPath and SharedContentPath elements the same primitive is a live-file " +
                        "swap into the installed directory even without a package resign. HIGH is per URI so " +
                        "the report shows every plaintext endpoint the .appinstaller ships.") `
                    -Fix 'Serve the .appinstaller and every URI it names over HTTPS to a publisher-controlled host. Pin the publisher certificate.'
            }
        }

        # ---- msix.appinstaller.hotpath-uri (HIGH) -----------------------------------
        # Restricted to the elements that ACTUALLY perform a live-file patch of the
        # installed directory without a full package resign. Deliberately excludes:
        #   OptionalPackage    - a normal add-on MSIX shipped alongside main, signed itself
        #   ContentGroupMap    - streaming-install layout, not a file-swap primitive
        #   RepairPackage      - a signed package fetched only during repair, not a patch
        $hotElements = @('HotPath','HotSource','SharedContentPath')
        foreach ($u in $uris) {
            if ($hotElements -contains $u.Element) {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.hotpath-uri' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) declares a live-patch URI: <$($u.Element)>" `
                    -File $f.FullName -Evidence "<$($u.Element) Uri='$($u.Uri)'>" `
                    -Cwe @('CWE-494','CWE-345') `
                    -Description ("The .appinstaller declares a <$($u.Element)> element. In the appinstaller " +
                        "2021+ schema those elements patch files in the installed MSIX directory in place, " +
                        "without a full package resign. Anyone who can serve the fetch URI (or MITM it if " +
                        "plaintext) rewrites application files under the signed package identity - the " +
                        "MSIX signature guarantee no longer applies to the patched files.") `
                    -Fix 'Only use HotPath / SharedContentPath if the fetch URI is HTTPS + certificate-pinned to the publisher, and the served bytes are themselves signed by an out-of-band vendor signature that the app verifies at load time.'
            }
        }

        # ---- msix.appinstaller.force-update-any-version (HIGH) ----------------------
        # <ForceUpdateFromAnyVersion>true</> allows a lower-version .msix to REPLACE the
        # currently installed one -> a downgrade attack to a known-vulnerable release is
        # legitimate under the app's update policy.
        $fu = $root.SelectNodes('//*[local-name()="ForceUpdateFromAnyVersion"]')
        foreach ($n in $fu) {
            if ("$($n.InnerText)" -match '(?i)^\s*true\s*$') {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.force-update-any-version' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) allows downgrade updates (ForceUpdateFromAnyVersion=true)" `
                    -File $f.FullName -Evidence '<ForceUpdateFromAnyVersion>true</ForceUpdateFromAnyVersion>' `
                    -Cwe @('CWE-1329') `
                    -Description ('When ForceUpdateFromAnyVersion is true the .appinstaller can install a ' +
                        'package whose version is LOWER than the currently installed one. Combined with the ' +
                        "vendor's own signature on an older release, this permits a downgrade attack that " +
                        're-introduces already-fixed CVEs. Windows treats the downgrade as a normal update.') `
                    -Fix 'Set ForceUpdateFromAnyVersion=false (or remove it), and rely on Windows Package Manager to refuse a lower-version install unless explicitly authorised by the operator.'
            }
        }

        # ---- msix.appinstaller.silent-update (MEDIUM) --------------------------------
        $ol = $root.SelectSingleNode('//*[local-name()="OnLaunch"]')
        if ($ol) {
            $showPromptRaw = "$($ol.GetAttribute('ShowPrompt'))"
            $blocksActRaw  = "$($ol.GetAttribute('UpdateBlocksActivation'))"
            # OnLaunch schema defaults: ShowPrompt=false, UpdateBlocksActivation=false. Both
            # being false (either absent or an explicit "false") means the update just
            # happens; the user never sees it. Report the effective value in the evidence
            # so a bare <OnLaunch/> does not read as if the parse broke.
            $showPromptEff = if ($showPromptRaw) { $showPromptRaw } else { 'false (default)' }
            $blocksActEff  = if ($blocksActRaw)  { $blocksActRaw }  else { 'false (default)' }
            $isSilentPrompt = ($showPromptRaw -eq '' -or $showPromptRaw -match '(?i)^\s*false\s*$')
            $isSilentBlock  = ($blocksActRaw  -eq '' -or $blocksActRaw  -match '(?i)^\s*false\s*$')
            if ($isSilentPrompt -and $isSilentBlock) {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.silent-update' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($f.Name) auto-updates on launch with no user prompt" `
                    -File $f.FullName -Evidence "<OnLaunch ShowPrompt='$showPromptEff' UpdateBlocksActivation='$blocksActEff'/>" `
                    -Cwe @('CWE-345','CWE-1188') `
                    -Description ('The OnLaunch update policy fetches and installs a new package silently ' +
                        'on every launch, with no user prompt. Any compromise of the update endpoint (or ' +
                        'a MITM against a plaintext URI) turns into a code-push with no human in the loop.') `
                    -Fix 'Set ShowPrompt="true" and UpdateBlocksActivation="true" so the user consents (or explicitly declines) before a fetched update is installed. Reserve silent update for security-critical patches only.'
            }
        }

        # ---- msix.appinstaller.dependency-cross-domain (MEDIUM) ----------------------
        # Build MainPackage / MainBundle host set, then flag any Package under Dependencies
        # whose Uri host is different.
        $mainHosts = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($u in $uris) {
            if ($u.Element -in 'MainPackage','MainBundle') {
                $h = _HostOf $u.Uri
                if ($h) { [void]$mainHosts.Add($h.ToLowerInvariant()) }
            }
        }
        if ($mainHosts.Count -gt 0) {
            foreach ($u in $uris) {
                if ($u.Element -eq 'Package') {
                    $h = _HostOf $u.Uri
                    if (-not $h) { continue }
                    if ($mainHosts.Contains($h.ToLowerInvariant())) { continue }
                    # Microsoft-hosted framework CDN: VCLibs, .NET Native, WinUI2 all ship
                    # from Microsoft-owned hosts alongside a vendor's own MainPackage. That
                    # is the norm, not a defect, so this rule stops firing on those.
                    if ($h -match $msftFrameworkHostRx) { continue }
                    New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.dependency-cross-domain' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title "$($f.Name) dependency Uri host $h differs from MainPackage host(s)" `
                        -File $f.FullName -Evidence "<Package Uri='$($u.Uri)'>; main hosts=$($mainHosts -join ',')" `
                        -Cwe @('CWE-494') `
                        -Description ('A Dependencies\Package Uri lives on a host that is not one of the ' +
                            "MainPackage / MainBundle hosts and is not on the Microsoft framework CDN " +
                            "allow-list (VCLibs, WinUI2, .NET Native and their Microsoft-owned mirrors are " +
                            "excluded from this rule). For a first-party dependency it means the vendor " +
                            "trusts a third party they may not have audited. Confirm the third-party host " +
                            "actually belongs to the dependency's publisher.") `
                        -Fix 'Serve every dependency from a publisher-controlled host, or verify each cross-domain URI is a well-known framework endpoint.'
                }
            }
        }

        # ---- msix.appinstaller.self-uri-mismatch (MEDIUM) ---------------------------
        if ($selfUri) {
            $selfHost = _HostOf $selfUri
            if ($selfHost -and $mainHosts.Count -gt 0 -and -not $mainHosts.Contains($selfHost.ToLowerInvariant())) {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.appinstaller.self-uri-mismatch' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($f.Name) <AppInstaller Uri> host $selfHost differs from MainPackage host(s)" `
                    -File $f.FullName -Evidence "self=$selfUri; main hosts=$($mainHosts -join ',')" `
                    -Cwe @('CWE-346') `
                    -Description ('The .appinstaller root Uri (where Windows checks for the next version) ' +
                        'is on a different host than the MainPackage / MainBundle. That split is unusual for ' +
                        'a publisher-controlled release channel and often indicates a proxy / mirror that ' +
                        'the publisher does not own.') `
                    -Fix 'Serve the .appinstaller and the MainPackage from the same publisher-controlled host, or document the split.'
            }
        }
    }
}
