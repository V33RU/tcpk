function Test-TcpkMsixDeclaredVsUsed {
<#
.SYNOPSIS
    B08. Declared-vs-used capability cross-check.

.DESCRIPTION
    Lists the network-impact capabilities the manifest declares but the
    shipped binaries do NOT seem to actually use (no static import of
    ws2_32.dll, no http* strings, etc.). Over-declared capabilities are a
    privilege-bloat hygiene issue: the app gets more OS permissions than
    it needs, which raises blast radius if compromised.

    This is a heuristic -- a managed-only app could still call sockets via
    System.Net without any visible native marker -- so confidence is
    Inferred, severity is LOW.

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

    $declared = @()
    if ($m.Package.Capabilities) {
        $declared = @($m.Package.Capabilities.ChildNodes | ForEach-Object { $_.Name })
    }
    if (-not $declared) { return }

    # Heuristic: for each declared capability, scan first-party PEs for
    # static markers that suggest the capability is being exercised.
    $markers = @{
        'internetClient'             = @('ws2_32','wininet','System.Net.Http','HttpClient','WebClient','Socket(')
        'internetClientServer'       = @('ws2_32','HttpListener','TcpListener')
        'privateNetworkClientServer' = @('ws2_32','HttpListener','TcpListener')
        'documentsLibrary'           = @('KnownFolders.DocumentsLibrary','MyDocuments','SpecialFolder.Personal')
        'picturesLibrary'            = @('KnownFolders.PicturesLibrary','SpecialFolder.MyPictures')
        'videosLibrary'              = @('KnownFolders.VideosLibrary','SpecialFolder.MyVideos')
        'musicLibrary'               = @('KnownFolders.MusicLibrary','SpecialFolder.MyMusic')
        'removableStorage'           = @('KnownFolders.RemovableDevices')
        'enterpriseAuthentication'   = @('Negotiate','Kerberos','WindowsAuthentication')
        'sharedUserCertificates'     = @('X509Store','UserCertificateStore')
    }

    # Build a single concatenated text blob from first-party PEs once
    $allText = New-Object Text.StringBuilder
    foreach ($pe in Get-TcpkPeFiles -Path $expanded) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $t = Read-TcpkAllText -Path $pe.FullName
        if ($t) { [void]$allText.Append($t) }
    }
    $blob = $allText.ToString()

    foreach ($cap in $declared) {
        if (-not $markers.ContainsKey($cap)) { continue }
        $used = $false
        foreach ($mk in $markers[$cap]) {
            if ($blob.Contains($mk)) { $used = $true; break }
        }
        if (-not $used) {
            New-TcpkFinding -Module 'manifest' -RuleId "msix.over-declared.$cap" `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "Capability '$cap' declared but no first-party code marker found" `
                -File $Path -Evidence "markers scanned: $($markers[$cap] -join ', ')" `
                -Cwe @('CWE-250') `
                -Description 'Heuristic: the manifest grants this capability but no first-party DLL contains any string suggesting it is actually used. Verify and drop if confirmed unused.' `
                -Fix "Remove <Capability Name='$cap' /> from AppxManifest.xml if not required."
        }
    }
}
