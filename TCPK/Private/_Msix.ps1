# MSIX / AppX expansion helper.
# Given a path to a .msix / .appx / .msixbundle file, extract into a temp
# directory and return the directory path.
# Given a directory (already-extracted install), return it as-is.

function Expand-TcpkMsix {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer) { return $item.FullName }

    $ext = $item.Extension.ToLowerInvariant()
    if ($ext -notin '.msix','.appx','.msixbundle','.appxbundle','.zip') {
        return $item.FullName
    }

    $dest = Join-Path $env:TEMP ("TCPK_" + [IO.Path]::GetFileNameWithoutExtension($Path))
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest -Force | Out-Null

    # Expand-Archive in PS 5.1 dislikes non-.zip extensions; copy to .zip first.
    $tmpZip = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName() + '.zip')
    try {
        Copy-Item -LiteralPath $Path -Destination $tmpZip -Force
        Expand-Archive -LiteralPath $tmpZip -DestinationPath $dest -Force
        return $dest
    } finally {
        if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force }
    }
}

# Convenience: read AppxManifest.xml from an extracted package dir.
# Returns $null if no manifest.
function Read-TcpkAppxManifest {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ExpandedPath)
    $mp = Join-Path $ExpandedPath 'AppxManifest.xml'
    if (-not (Test-Path -LiteralPath $mp)) { return $null }
    try {
        [xml](Get-Content -LiteralPath $mp -Raw)
    } catch {
        $null
    }
}

# Build an XmlNamespaceManager for AppxManifest XPath queries.
# Returns $null if the XML doesn't have a NameTable (defensive).
function Get-TcpkAppxNsMgr {
    [CmdletBinding()] param([Parameter(Mandatory)][xml]$Manifest)
    if (-not $Manifest.NameTable) { return $null }
    $nsm = New-Object System.Xml.XmlNamespaceManager $Manifest.NameTable
    $nsm.AddNamespace('d',       'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $nsm.AddNamespace('uap',     'http://schemas.microsoft.com/appx/manifest/uap/windows10')
    $nsm.AddNamespace('uap2',    'http://schemas.microsoft.com/appx/manifest/uap/windows10/2')
    $nsm.AddNamespace('uap3',    'http://schemas.microsoft.com/appx/manifest/uap/windows10/3')
    $nsm.AddNamespace('uap4',    'http://schemas.microsoft.com/appx/manifest/uap/windows10/4')
    $nsm.AddNamespace('uap5',    'http://schemas.microsoft.com/appx/manifest/uap/windows10/5')
    $nsm.AddNamespace('uap10',   'http://schemas.microsoft.com/appx/manifest/uap/windows10/10')
    $nsm.AddNamespace('desktop', 'http://schemas.microsoft.com/appx/manifest/desktop/windows10')
    $nsm.AddNamespace('desktop2','http://schemas.microsoft.com/appx/manifest/desktop/windows10/2')
    $nsm.AddNamespace('desktop4','http://schemas.microsoft.com/appx/manifest/desktop/windows10/4')
    $nsm.AddNamespace('rescap',  'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities')
    $nsm.AddNamespace('com',     'http://schemas.microsoft.com/appx/manifest/com/windows10')
    # Comma operator prevents PowerShell from enumerating the IEnumerable
    # XmlNamespaceManager into the pipeline as a string[] of prefixes.
    , $nsm
}
