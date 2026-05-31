function Test-TcpkMsixFileAssocs {
<#
.SYNOPSIS
    B04. File type associations declared in AppxManifest.xml.

.DESCRIPTION
    A file type association makes any file with that extension a one-click
    attacker delivery vector: user double-clicks malicious.foo, OS hands the
    bytes to this app, parser bugs become RCE.

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

    foreach ($node in $m.DocumentElement.SelectNodes('//uap:Extension[@Category="windows.fileTypeAssociation"]', $nsm)) {
        $fta = $node.FileTypeAssociation
        if (-not $fta) { continue }
        $exts = @()
        if ($fta.SupportedFileTypes -and $fta.SupportedFileTypes.FileType) {
            $exts = @($fta.SupportedFileTypes.FileType)
        }
        $extList = if ($exts) { $exts -join ', ' } else { '(unknown)' }
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.file-type-association' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "File type association declared: $extList" `
            -File $Path -Evidence $extList `
            -Cwe @('CWE-20') `
            -Description 'Files of these extensions, when opened via Explorer, will be delivered to this app. Treat input as attacker-controlled.' `
            -Fix 'Audit the file-open handler for parser bugs and unsafe deserialization on the supported file format.'
    }
}
