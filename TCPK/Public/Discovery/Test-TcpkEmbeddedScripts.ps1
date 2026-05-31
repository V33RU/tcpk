function Test-TcpkEmbeddedScripts {
<#
.SYNOPSIS
    A20. Embedded script files shipped in the package.

.DESCRIPTION
    Finds PowerShell / JavaScript / Python / Lua / VBScript / batch files
    shipped inside the install dir. Each is INFO severity; manual review
    is the next step. Combined with reflection-based code loading (A16),
    embedded scripts often become an indirect code-execution sink.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $exts = @{
        '.ps1'  = 'PowerShell'
        '.psm1' = 'PowerShell module'
        '.js'   = 'JavaScript'
        '.py'   = 'Python'
        '.lua'  = 'Lua'
        '.vbs'  = 'VBScript'
        '.bat'  = 'Batch'
        '.cmd'  = 'Batch'
        '.wsf'  = 'WSH'
    }

    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)) {
        $ext = $f.Extension.ToLowerInvariant()
        if (-not $exts.ContainsKey($ext)) { continue }

        New-TcpkFinding -Module 'static' -RuleId "embedded-script.$($ext.TrimStart('.'))" `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($exts[$ext]) script shipped: $($f.Name)" `
            -File $f.FullName -Evidence "size=$($f.Length)" `
            -Description 'Triage: confirm whether the host process executes this script at runtime, and whether the path is user-writable.'
    }
}
