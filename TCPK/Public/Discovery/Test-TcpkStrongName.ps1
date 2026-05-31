function Test-TcpkStrongName {
<#
.SYNOPSIS
    A05. .NET assembly strong-name presence check.

.DESCRIPTION
    For each .NET PE under the path, reads the assembly identity via
    System.Reflection.AssemblyName and reports any assembly that ships
    WITHOUT a public-key token (unsigned). Strong names are not a security
    boundary in modern .NET (Core+) but their absence still indicates a
    weaker assembly identity model that interacts with reflection-based
    loading patterns.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -notin '.dll','.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name)  { continue }
        try {
            $an = [System.Reflection.AssemblyName]::GetAssemblyName($pe.FullName)
        } catch {
            # Not a managed assembly, or unreadable -- silently skip
            continue
        }
        $tokenBytes = $an.GetPublicKeyToken()
        $hasToken = ($tokenBytes -and $tokenBytes.Length -gt 0)
        if (-not $hasToken) {
            New-TcpkFinding -Module 'static' -RuleId 'strongname.unsigned' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "$($pe.Name) has no strong-name public key token" `
                -File $pe.FullName -Evidence "Version=$($an.Version)" `
                -Description 'Assembly identity is name+version only -- weakens reflection-based assembly resolution.' `
                -Fix 'Sign the assembly during build (csc.exe /keyfile, or <SignAssembly>true</SignAssembly> in csproj).'
        }
    }
}
