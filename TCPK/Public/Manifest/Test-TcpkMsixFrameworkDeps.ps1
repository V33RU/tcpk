function Test-TcpkMsixFrameworkDeps {
<#
.SYNOPSIS
    B02. Framework dependencies (VCLibs / WindowsAppRuntime) declared correctly.

.DESCRIPTION
    Cross-checks each shipped PE's static imports against the framework
    PackageDependency entries in AppxManifest.xml. If any shipped DLL imports
    VC runtime (vcruntime140.dll etc.) but the manifest does not declare a
    Microsoft.VCLibs dependency, the OS may not provision the framework
    package and load can fall back to PATH-based resolution.

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

    $deps = @()
    if ($m.Package.Dependencies) {
        $deps = @($m.Package.Dependencies.PackageDependency | ForEach-Object { $_.Name })
    }
    $hasVcLibs = $deps -match 'VCLibs'

    if (-not $hasVcLibs) {
        foreach ($pe in Get-TcpkPeFiles -Path $expanded) {
            $info = Read-TcpkPe -Path $pe.FullName
            if (-not $info) { continue }
            $vcImports = $info.Imports | Where-Object {
                $_ -match '^(msvcp140|vcruntime140|concrt140|vccorlib140)'
            }
            if ($vcImports) {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.missing-vclibs-dep' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) needs VC runtime but VCLibs is not declared in manifest" `
                    -File $pe.FullName -Evidence "imports: $($vcImports -join ', ')" `
                    -Cwe @('CWE-427') `
                    -Fix "Declare <PackageDependency Name='Microsoft.VCLibs.140.00.UWPDesktop' MinVersion='14.0.x.y' /> in AppxManifest.xml."
                break
            }
        }
    }
}
