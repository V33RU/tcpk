# Read a shipped .NET assembly's OWN identity (package name + version) so a bare managed DLL
# gets CVE-checked even when the app ships no *.deps.json / packages.config manifest.
#
# WHY: the OSV NuGet path only sees packages DECLARED in a manifest. A mixed native + .NET app
# often ships Newtonsoft.Json.dll etc. as loose DLLs with no manifest,
# so they were never CVE-checked. Reading the assembly identity via the bundled Mono.Cecil closes
# that gap. Uses AssemblyInformationalVersion (== the NuGet package version, e.g. "13.0.4+sha");
# NEVER AssemblyVersion, which vendors freeze (13.0.0.0) and would misfire the version compare.

# Framework / runtime assemblies whose CVEs track the .NET runtime, not a NuGet package version --
# skipped to avoid noise + wasted OSV queries. Real NuGet packages that happen to be Microsoft-
# published (System.Text.Json, System.IdentityModel.*, Microsoft.Data.SqlClient, ...) are NOT
# skipped: only the base-runtime assemblies are.
$script:TcpkFxAsmSkip = '^(mscorlib|netstandard|WindowsBase|PresentationCore|PresentationFramework|ReachFramework|System\.Private\..*|System|System\.Core|System\.Xml|System\.Data|System\.Drawing|System\.Windows\.Forms|System\.Runtime|System\.Configuration|System\.ServiceModel|System\.Web|clr.*|coreclr|Microsoft\.CSharp|Microsoft\.VisualBasic|Microsoft\.Win32\..*|Accessibility|UIAutomation.*)$'

function Get-TcpkManagedNugetComponents {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Dir)
    if (-not (Initialize-TcpkCecil)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($f in (Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter '*.dll' -ErrorAction SilentlyContinue)) {
        $asm = $null; try { $asm = Get-TcpkCecilAssembly $f.FullName } catch { }
        if (-not $asm) { continue }                          # native / unreadable -> Cecil returns null
        $name = "$($asm.Name.Name)"; if (-not $name) { continue }
        if ($name -match $script:TcpkFxAsmSkip) { continue }

        # version: AssemblyInformationalVersion first (the true NuGet version), then FileVersion.
        # AssemblyVersion is deliberately NOT used (often frozen to <major>.0.0.0).
        $ver = $null
        try {
            $ia = $asm.CustomAttributes | Where-Object { "$($_.AttributeType.FullName)" -eq 'System.Reflection.AssemblyInformationalVersionAttribute' } | Select-Object -First 1
            if ($ia -and $ia.ConstructorArguments.Count) { $ver = "$($ia.ConstructorArguments[0].Value)" }
        } catch { }
        if (-not $ver) { try { $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($f.FullName).FileVersion } catch { } }
        if (-not $ver) { continue }
        $mm = [regex]::Match("$ver", '^\d+\.\d+(\.\d+)?'); if (-not $mm.Success) { continue }
        $ver = $mm.Value

        $key = "$($name.ToLowerInvariant())|$ver"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $out.Add([pscustomobject]@{ Name = $name; Version = $ver; File = $f.Name })
    }
    return @($out.ToArray())
}
