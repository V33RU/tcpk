function Get-TcpkAppIdentity {
<#
.SYNOPSIS
    Fast pre-audit "what kind of application is this?" fingerprint.

.DESCRIPTION
    A concise identity projection for the "Identify" step shown BEFORE an audit runs
    (desktop GUI, web control panel, agentic workbench). It reuses the recon profiler
    (Get-TcpkTargetProfile) -- app type, runtime/language, UI framework, publisher,
    architecture, code-signing -- and returns a compact object plus a one-line Summary,
    so the operator sees what they are about to scan (native C/C++, .NET desktop,
    Electron, Java, Python, Go/Rust, MSIX, ...) without running the full audit.

    Emits NO findings. Metadata only.

.PARAMETER Path
    Target install dir, EXE/DLL, or an MSIX/MSI/ZIP (auto-unwrapped by the profiler).

.OUTPUTS
    [pscustomobject] identity summary.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $prof = Get-TcpkTargetProfile -Path $Path
    $managed = ("$($prof.Runtime)" -match '(?i)\.NET')
    $ui = @($prof.UiFrameworks | Where-Object { $_ -and $_ -ne 'unknown / custom' })

    # one-line human summary: "<AppType> | <Runtime> | <arch> -- <UI> -- signed by <Publisher>"
    $bits = New-Object System.Collections.Generic.List[string]
    if ($prof.AppType) { $bits.Add("$($prof.AppType)") }
    if ($prof.Runtime -and "$($prof.Runtime)" -ne "$($prof.AppType)") { $bits.Add("$($prof.Runtime)") }
    if ($prof.Architecture -and $prof.Architecture -ne 'unknown') { $bits.Add("$($prof.Architecture)") }
    $summary = ($bits -join ' | ')
    if ($ui.Count) { $summary += "  --  UI: " + ($ui -join ', ') }
    if ($prof.Publisher) { $summary += "  --  by $($prof.Publisher)" }

    [pscustomobject]@{
        Name            = $prof.Name
        Version         = $prof.Version
        Publisher       = $prof.Publisher
        AppType         = $prof.AppType
        Runtime         = $prof.Runtime
        RuntimeDetail   = $prof.RuntimeDetail
        Architecture    = $prof.Architecture
        MainExecutable  = $prof.MainExecutable
        Managed         = [bool]$managed
        UiFrameworks    = @($ui)
        NetworkProtocols= @($prof.NetworkProtocols | Where-Object { $_ -and $_ -ne 'not determined' })
        SignatureStatus = "$($prof.Signature.Status)"
        Signer          = "$($prof.Signature.Subject)"
        IsElectron      = [bool]$prof.IsElectron
        IsTauri         = [bool]$prof.IsTauri
        IsFlutter       = [bool]$prof.IsFlutter
        DllCount        = $prof.Counts.Dll
        ExeCount        = $prof.Counts.Exe
        Summary         = $summary
    }
}
