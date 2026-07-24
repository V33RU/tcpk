function Test-TcpkEtwProviders {
<#
.SYNOPSIS
    H04. Custom ETW / EventSource providers (cross-process telemetry leak).

.DESCRIPTION
    An app that registers its own ETW provider (System.Diagnostics.Tracing.
    EventSource, the native EventRegister/EventWrite APIs, or a TraceLogging
    provider) emits structured events that ANY process able to start a trace
    session for the provider GUID can read. If those events carry credentials,
    tokens, PII, file paths, or request bodies, that is an information-
    disclosure channel that bypasses file-log ACLs.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = @(
        'System.Diagnostics.Tracing.EventSource','EventSourceAttribute',
        'EventRegister','EventWrite','EventWriteTransfer','EventProviderTraits',
        'TraceLoggingProvider','EtwProvider','RegisterTraceGuids'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        # Skip non-first-party binaries: EventRegister/EventSource in the Electron main exe and
        # the elevate helper is standard Chromium/Electron tracing, not a first-party provider.
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @($markers | Where-Object { $text.Contains($_) })
        if ($hits.Count -eq 0) { continue }

        # Try to surface declared provider names ([EventSource(Name="...")])
        $names = @([regex]::Matches($text, 'EventSource\(Name\s*=\s*"([^"]{3,80})"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique -First 6)
        $evid = "markers: $($hits -join ', ')"
        if ($names.Count) { $evid += " | providers: $($names -join ', ')" }

        New-TcpkFinding -Module 'logging' -RuleId 'etw.custom-provider' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title "$($pe.Name) registers a custom ETW/EventSource provider" `
            -File $pe.FullName -Evidence $evid -Cwe @('CWE-532','CWE-200') `
            -Description 'Custom ETW events are readable by any process that can start a trace session for the provider GUID (no file ACL applies). Decompile the WriteEvent / EventWrite call sites and confirm no credentials, tokens, session IDs, PII, or full request/response bodies are emitted.' `
            -Fix 'Keep secrets and PII out of ETW payloads; mark sensitive events with appropriate keywords/levels and restrict via a controlled provider.'
    }
}
