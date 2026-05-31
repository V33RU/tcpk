function Enable-TcpkLlmCloud {
<#
.SYNOPSIS
    Allow TCPK to send findings to a CLOUD LLM backend for this session.

.DESCRIPTION
    By default TCPK uses a LOCAL Ollama model -- nothing leaves the machine.
    Findings can contain extracted secrets, internal URLs, and decompiled
    proprietary code. Sending those to a third-party cloud LLM is a
    deliberate decision, so it is gated.

    Calling this with -Acknowledge sets a session flag permitting cloud use
    (only takes effect if llm-config.json backend = 'cloud'). Secret values
    are still redacted to prefix/suffix before any prompt is built.

.PARAMETER Acknowledge
    Confirms you accept sending audit data to the configured cloud endpoint.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][switch]$Acknowledge)
    if (-not $Acknowledge) { throw '-Acknowledge required.' }
    $script:TcpkLlmCloudEnabled = $true
    $cfg = Get-TcpkLlmConfig
    Write-Information -InformationAction Continue -MessageData @"

TCPK cloud LLM ENABLED for this session.
-----------------------------------------------------------
Backend:  $($cfg.cloud.baseUrl)
Model:    $($cfg.cloud.model)
API key:  from env var '$($cfg.cloud.apiKeyEnvVar)'

Reminder: audit findings (redacted secrets, internal URLs, decompiled
code excerpts) will be sent to the above endpoint. Use only for targets
where that is acceptable. Disable with: Disable-TcpkLlmCloud

"@
}
