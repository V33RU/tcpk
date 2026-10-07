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
    (only takes effect if the configured provider in llm-config.json is a
    cloud backend). Secret values are still redacted to prefix/suffix before
    any prompt is built.

.PARAMETER Acknowledge
    Confirms you accept sending audit data to the configured cloud endpoint.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][switch]$Acknowledge)
    if (-not $Acknowledge) { throw '-Acknowledge required.' }
    $script:TcpkLlmCloudEnabled = $true
    $cfg = Get-TcpkLlmConfig
    # Resolve the real destination the same way Get-TcpkLlmClient does, so the
    # consent banner names the endpoint that proprietary code will actually reach.
    $providerName = if ($cfg.provider) { $cfg.provider } else { 'ollama' }
    $preset = $script:TcpkLlmProviders[$providerName]
    $baseUrl = if ($cfg.baseUrl) { $cfg.baseUrl } elseif ($preset) { $preset.baseUrl } else { '' }
    $model   = if ($cfg.model)   { $cfg.model }   elseif ($preset) { $preset.defaultModel } else { '' }
    if (-not $baseUrl) { $baseUrl = '(unset -- set baseUrl in llm-config.json)' }
    if (-not $model)   { $model   = '(unset -- set model in llm-config.json)' }
    $keyState = if ($cfg.apiKey) { 'set in llm-config.json' }
                elseif ($preset -and -not $preset.needsKey) { 'not required for this provider' }
                else { 'NOT SET -- enter it in the GUI AI panel or llm-config.json apiKey' }
    Write-Information -InformationAction Continue -MessageData @"

TCPK cloud LLM ENABLED for this session.
-----------------------------------------------------------
Provider: $providerName
Endpoint: $baseUrl
Model:    $model
API key:  $keyState

Reminder: audit findings (redacted secrets, internal URLs, decompiled
code excerpts) will be sent to the above endpoint. Use only for targets
where that is acceptable. Disable with: Disable-TcpkLlmCloud

"@
}
