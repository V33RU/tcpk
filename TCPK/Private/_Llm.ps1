# LLM client -- multi-provider, model-agnostic.
# Two API dialects are supported:
#   * 'openai'    -> POST {baseUrl}/chat/completions   (Ollama, OpenAI, DeepSeek, Gemini, Grok/xAI, Azure, any OpenAI-compatible gateway)
#   * 'anthropic' -> POST {baseUrl}/v1/messages        (Claude)
# Provider, model, key and dialect all come from Data\llm-config.json, which the
# GUI writes when the operator picks a backend. The MODEL is free-text -- you can
# type ANY model the provider exposes (no hardcoded model list); 'custom' lets you
# point at any other OpenAI-compatible endpoint by setting baseUrl in the config.

$script:TcpkLlmConfig = $null

# Built-in provider presets. The GUI exposes these by name; 'custom' = bring-your-own URL.
# Gemini and Grok both expose an OpenAI-compatible surface (Bearer auth, /chat/completions,
# /models), so they use the 'openai' dialect.
$script:TcpkLlmProviders = @{
    'ollama'    = @{ dialect='openai';    baseUrl='http://localhost:11434/v1'; needsKey=$false; cloud=$false; defaultModel='qwen2.5-coder:7b' }
    'claude'    = @{ dialect='anthropic'; baseUrl='https://api.anthropic.com';  needsKey=$true;  cloud=$true;  defaultModel='claude-sonnet-5' }
    'openai'    = @{ dialect='openai';    baseUrl='https://api.openai.com/v1';  needsKey=$true;  cloud=$true;  defaultModel='gpt-4o' }
    'gemini'    = @{ dialect='openai';    baseUrl='https://generativelanguage.googleapis.com/v1beta/openai'; needsKey=$true; cloud=$true; defaultModel='gemini-2.0-flash' }
    'grok'      = @{ dialect='openai';    baseUrl='https://api.x.ai/v1';        needsKey=$true;  cloud=$true;  defaultModel='grok-2-latest' }
    'deepseek'  = @{ dialect='openai';    baseUrl='https://api.deepseek.com';   needsKey=$true;  cloud=$true;  defaultModel='deepseek-chat' }
    'custom'    = @{ dialect='openai';    baseUrl='';                           needsKey=$true;  cloud=$true;  defaultModel='' }
}

function Get-TcpkLlmConfigPath { Join-Path $script:TcpkRoot 'Data\llm-config.json' }

function Get-TcpkLlmConfig {
    [CmdletBinding()] param([switch]$Force)
    if ($script:TcpkLlmConfig -and -not $Force) { return $script:TcpkLlmConfig }
    $path = Get-TcpkLlmConfigPath
    if (Test-Path -LiteralPath $path) {
        $script:TcpkLlmConfig = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    } else {
        $script:TcpkLlmConfig = [pscustomobject]@{
            enabled = $false; provider = 'ollama'; model = 'qwen2.5-coder:7b'
            baseUrl = ''; apiKey = ''; temperature = 0.1; timeoutSeconds = 120
            redactSecrets = $true; onlyEnrichSeverityAtLeast = 'MEDIUM'
        }
    }
    return $script:TcpkLlmConfig
}

# Write config (called by the GUI when the operator picks a backend / enters a key).
function Set-TcpkLlmConfig {
    [CmdletBinding()]
    param(
        [string]$Provider, [string]$Model, [string]$BaseUrl, [string]$ApiKey,
        [bool]$Enabled, [double]$Temperature
    )
    $cfg = Get-TcpkLlmConfig
    if ($PSBoundParameters.ContainsKey('Provider'))    { $cfg | Add-Member provider $Provider -Force }
    if ($PSBoundParameters.ContainsKey('Model'))       { $cfg | Add-Member model $Model -Force }
    if ($PSBoundParameters.ContainsKey('BaseUrl'))     { $cfg | Add-Member baseUrl $BaseUrl -Force }
    if ($PSBoundParameters.ContainsKey('ApiKey'))      { $cfg | Add-Member apiKey $ApiKey -Force }
    if ($PSBoundParameters.ContainsKey('Enabled'))     { $cfg | Add-Member enabled $Enabled -Force }
    if ($PSBoundParameters.ContainsKey('Temperature')) { $cfg | Add-Member temperature $Temperature -Force }
    $cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Get-TcpkLlmConfigPath) -Encoding UTF8
    $script:TcpkLlmConfig = $cfg
    return $cfg
}

# Resolve effective backend settings: dialect, url, model, headers, auth.
function Resolve-TcpkLlmBackend {
    [CmdletBinding()] param()
    $cfg = Get-TcpkLlmConfig
    $providerName = if ($cfg.provider) { $cfg.provider } else { 'ollama' }
    $preset = $script:TcpkLlmProviders[$providerName]
    if (-not $preset) { throw "Unknown LLM provider '$providerName'." }

    # cloud providers require the cloud gate + a key
    if ($preset.cloud) {
        if (-not $script:TcpkLlmCloudEnabled) {
            throw "Provider '$providerName' is a cloud backend. Run Enable-TcpkLlmCloud -Acknowledge (the GUI does this when you pick a cloud provider)."
        }
    }

    $baseUrl = if ($cfg.baseUrl) { $cfg.baseUrl } else { $preset.baseUrl }
    $model   = if ($cfg.model)   { $cfg.model }   else { $preset.defaultModel }
    $key     = $cfg.apiKey

    if ($preset.needsKey -and -not $key) {
        throw "Provider '$providerName' needs an API key. Enter it in the GUI (AI panel) or set llm-config.json apiKey."
    }

    $headers = @{ 'Content-Type' = 'application/json' }
    if ($preset.dialect -eq 'anthropic') {
        if ($key) { $headers['x-api-key'] = $key }
        $headers['anthropic-version'] = '2023-06-01'
    } elseif ($key) {
        $headers['Authorization'] = "Bearer $key"
    }

    return @{
        Provider = $providerName
        Dialect  = $preset.dialect
        BaseUrl  = $baseUrl.TrimEnd('/')
        Model    = $model
        Headers  = $headers
    }
}

# Is the CONFIGURED provider a cloud backend? Used to keep -EnableLlm local-only by
# default: cloud means the decompiled IL would leave the machine, which can breach a
# confidential engagement, so the audit requires an explicit -AllowCloudLlm to proceed.
function Test-TcpkLlmIsCloud {
    [CmdletBinding()] param()
    $cfg = Get-TcpkLlmConfig
    $name = if ($cfg.provider) { $cfg.provider } else { 'ollama' }
    $preset = $script:TcpkLlmProviders[$name]
    return [bool]($preset -and $preset.cloud)
}

function Test-TcpkLlmAvailable {
    [CmdletBinding()] param()
    try {
        $b = Resolve-TcpkLlmBackend
        if ($b.Dialect -eq 'anthropic') {
            # Anthropic has no public model-list ping; do a tiny messages call.
            $null = Invoke-TcpkLlm -System 'ping' -User 'reply ok' -MaxRetries 0
            return $true
        } else {
            $r = Invoke-RestMethod -Uri "$($b.BaseUrl)/models" -Headers $b.Headers -TimeoutSec 8 -ErrorAction Stop
            return $true
        }
    } catch {
        return $false
    }
}

function Invoke-TcpkLlm {
<#
.SYNOPSIS Send a chat prompt to the configured provider; return text (or parsed JSON with -AsJson).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$System,
        [Parameter(Mandatory)][string]$User,
        [switch]$AsJson,
        [int]$MaxRetries = 2
    )
    $cfg = Get-TcpkLlmConfig
    $b = Resolve-TcpkLlmBackend

    if ($b.Dialect -eq 'anthropic') {
        $uri = "$($b.BaseUrl)/v1/messages"
        # Do NOT send `temperature`: the newest Claude models (Opus 4.6/4.7/4.8,
        # Sonnet 4.6, ...) reject a custom temperature with HTTP 400
        # "temperature is deprecated for this model". Omitting it works across ALL
        # models, and the JSON-verdict prompt is already tightly constrained.
        $body = @{
            model      = $b.Model
            max_tokens = 1024
            system     = $System
            messages   = @(@{ role='user'; content=$User })
        }
    } else {
        $uri = "$($b.BaseUrl)/chat/completions"
        $body = @{
            model    = $b.Model
            messages = @(
                @{ role='system'; content=$System },
                @{ role='user';   content=$User }
            )
        }
        # Reasoning / GPT-5 models reject sampling params with HTTP 400
        # ("temperature is not supported / only the default (1) is supported"):
        # OpenAI o-series (o1/o3/o4/...), GPT-5.x, and DeepSeek-reasoner.
        # Only send temperature for models that accept it (gpt-4o/4.1, ollama,
        # deepseek-chat, other local models).
        if ($b.Model -notmatch '(?i)^(o\d|gpt-5)' -and $b.Model -notmatch '(?i)reasoner') {
            $body.temperature = [double]$cfg.temperature
        }
        if ($AsJson) { $body.response_format = @{ type = 'json_object' } }
    }
    $json = $body | ConvertTo-Json -Depth 8

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $b.Headers -Body $json `
                -TimeoutSec $cfg.timeoutSeconds -ErrorAction Stop
            $text = if ($b.Dialect -eq 'anthropic') { $resp.content[0].text } else { $resp.choices[0].message.content }
            if (-not $AsJson) { return $text }

            $clean = $text -replace '(?s)^\s*```(?:json)?\s*','' -replace '(?s)\s*```\s*$',''
            try { return ($clean | ConvertFrom-Json) }
            catch {
                $m = [regex]::Match($clean, '(?s)\{.*\}')
                if ($m.Success) { try { return ($m.Value | ConvertFrom-Json) } catch {} }
                return $null
            }
        } catch {
            if ($attempt -gt $MaxRetries) { throw "LLM call failed after $attempt attempts: $($_.Exception.Message)" }
            Start-Sleep -Seconds ([Math]::Min(5, $attempt * 2))
        }
    }
}
