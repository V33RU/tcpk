function Get-TcpkLlmProvider {
<#
.SYNOPSIS
    List the built-in LLM providers (for the GUI dropdown) or the current selection.
.PARAMETER Current
    Return the currently-configured provider settings instead of the list.
#>
    [CmdletBinding()] param([switch]$Current)
    if ($Current) {
        $cfg = Get-TcpkLlmConfig
        return [pscustomobject]@{
            Provider = $cfg.provider; Model = $cfg.model
            BaseUrl = $cfg.baseUrl; Enabled = $cfg.enabled
            HasKey = [bool]$cfg.apiKey
        }
    }
    foreach ($name in $script:TcpkLlmProviders.Keys | Sort-Object) {
        $p = $script:TcpkLlmProviders[$name]
        [pscustomobject]@{
            Provider     = $name
            Dialect      = $p.dialect
            Cloud        = $p.cloud
            NeedsKey     = $p.needsKey
            BaseUrl      = $p.baseUrl
            DefaultModel = $p.defaultModel
        }
    }
}
