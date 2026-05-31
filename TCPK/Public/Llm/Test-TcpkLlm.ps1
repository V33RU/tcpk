function Test-TcpkLlm {
<#
.SYNOPSIS
    Connectivity + sanity check for the configured LLM provider.
#>
    [CmdletBinding()] param()

    $cfg = Get-TcpkLlmConfig
    $b = $null
    try { $b = Resolve-TcpkLlmBackend } catch {
        Write-Warning $_.Exception.Message
        return [pscustomobject]@{ Provider=$cfg.provider; Reachable=$false; ModelResponds=$false; Reply=$null }
    }

    Write-Information -InformationAction Continue -MessageData "Provider: $($b.Provider)  Dialect: $($b.Dialect)  Model: $($b.Model)  URL: $($b.BaseUrl)"
    Write-Information -InformationAction Continue -MessageData "Checking backend..."

    $reply = $null; $reachable = $false; $responds = $false
    try {
        $reply = Invoke-TcpkLlm `
            -System 'You are a security analysis assistant. Answer in one short sentence.' `
            -User   'Reply with exactly: TCPK LLM link OK' -MaxRetries 1
        $reachable = $true; $responds = [bool]$reply
    } catch {
        Write-Warning "LLM call failed: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        Provider      = $b.Provider
        Model         = $b.Model
        Reachable     = $reachable
        ModelResponds = $responds
        Reply         = $reply
    }
}
