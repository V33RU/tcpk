function Test-TcpkLlm {
<#
.SYNOPSIS
    Connectivity + sanity check for the configured LLM provider.
#>
    [CmdletBinding()] param()

    $cfg = Get-TcpkLlmConfig
    $b = $null
    try { $b = Resolve-TcpkLlmBackend } catch {
        # The reason used to go out on the WARNING stream only. The GUI does not display
        # that stream, so every failure surfaced as a bare "Reachable=False": a missing
        # cloud consent, a wrong port, a dead proxy and a token an SSO org has not
        # authorised were indistinguishable. Return it as a field so a caller can show it.
        $m = "$($_.Exception.Message)"
        Write-Warning $m
        return [pscustomobject]@{ Provider=$cfg.provider; Model=$cfg.model; Reachable=$false; ModelResponds=$false; Reply=$null; Error=$m }
    }

    Write-Information -InformationAction Continue -MessageData "Provider: $($b.Provider)  Dialect: $($b.Dialect)  Model: $($b.Model)  URL: $($b.BaseUrl)"
    Write-Information -InformationAction Continue -MessageData "Checking backend..."

    $reply = $null; $reachable = $false; $responds = $false; $err = $null
    try {
        $reply = Invoke-TcpkLlm `
            -System 'You are a security analysis assistant. Answer in one short sentence.' `
            -User   'Reply with exactly: TCPK LLM link OK' -MaxRetries 1
        $reachable = $true; $responds = [bool]$reply
    } catch {
        $err = Get-TcpkHttpErrorText $_
        Write-Warning "LLM call failed: $err"
    }

    [pscustomobject]@{
        Provider      = $b.Provider
        Model         = $b.Model
        Reachable     = $reachable
        ModelResponds = $responds
        Reply         = $reply
        Error         = $err
    }
}
