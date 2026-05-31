function Disable-TcpkLlmCloud {
<#
.SYNOPSIS
    Turn off cloud LLM use for this session (reverts to local-only).
#>
    [CmdletBinding()] param()
    $script:TcpkLlmCloudEnabled = $false
    Write-Information -InformationAction Continue -MessageData 'TCPK cloud LLM disabled. Local backend only.'
}
