function Test-TcpkRpcSurface {
<#
.SYNOPSIS
    E16. MS-RPC server interface surface (static).

.DESCRIPTION
    A thick client that registers an RPC server interface exposes a cross-process
    (and sometimes cross-host) attack surface: any caller that can bind to the
    interface invokes its methods. This statically detects RPC SERVER primitives
    (RpcServerRegisterIf*, RpcServerUseProtseq*, RpcServerListen, NdrServerCall,
    MIDL_SERVER_INFO) in first-party binaries -- a triage signal to enumerate the
    interface (RpcView) and review each method's access checks.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $serverMarkers = @(
        'RpcServerRegisterIf','RpcServerRegisterIf2','RpcServerRegisterIfEx',
        'RpcServerUseProtseq','RpcServerUseProtseqEp','RpcServerUseAllProtseqs',
        'RpcServerListen','RpcServerInqBindings','NdrServerCall2','NdrServerCallNdr64',
        'MIDL_SERVER_INFO','I_RpcServerStartListening','RpcServerRegisterAuthInfo'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsNativeNoise $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @($serverMarkers | Where-Object { $text.Contains($_) } | Select-Object -Unique)
        if ($hits.Count -eq 0) { continue }

        # auth on the interface?
        $hasAuth = $text.Contains('RpcServerRegisterAuthInfo') -or $text.Contains('RpcBindingInqAuthClient')
        $sev = if ($hasAuth) { 'LOW' } else { 'MEDIUM' }

        New-TcpkFinding -Module 'runtime' -RuleId 'rpc.server-interface' `
            -Severity $sev -Confidence 'Inferred' `
            -Title "$($pe.Name) registers an RPC server interface" `
            -File $pe.FullName -Evidence "$($hits -join ', ')$(if (-not $hasAuth) { ' | no RpcServerRegisterAuthInfo seen' })" `
            -Cwe @('CWE-668','CWE-306') `
            -Description 'The binary exposes an MS-RPC server. Enumerate the endpoint with RpcView, identify the interface UUID, and confirm every method validates the caller (RpcBindingInqAuthClient / a security callback). Unauthenticated RPC methods that touch privileged operations are a cross-process EoP/RCE primitive.' `
            -Fix 'Require authentication on the interface (RpcServerRegisterIf2 with a security callback / RpcServerRegisterAuthInfo); restrict the protocol sequence (ncalrpc/local) where possible.'
    }
}
