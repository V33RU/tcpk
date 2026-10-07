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

    # Registration primitives, including the modern RpcServerRegisterIf3 / RpcServerRegisterIf2Ex
    # (If3 takes both a security descriptor and an interface security callback). The plain
    # RpcServerRegisterIf prefix would substring-match the newer names, but listing them
    # explicitly credits the actual API in the evidence and catches If2Ex on its own.
    $serverMarkers = @(
        'RpcServerRegisterIf','RpcServerRegisterIf2','RpcServerRegisterIfEx',
        'RpcServerRegisterIf2Ex','RpcServerRegisterIf3',
        'RpcServerUseProtseq','RpcServerUseProtseqEp','RpcServerUseAllProtseqs',
        'RpcServerListen','RpcServerInqBindings','NdrServerCall2','NdrServerCallNdr64',
        'MIDL_SERVER_INFO','I_RpcServerStartListening','RpcServerRegisterAuthInfo'
    )
    # Caller-authentication / security-callback APIs. Transport auth (RpcServerRegisterAuthInfo),
    # per-call client inspection (RpcBindingInqAuthClient) and the call-attributes query a
    # security callback uses to vet the caller (RpcServerInqCallAttributes /
    # I_RpcBindingInqSecurityContext). Any of these means the interface has SOME access control;
    # none means a bound caller reaches every method unchecked.
    $authMarkers = @(
        'RpcServerRegisterAuthInfo','RpcBindingInqAuthClient',
        'RpcServerInqCallAttributes','I_RpcBindingInqSecurityContext'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsNativeNoise $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @($serverMarkers | Where-Object { $text.Contains($_) } | Select-Object -Unique)
        if ($hits.Count -eq 0) { continue }

        # auth on the interface? (transport auth, per-call inspection, or a security callback)
        $authHits = @($authMarkers | Where-Object { $text.Contains($_) } | Select-Object -Unique)
        $hasAuth  = $authHits.Count -gt 0
        $sev = if ($hasAuth) { 'LOW' } else { 'MEDIUM' }
        $authNote = if ($hasAuth) { " | auth: $($authHits -join ', ')" }
                    else { ' | no caller-auth or security-callback API seen (RpcServerRegisterAuthInfo / RpcBindingInqAuthClient / RpcServerInqCallAttributes)' }

        New-TcpkFinding -Module 'runtime' -RuleId 'rpc.server-interface' `
            -Severity $sev -Confidence 'Inferred' `
            -Title "$($pe.Name) registers an RPC server interface" `
            -File $pe.FullName -Evidence "$($hits -join ', ')$authNote" `
            -Cwe @('CWE-668','CWE-306') `
            -Description 'The binary exposes an MS-RPC server. Enumerate the endpoint with RpcView, identify the interface UUID, and confirm every method validates the caller (a security callback passed to RpcServerRegisterIf2/If3, RpcBindingInqAuthClient, or RpcServerRegisterAuthInfo). A server that links none of these registers its interface with no access control, so any local caller that binds invokes its methods -- a cross-process EoP/RCE primitive. This is a static string signal: confirm the callback argument is non-null, since a callback parameter may be passed NULL.' `
            -Fix 'Require authentication on the interface (RpcServerRegisterIf2/If3 with a non-null security callback, or RpcServerRegisterAuthInfo); restrict the protocol sequence (ncalrpc/local) where possible.'
    }
}
