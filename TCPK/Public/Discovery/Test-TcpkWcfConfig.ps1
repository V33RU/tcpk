function Test-TcpkWcfConfig {
<#
.SYNOPSIS
    A14. Audit shipped WCF config files for cleartext / unauthenticated bindings.

.DESCRIPTION
    Walks *.config / app.config / web.config / *.exe.config files under the
    target path and flags:
      - BasicHttpBinding without transport security (cleartext SOAP)
      - <authentication mode="None"> declarations

.PARAMETER Path
    Folder. Single files ignored.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $configs = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -eq '.config' }

    foreach ($f in $configs) {
        try { $t = [IO.File]::ReadAllText($f.FullName) } catch { continue }

        if ($t -match '(?i)BasicHttpBinding' -and
            $t -notmatch '(?i)security mode="(Transport|TransportWithMessageCredential)') {
            New-TcpkFinding -Module 'static' -RuleId 'wcf.basichttp-cleartext' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "BasicHttpBinding without transport security (cleartext SOAP)" `
                -File $f.FullName -Evidence 'BasicHttpBinding without security mode=Transport' `
                -Cwe @('CWE-319') `
                -Fix 'Switch to WSHttpBinding or BasicHttpsBinding with Transport security.'
        }

        if ($t -match '<authentication[^>]*mode="None"') {
            New-TcpkFinding -Module 'static' -RuleId 'wcf.no-auth' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WCF service declared with authentication mode='None'" `
                -File $f.FullName -Evidence 'authentication mode="None"' `
                -Cwe @('CWE-306')
        }

        # ---- wcf.message-cred-none: HIGH ---------------------------------------
        # Extension. <authentication mode="None"> above is the WCF service-model /
        # ASP.NET-shape flag; here we look at the BINDING SECURITY element that
        # authenticates the SOAP message itself:
        #
        #   <wsHttpBinding>
        #     <binding name="anon">
        #       <security mode="Message">
        #         <message clientCredentialType="None" negotiateServiceCredential="true"/>
        #       </security>
        #     </binding>
        #   </wsHttpBinding>
        #
        # clientCredentialType="None" on WSHttp / WSFederation / NetTcp / NetNamed /
        # NetMsmq lets the client speak the RPC without authenticating. Different
        # bug shape from wcf.basichttp-cleartext (transport) and wcf.no-auth
        # (service model).
        if ($t -match '(?is)<message\b[^>]*\bclientCredentialType\s*=\s*"None"') {
            New-TcpkFinding -Module 'static' -RuleId 'wcf.message-cred-none' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'WCF binding declares <message clientCredentialType="None"/> (unauthenticated RPC)' `
                -File $f.FullName -Evidence '<message clientCredentialType="None"/>' `
                -Cwe @('CWE-306','CWE-287') `
                -Description ('The WCF binding security block accepts an unauthenticated SOAP message. ' +
                    'Any caller who can reach the endpoint invokes contract methods without proving identity. ' +
                    'Distinct from wcf.no-auth (which fires on the service-model authentication element) and ' +
                    'wcf.basichttp-cleartext (which fires on the transport). All three can coexist on the ' +
                    'same endpoint.') `
                -Fix 'Set clientCredentialType to Windows / Certificate / UserName as appropriate for the deployment, or move to a binding that requires transport auth (BasicHttpsBinding with clientCredentialType=Certificate).'
        }

        # Also flag NetTcpBinding / NetNamedPipeBinding with security mode="None".
        # These are common on Windows service backends and often left unauthenticated
        # under the assumption that same-machine access is "trusted enough".
        if ($t -match '(?is)<(?:netTcpBinding|netNamedPipeBinding)\b[\s\S]{0,400}?<security\b[^>]*\bmode\s*=\s*"None"') {
            $which = if ($t -match '(?i)netTcpBinding') { 'netTcpBinding' } else { 'netNamedPipeBinding' }
            New-TcpkFinding -Module 'static' -RuleId 'wcf.message-cred-none' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "WCF $which security mode='None' (unauthenticated endpoint)" `
                -File $f.FullName -Evidence "$which + <security mode='None'/>" `
                -Cwe @('CWE-306','CWE-287') `
                -Description ("$which with <security mode='None'/> disables both transport and message " +
                    'authentication. On a shared-user host or a container image the endpoint accepts ' +
                    'connections from any local process, including lower-integrity sandboxes.') `
                -Fix "Set security mode='Transport' or 'Message' with a non-'None' clientCredentialType. For local IPC prefer Windows credentials on netNamedPipeBinding + a DACL that restricts the pipe."
        }
    }
}
