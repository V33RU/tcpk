# Platform / privilege helpers.

function Test-TcpkIsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return ($IsWindows -eq $true)
}

function Test-TcpkIsAdmin {
    if (-not (Test-TcpkIsWindows)) { return $false }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-TcpkWindows {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Caller)
    if (-not (Test-TcpkIsWindows)) {
        Write-Warning "$Caller requires Windows. Skipping."
        return $false
    }
    return $true
}

function Get-TcpkPsVersion {
    return $PSVersionTable.PSVersion.ToString()
}
