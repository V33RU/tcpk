function Get-TcpkCaptureInterface {
<#
.SYNOPSIS
    List the network capture interfaces available via the operator's installed Wireshark
    (tshark -D). For picking an interface for Invoke-TcpkPcapCapture.

.OUTPUTS
    [pscustomobject] with Id / Name / Desc per interface. Empty if tshark is not installed.
#>
    [CmdletBinding()]
    param([string]$TsharkPath)
    Get-TcpkCaptureInterfaces -TsharkPath $TsharkPath
}
