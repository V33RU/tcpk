function Test-TcpkNamedObjects {
<#
.SYNOPSIS
    E15. Named kernel objects (mutex/event/section) -- squatting / race surface.

.DESCRIPTION
    Statically extracts named-object literals (Global\... / Local\... and the
    creation APIs) from first-party binaries. A named object created with a
    predictable name and a default DACL can be pre-created ("squatted") by a
    low-privileged process before the real app starts:
      - squatting a single-instance mutex -> denial of service
      - squatting a shared section/event   -> state confusion / race condition
      - if a privileged process opens it    -> potential privilege escalation

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $apiRx = [regex]'(CreateMutex|CreateMutexEx|OpenMutex|CreateEvent|CreateEventEx|CreateSemaphore|CreateFileMapping|OpenFileMapping|CreateWaitableTimer)'
    $nameRx = [regex]'(Global|Local)\\[A-Za-z0-9_.{}\-]{3,64}'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $names = @($nameRx.Matches($text) | ForEach-Object { $_.Value } | Select-Object -Unique)
        $apis  = @($apiRx.Matches($text)  | ForEach-Object { $_.Value } | Select-Object -Unique)
        if ($names.Count -eq 0 -and $apis.Count -eq 0) { continue }

        # Global\ names are the squattable ones (visible to all sessions)
        $globalNames = @($names | Where-Object { $_ -like 'Global\*' })
        $sev = if ($globalNames.Count) { 'MEDIUM' } else { 'LOW' }
        $evid = ''
        if ($names.Count) { $evid += "names: $((@($names) | Select-Object -First 12) -join ', ')" }
        if ($apis.Count)  { if ($evid) { $evid += ' | ' }; $evid += "apis: $($apis -join ', ')" }

        New-TcpkFinding -Module 'runtime' -RuleId 'named-object.creation' `
            -Severity $sev -Confidence 'Inferred' `
            -Title "$($pe.Name) creates named kernel objects$(if ($globalNames.Count) { ' (Global\ namespace)' })" `
            -File $pe.FullName -Evidence $evid -Cwe @('CWE-412','CWE-668') `
            -Description 'Named objects with predictable names and default DACLs can be pre-created by a low-privileged process (squatting). Confirm a strong, randomized name OR an explicit DACL (deny non-owners), and that the app fails safe when CreateMutex/CreateEvent returns ERROR_ALREADY_EXISTS from an object it did not create.' `
            -Fix 'Create named objects with an explicit SECURITY_ATTRIBUTES DACL; treat ERROR_ALREADY_EXISTS on a Global\ object as hostile.'
    }
}
