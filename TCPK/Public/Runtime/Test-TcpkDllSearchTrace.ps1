function Test-TcpkDllSearchTrace {
<#
.SYNOPSIS
    E08. ETW capture of NAME NOT FOUND DLL probes during a window.

.DESCRIPTION
    Starts a kernel-file ETW session, captures Microsoft-Windows-Kernel-File
    events for -Seconds seconds, filters to the target PID, and emits a
    HIGH finding for each *.dll probe that returned 0xC0000034
    (STATUS_OBJECT_NAME_NOT_FOUND). Each such probe is a runtime-confirmed
    hijack candidate.

    Requires admin. Operator should exercise the app during the window.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProcessName,
        [int]$Seconds = 30
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkDllSearchTrace')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'dll-search.skipped-no-admin' `
            -Title 'DLL-search ETW trace skipped (admin required)'
        return
    }

    $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        New-TcpkSkippedFinding -RuleId 'dll-search.no-process' `
            -Title "Process '$ProcessName' not running"
        return
    }

    $sess = "TCPK-DllSearch-$([Guid]::NewGuid().ToString().Substring(0,8))"
    $etl  = Join-Path $env:TEMP "$sess.etl"
    $started = $false

    try {
        $out = & logman create trace $sess -p Microsoft-Windows-Kernel-File 0xffffffff 0xff -o $etl -ets 2>&1
        if ($LASTEXITCODE -ne 0) {
            New-TcpkSkippedFinding -RuleId 'dll-search.etw-start-failed' `
                -Title "Could not start ETW session: $LASTEXITCODE" -Reason ($out -join ' ')
            return
        }
        $started = $true
        Write-Information -MessageData "  Capturing $Seconds s of file-event ETW for PID $($proc.Id)..." -InformationAction Continue
        Start-Sleep -Seconds $Seconds
    } finally {
        if ($started) { & logman stop $sess -ets 2>&1 | Out-Null }
    }

    if (-not (Test-Path $etl)) { return }
    try { $events = Get-WinEvent -Path $etl -Oldest -ErrorAction Stop } catch {
        New-TcpkSkippedFinding -RuleId 'dll-search.etw-parse-failed' `
            -Title 'Cannot parse captured ETL' -Reason $_.Exception.Message
        Remove-Item $etl -Force -ErrorAction SilentlyContinue
        return
    }
    foreach ($e in $events) {
        try { $xml = [xml]$e.ToXml() } catch { continue }
        try { $epid = $xml.Event.System.Execution.ProcessID } catch { continue }
        if (-not $epid -or [int]$epid -ne $proc.Id) { continue }
        $file = $null; $st = $null
        try {
            $file = ($xml.Event.EventData.Data | Where-Object Name -eq 'FileName').'#text'
            $st   = ($xml.Event.EventData.Data | Where-Object Name -eq 'Status').'#text'
        } catch { }
        if ($file -and $st -and $file -match '\.dll$' -and $st -eq '0xC0000034') {
            New-TcpkFinding -Module 'runtime' -RuleId 'dll-search.name-not-found' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($proc.Name) probed $file and got NAME NOT FOUND" `
                -File $file -Evidence "PID=$epid status=$st" `
                -Cwe @('CWE-427') `
                -Fix 'Patch the call site to use a full path or LOAD_LIBRARY_SEARCH_SYSTEM32.'
        }
    }
    Remove-Item $etl -Force -ErrorAction SilentlyContinue
}
