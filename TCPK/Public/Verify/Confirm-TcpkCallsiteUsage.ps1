function Confirm-TcpkCallsiteUsage {
<#
.SYNOPSIS
    Deterministic IL verification of callsites.* findings: is the flagged API
    actually invoked, reachable, and fed by external input -- or a false positive?

.DESCRIPTION
    A substring scan (Test-TcpkCallsites) proves a dangerous API NAME is present in a
    binary, not that it is a real bug. This pass reads the IL with Mono.Cecil and
    refines each callsites.* finding's Confidence (never inventing findings):

      * API never actually called (call/newobj absent) -> 'Likely-FP (IL)', INFO
        -- the rule matched a string/type reference, not an invocation.
      * Injection-class sink called only with CONSTANT arguments -> 'Likely-FP (IL)',
        severity dropped one notch -- no external input reaches the sink here.
      * Injection-class sink REACHABLE and called with a DYNAMIC (ldarg/ldloc/ldfld/
        call) argument -> 'Confirmed (IL)' -- external input may reach it; review.
      * Otherwise (usage-class rule, or argument indeterminate) -> left as-is with an
        "actually invoked (N sites)" note.

    Conservative by design: the argument check only says 'constant' when NO dynamic
    source is found in the window, so a real bug is not demoted on a miss. Only
    managed-BCL sinks are mapped (P/Invoke-only rules are left untouched). Requires
    the Mono.Cecil bridge (ships with ILSpy); without it, findings pass through.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.OUTPUTS
    [TcpkFinding] -- same objects, Confidence/Severity/Description refined where proven.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings)

    begin {
        $all = New-Object 'System.Collections.Generic.List[object]'

        # callsites.<suffix> -> the managed sink type(s)/method(s) to look for, and
        # whether the dangerous ARGUMENT carries external input (injection-class).
        $map = @{
            'command-execution'          = @{ Inj = $true;  Sinks = @(@{T='System.Diagnostics.Process'},@{T='System.Diagnostics.ProcessStartInfo'}) }
            'sql-command-construction'   = @{ Inj = $true;  Sinks = @(@{T='SqlCommand'},@{T='OleDbCommand'},@{T='OdbcCommand'},@{T='MySqlCommand'},@{T='NpgsqlCommand'},@{T='SqliteCommand'},@{T='SQLiteCommand'}) }
            'ssrf-request-build'         = @{ Inj = $true;  Sinks = @(@{T='System.Net.WebRequest'},@{T='System.Net.Http.HttpClient'},@{T='System.Net.WebClient'},@{T='System.Net.Http.HttpRequestMessage'},@{T='RestClient'}) }
            'nosql-command-construction' = @{ Inj = $true;  Sinks = @(@{T='MongoCollection'},@{T='IMongoCollection'},@{T='BsonJavaScript'},@{T='FilterDefinition'},@{T='LiteCollection'}) }
            'ldap-query'                 = @{ Inj = $true;  Sinks = @(@{T='DirectorySearcher'},@{T='DirectoryEntry'}) }
            'xaml-objectdataprovider-rce'= @{ Inj = $true;  Sinks = @(@{T='XamlReader'},@{T='XamlServices'},@{T='ObjectDataProvider'}) }
            'path-traversal-build'       = @{ Inj = $true;  Sinks = @(@{T='System.IO.Path';M='Combine|GetFullPath'},@{T='ZipFile'}) }
            'weak-symmetric-crypto'      = @{ Inj = $false; Sinks = @(@{T='DESCryptoServiceProvider'},@{T='TripleDESCryptoServiceProvider'},@{T='RC2CryptoServiceProvider'},@{T='Cryptography.DES'},@{T='Cryptography.TripleDES'},@{T='Cryptography.RC2'}) }
            'weak-hash-md5-sha1'         = @{ Inj = $false; Sinks = @(@{T='Cryptography.MD5'},@{T='MD5CryptoServiceProvider'},@{T='SHA1Managed'},@{T='SHA1CryptoServiceProvider'},@{T='Cryptography.SHA1'}) }
            'weak-rng'                   = @{ Inj = $false; Sinks = @(@{T='System.Random'}) }
            'base64-as-encryption'       = @{ Inj = $false; Sinks = @(@{T='System.Convert';M='ToBase64String|FromBase64String'}) }
            'env-var-path-use'           = @{ Inj = $false; Sinks = @(@{T='System.Environment';M='GetEnvironmentVariable|ExpandEnvironmentStrings'}) }
        }
        $rank = @{ 'CRITICAL'=4; 'HIGH'=3; 'MEDIUM'=2; 'LOW'=1; 'INFO'=0 }
        $byRank = @{ 4='CRITICAL'; 3='HIGH'; 2='MEDIUM'; 1='LOW'; 0='INFO' }

        $cecilOk = $false
        try { $cecilOk = Test-TcpkCecilAvailable } catch { $cecilOk = $false }
    }

    process { foreach ($f in $Findings) { $all.Add($f) } }

    end {
        foreach ($f in $all) {
            if (-not $cecilOk -or "$($f.RuleId)" -notlike 'callsites.*') { $f; continue }
            if (-not $f.File -or ("$($f.File)" -notmatch '\.(dll|exe)$') -or -not (Test-Path -LiteralPath $f.File)) { $f; continue }
            $suffix = ("$($f.RuleId)" -split '\.', 2)[-1]
            $spec = $map[$suffix]
            if (-not $spec) { $f; continue }

            $total = 0; $anyReach = $false; $anyDyn = $false; $anyConst = $false
            foreach ($sink in $spec.Sinks) {
                $u = $null
                try {
                    if ($sink.M) { $u = Get-TcpkCallsiteUsage -DllPath $f.File -TypeFragment $sink.T -MethodName $sink.M -Injection:$spec.Inj }
                    else         { $u = Get-TcpkCallsiteUsage -DllPath $f.File -TypeFragment $sink.T -Injection:$spec.Inj }
                } catch { }
                if (-not $u) { continue }
                $total += $u.CallSiteCount
                if ($u.AnyReachable) { $anyReach = $true }
                if ($u.AnyDynamic)   { $anyDyn = $true }
                if ($u.AllConstant)  { $anyConst = $true }
            }

            if ($total -eq 0) {
                $f.Confidence = 'Likely-FP (IL)'
                $f.Severity   = 'INFO'
                $f.Description = "$($f.Description) [TCPK IL: the flagged API is not actually invoked in $(Split-Path $f.File -Leaf) (call/newobj absent) -- the rule matched a string/type reference, not a call site.]"
            }
            elseif ($spec.Inj -and -not $anyDyn -and $anyConst) {
                $r = if ($rank.ContainsKey("$($f.Severity)")) { [Math]::Max(0, $rank["$($f.Severity)"] - 1) } else { 1 }
                $f.Severity   = $byRank[$r]
                $f.Confidence = 'Likely-FP (IL)'
                $f.Description = "$($f.Description) [TCPK IL: called only with constant argument(s) across $total call site(s) -- no external input reaches the sink here; likely not injectable.]"
            }
            elseif ($spec.Inj -and $anyReach -and $anyDyn) {
                $f.Confidence = 'Confirmed (IL)'
                $f.Description = "$($f.Description) [TCPK IL: reachable call with non-constant argument(s) ($total call site(s)) -- external input may reach the sink; review the data flow.]"
            }
            else {
                $f.Description = "$($f.Description) [TCPK IL: API is actually invoked ($total call site(s), reachable=$anyReach).]"
            }
            $f
        }
    }
}
