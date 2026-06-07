function Confirm-TcpkCallsiteUsage {
<#
.SYNOPSIS
    Deterministic IL verification of callsites.* and deser.* findings: is the flagged
    API actually invoked, reachable, and fed by external input -- or a false positive?

.DESCRIPTION
    A substring scan (Test-TcpkCallsites / Test-TcpkDeserialization) proves a dangerous
    API NAME is present in a binary, not that it is a real bug. This pass reads the IL
    with Mono.Cecil and refines each finding's Confidence (never inventing findings):

      * API never actually called (call/newobj absent) -> 'Likely-FP (IL)', INFO
        -- the rule matched a string/type reference, not an invocation.
      * Injection-class sink called only with CONSTANT arguments -> 'Likely-FP (IL)',
        severity dropped one notch -- no external input reaches the sink here.
      * Injection-class sink REACHABLE and TAINTED (the enclosing method reads an
        external-input source -- file/registry/network/IPC/HTTP request -- or a caller
        parameter flows into the argument) -> 'Confirmed (IL)': external input reaches
        the sink. This is a bounded source->sink taint signal, not a full data-flow.
      * Injection-class sink reachable + non-constant but with NO proven external
        source -> left as-is with a "review the data flow" note (not over-claimed).
      * deser.* (unsafe formatter): Deserialize()/ReadObject() actually invoked ->
        'Confirmed (IL)' (stronger note if tainted); referenced-but-never-called ->
        'Likely-FP (IL)' / INFO.
      * Otherwise (usage/capability rule) -> left as-is with an "actually invoked"
        note; capability P/Invoke (keylogging, screen-capture, impersonation) that is
        merely DECLARED but never called is demoted to 'Likely-FP (IL)' / INFO.

    Conservative by design: the argument check only says 'constant' when NO dynamic
    source is found in the window, so a real bug is not demoted on a miss; and a
    'Confirmed (IL)' upgrade requires a proven taint source, not just a dynamic load.
    Both managed-BCL sinks and P/Invoke (native) sinks are matched. Requires the
    Mono.Cecil bridge (ships with ILSpy); without it, findings pass through.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.OUTPUTS
    [TcpkFinding] -- same objects, Confidence/Severity/Description refined where proven.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings)

    begin {
        $all = New-Object 'System.Collections.Generic.List[object]'

        # callsites.<suffix> -> the sink type(s)/method(s) to look for, and whether the
        # dangerous ARGUMENT carries external input (injection-class). Each sink is:
        #   T  = type fragment (managed BCL) OR, with Mo, a method-name fragment
        #   M  = method-name fragment (single token only -- it is regex-ESCAPED, so an
        #        alternation like 'A|B' would never match; split into two sinks instead)
        #   Mo = match by called METHOD name (any declaring type) -- for P/Invoke sinks
        #        (CreateProcess/WinExec/ShellExecute, SetWindowsHookEx, LogonUser, ...)
        $map = @{
            'command-execution'          = @{ Inj = $true;  Sinks = @(@{T='System.Diagnostics.Process'},@{T='System.Diagnostics.ProcessStartInfo'},@{T='CreateProcess';Mo=$true},@{T='WinExec';Mo=$true},@{T='ShellExecute';Mo=$true}) }
            'sql-command-construction'   = @{ Inj = $true;  Sinks = @(@{T='SqlCommand'},@{T='OleDbCommand'},@{T='OdbcCommand'},@{T='MySqlCommand'},@{T='NpgsqlCommand'},@{T='SqliteCommand'},@{T='SQLiteCommand'}) }
            'ssrf-request-build'         = @{ Inj = $true;  Sinks = @(@{T='System.Net.WebRequest'},@{T='System.Net.Http.HttpClient'},@{T='System.Net.WebClient'},@{T='System.Net.Http.HttpRequestMessage'},@{T='RestClient'}) }
            'nosql-command-construction' = @{ Inj = $true;  Sinks = @(@{T='MongoCollection'},@{T='IMongoCollection'},@{T='BsonJavaScript'},@{T='FilterDefinition'},@{T='LiteCollection'}) }
            'ldap-query'                 = @{ Inj = $true;  Sinks = @(@{T='DirectorySearcher'},@{T='DirectoryEntry'}) }
            'xaml-objectdataprovider-rce'= @{ Inj = $true;  Sinks = @(@{T='XamlReader'},@{T='XamlServices'},@{T='ObjectDataProvider'}) }
            'path-traversal-build'       = @{ Inj = $true;  Sinks = @(@{T='System.IO.Path';M='Combine'},@{T='System.IO.Path';M='GetFullPath'},@{T='ZipFile'}) }
            'weak-symmetric-crypto'      = @{ Inj = $false; Sinks = @(@{T='DESCryptoServiceProvider'},@{T='TripleDESCryptoServiceProvider'},@{T='RC2CryptoServiceProvider'},@{T='Cryptography.DES'},@{T='Cryptography.TripleDES'},@{T='Cryptography.RC2'}) }
            'weak-hash-md5-sha1'         = @{ Inj = $false; Sinks = @(@{T='Cryptography.MD5'},@{T='MD5CryptoServiceProvider'},@{T='SHA1Managed'},@{T='SHA1CryptoServiceProvider'},@{T='Cryptography.SHA1'}) }
            'weak-rng'                   = @{ Inj = $false; Sinks = @(@{T='System.Random'}) }
            'base64-as-encryption'       = @{ Inj = $false; Sinks = @(@{T='System.Convert';M='ToBase64String'},@{T='System.Convert';M='FromBase64String'}) }
            'env-var-path-use'           = @{ Inj = $false; Sinks = @(@{T='System.Environment';M='GetEnvironmentVariable'},@{T='System.Environment';M='ExpandEnvironmentStrings'}) }
            # capability rules (Inj=$false): invocation proof kills string/DllImport-only
            # FPs. A keyboard hook / screen grab / token impersonation that is declared
            # but never called is demoted to INFO; an actually-invoked one keeps its note.
            'input-capture'              = @{ Inj = $false; Sinks = @(@{T='SetWindowsHookEx';Mo=$true},@{T='GetAsyncKeyState';Mo=$true},@{T='GetKeyboardState';Mo=$true},@{T='keybd_event';Mo=$true},@{T='RegisterRawInputDevices';Mo=$true},@{T='BitBlt';Mo=$true},@{T='PrintWindow';Mo=$true},@{T='CopyFromScreen';Mo=$true}) }
            'token-impersonation'        = @{ Inj = $false; Sinks = @(@{T='LogonUser';Mo=$true},@{T='ImpersonateLoggedOnUser';Mo=$true},@{T='ImpersonateNamedPipeClient';Mo=$true},@{T='SetThreadToken';Mo=$true},@{T='DuplicateTokenEx';Mo=$true},@{T='WindowsIdentity';M='Impersonate'}) }
            'clipboard-access'           = @{ Inj = $false; Sinks = @(@{T='Clipboard'},@{T='OpenClipboard';Mo=$true},@{T='GetClipboardData';Mo=$true},@{T='SetClipboardData';Mo=$true}) }
        }
        # deser.<token> tokens that ARE a formatter type exposing Deserialize()/
        # ReadObject(). Tokens NOT here (e.g. 'typenamehandling', a Json.NET enum flag
        # whose real sink is JsonConvert.DeserializeObject) are left untouched -- the
        # type-fragment confirm cannot see them and must not demote them to FP.
        $deserTyped = @('binaryformatter','netdatacontractserializer','soapformatter',
                        'losformatter','objectstateformatter','javascriptserializer',
                        'xmlserializer','datacontractserializer')
        $rank = @{ 'CRITICAL'=4; 'HIGH'=3; 'MEDIUM'=2; 'LOW'=1; 'INFO'=0 }
        $byRank = @{ 4='CRITICAL'; 3='HIGH'; 2='MEDIUM'; 1='LOW'; 0='INFO' }

        $cecilOk = $false
        try { $cecilOk = Test-TcpkCecilAvailable } catch { $cecilOk = $false }
    }

    process { foreach ($f in $Findings) { $all.Add($f) } }

    end {
        foreach ($f in $all) {
            $rid = "$($f.RuleId)"
            $isCall  = $rid -like 'callsites.*'
            $isDeser = $rid -like 'deser.*'
            if (-not $cecilOk -or -not ($isCall -or $isDeser)) { $f; continue }
            if (-not $f.File -or ("$($f.File)" -notmatch '\.(dll|exe)$') -or -not (Test-Path -LiteralPath $f.File)) { $f; continue }
            $leaf = Split-Path $f.File -Leaf

            # ---- deser.* : confirm an unsafe-formatter Deserialize()/ReadObject() call ----
            if ($isDeser) {
                $token = ($rid -replace '^deser\.', '')
                if ($deserTyped -notcontains $token) { $f; continue }   # e.g. typenamehandling: leave untouched
                $dTotal = 0; $dReach = $false; $dTaint = $false
                foreach ($mn in @('Deserialize','ReadObject')) {
                    $u = $null
                    try { $u = Get-TcpkCallsiteUsage -DllPath $f.File -TypeFragment $token -MethodName $mn -Injection } catch { }
                    if (-not $u) { continue }
                    $dTotal += $u.CallSiteCount
                    if ($u.AnyReachable) { $dReach = $true }
                    if ($u.AnyTainted)   { $dTaint = $true }
                }
                if ($dTotal -eq 0) {
                    $f.Confidence = 'Likely-FP (IL)'
                    $f.Severity   = 'INFO'
                    $f.Description = "$($f.Description) [TCPK IL: the deserializer type is referenced but its Deserialize()/ReadObject() is never invoked in $leaf -- the rule matched a type/string reference, not a call.]"
                }
                elseif ($dTaint) {
                    $f.Confidence = 'Confirmed (IL)'
                    $f.Description = "$($f.Description) [TCPK IL: the deserializer's Deserialize()/ReadObject() is invoked ($dTotal call site(s)) and external input reaches it (the method reads a file/stream/network/IPC source or a caller parameter flows in) -- review this data-flow path.]"
                }
                else {
                    $f.Confidence = 'Confirmed (IL)'
                    $f.Description = "$($f.Description) [TCPK IL: the deserializer's Deserialize()/ReadObject() is actually invoked ($dTotal call site(s), reachable=$dReach) -- confirm whether the input can be attacker-controlled.]"
                }
                $f; continue
            }

            # ---- callsites.* : map the suffix to its sink type(s)/method(s) ----
            $suffix = ($rid -split '\.', 2)[-1]
            $spec = $map[$suffix]
            if (-not $spec) { $f; continue }

            $total = 0; $anyReach = $false; $anyDyn = $false; $anyConst = $false; $anyTaint = $false
            foreach ($sink in $spec.Sinks) {
                $u = $null
                $gp = @{ DllPath = $f.File; TypeFragment = $sink.T; Injection = [bool]$spec.Inj }
                if ($sink.M)  { $gp.MethodName = $sink.M }
                if ($sink.Mo) { $gp.MethodOnly = $true }
                try { $u = Get-TcpkCallsiteUsage @gp } catch { }
                if (-not $u) { continue }
                $total += $u.CallSiteCount
                if ($u.AnyReachable) { $anyReach = $true }
                if ($u.AnyDynamic)   { $anyDyn   = $true }
                if ($u.AnyTainted)   { $anyTaint = $true }
                if ($u.AllConstant)  { $anyConst = $true }
            }

            if ($total -eq 0) {
                $f.Confidence = 'Likely-FP (IL)'
                $f.Severity   = 'INFO'
                $f.Description = "$($f.Description) [TCPK IL: the flagged API is not actually invoked in $leaf (call/newobj absent) -- the rule matched a string/type reference, not a call site.]"
            }
            elseif ($spec.Inj -and $anyTaint) {
                # proven taint: an external-input source in the method, or a caller
                # parameter, flows into a reachable sink -> a real data-flow bug.
                $f.Confidence = 'Confirmed (IL)'
                $f.Description = "$($f.Description) [TCPK IL: reachable call where external input reaches the sink ($total call site(s)) -- the method reads an external source (file/registry/network/IPC/HTTP request) or a caller parameter flows into the argument. Treat as a real injectable path and review.]"
            }
            elseif ($spec.Inj -and -not $anyDyn -and $anyConst) {
                $r = if ($rank.ContainsKey("$($f.Severity)")) { [Math]::Max(0, $rank["$($f.Severity)"] - 1) } else { 1 }
                $f.Severity   = $byRank[$r]
                $f.Confidence = 'Likely-FP (IL)'
                $f.Description = "$($f.Description) [TCPK IL: called only with constant argument(s) across $total call site(s) -- no external input reaches the sink here; likely not injectable.]"
            }
            elseif ($spec.Inj -and $anyReach -and $anyDyn) {
                # reachable + non-constant, but no external-input SOURCE proven: do not
                # over-claim 'Confirmed'; leave Confidence as-is and flag for review.
                $f.Description = "$($f.Description) [TCPK IL: reachable call with a non-constant argument ($total call site(s)), but no external-input source was proven in the method -- possible injectable path; review the data flow.]"
            }
            else {
                $f.Description = "$($f.Description) [TCPK IL: API is actually invoked ($total call site(s), reachable=$anyReach).]"
            }
            $f
        }
    }
}
