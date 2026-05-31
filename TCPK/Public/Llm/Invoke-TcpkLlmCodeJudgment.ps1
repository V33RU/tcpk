function Invoke-TcpkLlmCodeJudgment {
<#
.SYNOPSIS
    L1 -- LLM-assisted verification of code-construct findings.

.DESCRIPTION
    For findings whose RuleId implies a code weakness (callsites.*, tls-bypass.*,
    deser.*, xxe.*, webview2.*), this:
      1. Extracts the relevant method's IL from the flagged DLL (Mono.Cecil).
      2. Asks the LLM whether the code actually exhibits the weakness.
      3. Updates each finding's Confidence and appends the LLM's reasoning.

    LLM verdicts are labelled 'Inferred (LLM)' / 'Confirmed (LLM)' -- the
    deterministic evidence stays intact so a human can verify. The LLM
    accelerates triage; it is not the source of truth.

    Requires a reachable LLM backend (Test-TcpkLlm) and the Mono.Cecil bridge
    (ships with ILSpy). Findings it can't process are returned unchanged.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects (e.g. from Invoke-TcpkAudit output or
    a findings.json re-loaded into objects).

.OUTPUTS
    [TcpkFinding] -- same objects, with Confidence/Description updated where judged.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings)

    begin {
        $all = New-Object 'System.Collections.Generic.List[object]'
        $codeRules = '^(callsites\.|tls-bypass\.|deser\.|xxe\.|webview2\.)'
        $llmOk = $false
        try { $llmOk = Test-TcpkLlmAvailable } catch { $llmOk = $false }
        if (-not $llmOk) {
            Write-Warning "LLM backend not reachable -- code judgment skipped. Findings returned unchanged."
        }
        $cecilOk = Test-TcpkCecilAvailable
        if ($llmOk -and -not $cecilOk) {
            Write-Warning "Mono.Cecil (ILSpy) not found -- cannot extract IL. Findings returned unchanged."
        }
        $systemPrompt = @'
You are a senior application security analyst reading decompiled .NET CIL (IL).
Decide whether the flagged method ACTUALLY exhibits the weakness or is benign.

You MUST reason about the IL opcodes literally. Key opcodes:
- ldc.i4.1            push the integer constant 1 (true)
- ldc.i4.0            push the integer constant 0 (false)
- ldc.i4.s N / ldc.i4 N   push constant N
- ret                 return the value currently on the stack
- ceq                 pop two values, push 1 if equal else 0 (this is a COMPARISON, NOT a constant)
- ldarg.N             load argument N onto the stack
- call / callvirt     call a method (real validation usually CALLS something)
- brtrue/brfalse/bne  a branch = conditional logic = NOT an unconditional bypass

CRITICAL distinction for TLS / certificate callbacks (return type Boolean):
- REAL bypass:    body is exactly  "ldc.i4.1; ret"  (returns constant true, no checks)
- NOT a bypass:   body uses ceq / call / branches (e.g. "ldarg.3; ldc.i4.0; ceq; ret"
                  means "return errors == 0" i.e. SslPolicyErrors.None -- this is SAFE,
                  it returns the comparison result, it does NOT always return true)
- NOT a bypass:   compares a thumbprint, calls chain.Build, etc.

Worked examples:
1) IL "ldc.i4.1 / ret"                       -> {"verdict":"real","confidence":"high","reason":"returns constant true with no checks"}
2) IL "ldarg.3 / ldc.i4.0 / ceq / ret"       -> {"verdict":"not-real","confidence":"high","reason":"returns errors==None comparison, not a constant"}
3) IL with callvirt to X509Chain::Build      -> {"verdict":"not-real","confidence":"medium","reason":"performs real chain validation"}
4) deserialization: real only if untrusted input reaches a Deserialize with an unsafe
   resolver; a mere type reference is not-real.

If the IL is too short/ambiguous to decide, answer uncertain.

Reply with ONLY this JSON (no prose, no code fences):
{"verdict":"real|not-real|uncertain","confidence":"high|medium|low","reason":"one concise sentence grounded in the specific opcodes you saw"}
'@
    }

    process { foreach ($f in $Findings) { $all.Add($f) } }

    end {
        foreach ($f in $all) {
            # Pass through anything that isn't a code-construct finding, or if LLM/Cecil unavailable
            if (-not $llmOk -or -not $cecilOk) { $f; continue }
            if ($f.RuleId -notmatch $codeRules) { $f; continue }
            if (-not $f.File -or -not (Test-Path -LiteralPath $f.File)) { $f; continue }
            if ($f.File -notmatch '\.(dll|exe)$') { $f; continue }

            # Symbol hint (regex alternation) + optional signature match for the
            # robust TLS path. The cert-validation callback can have any name, so
            # we identify it by its delegate signature (X509Chain + SslPolicyErrors).
            $hint = $null; $sigMatch = $null
            switch -Regex ($f.RuleId) {
                'tls-bypass|disabled-cert' {
                    $hint = 'CertificateValidation|CertValidation|ValidateCert|RemoteCertificate|ServerCertificate'
                    $sigMatch = @('X509Chain','SslPolicyErrors')
                }
                'deser'    { $hint = 'Deserialize|ReadObject|FromJson|FromXml' }
                'xxe'      { $hint = 'XmlReader|LoadXml|XmlDocument|XmlResolver' }
                'webview2' { $hint = 'WebMessageReceived|CoreWebView2|WebResource' }
                'callsites'{ $hint = ($f.RuleId -split '\.')[-1] }
                default    { $hint = ($f.RuleId -split '\.')[-1] }
            }

            $methods = $null
            try {
                if ($sigMatch) {
                    $methods = Get-TcpkMethodIl -DllPath $f.File -SymbolHint $hint -SignatureContains $sigMatch -MaxMethods 2
                } else {
                    $methods = Get-TcpkMethodIl -DllPath $f.File -SymbolHint $hint -MaxMethods 2
                }
            } catch {}
            if (-not $methods) {
                $f.Description = "$($f.Description) [LLM: could not locate method IL for '$hint'; left as-is.]"
                $f; continue
            }

            $ilText = ($methods | ForEach-Object { $_.Il }) -join "`n---`n"
            $userPrompt = @"
Finding category: $($f.RuleId)
Finding title: $($f.Title)

Decompiled IL of the flagged method(s):
$ilText
"@
            $judged = $null
            try { $judged = Invoke-TcpkLlm -System $systemPrompt -User $userPrompt -AsJson } catch {
                $f.Description = "$($f.Description) [LLM call failed: $($_.Exception.Message)]"
                $f; continue
            }

            if ($judged -and $judged.verdict) {
                # Conservative policy: the LLM annotates Confidence and adds its
                # reasoning, but NEVER changes Severity. A local model can misread
                # IL (it does), so we do not auto-demote a real finding or auto-
                # promote a benign one off the model's say-so. The human triages
                # using the LLM note + the deterministic evidence that stays intact.
                switch ($judged.verdict) {
                    'real'      { $f.Confidence = 'Confirmed (LLM)' }
                    'not-real'  { $f.Confidence = 'Likely-FP (LLM)' }
                    default     { $f.Confidence = 'Uncertain (LLM)' }
                }
                $f.Description = "$($f.Description) [LLM verdict: $($judged.verdict) ($($judged.confidence)) -- $($judged.reason). NOTE: LLM advisory only; severity unchanged; verify against the evidence.]"
            } else {
                $f.Description = "$($f.Description) [LLM returned no parseable verdict.]"
            }
            $f
        }
    }
}
