function Invoke-TcpkLlmCodeJudgment {
<#
.SYNOPSIS
    L1 -- LLM skeptic-refute triage of code-construct LEAD findings.

.DESCRIPTION
    This is the agentic precision engine for the audit's LEADS. For each Inferred /
    Unverified code-construct finding (RuleId callsites.*, tls-bypass.*, deser.*, xxe.*,
    webview2.*) it:
      1. Extracts the flagged method's IL from the DLL (Mono.Cecil).
      2. Runs an ADVERSARIAL N-vote skeptic (Invoke-TcpkLlmSkepticVote): the model is
         asked to REFUTE the finding and defaults to 'not-real'. A MAJORITY of 'real'
         verdicts is required to promote; a model error, unparseable reply, or 'uncertain'
         is an abstain that can never create a 'real' majority (default-refuted-if-uncertain).
      3. Rewrites Confidence from the vote: a real majority -> 'Confirmed (LLM)' (moves the
         lead into PROVEN); a not-real majority -> 'Likely-FP (LLM)' (drops it out of the
         lead pile); anything unresolved -> left AS the lead it was.

    It triages LEADS ONLY. A finding that already carries a deterministic tier
    (Confirmed (IL) / Confirmed (dynamic) / Confirmed / Likely-FP (IL) / ...) passes
    through UNCHANGED -- a local model never overrides deterministic proof. The
    deterministic evidence stays intact in every case; the LLM accelerates triage, it is
    not the source of truth, and Severity is never changed.

    Requires a reachable LLM backend (Test-TcpkLlmAvailable) and the Mono.Cecil bridge
    (ships with ILSpy). Findings it can't process are returned unchanged.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects (e.g. from Invoke-TcpkAudit output or a
    findings.json re-loaded into objects).

.PARAMETER Votes
    Number of independent adversarial votes per lead (default 3). A majority
    (floor(Votes/2)+1) of 'real' verdicts is required to promote. The loop early-stops
    once either side locks a majority, so the typical cost is 2 calls per lead. Set 1 for
    a fast single-shot pass.

.OUTPUTS
    [TcpkFinding] -- same objects, with Confidence/Description updated where a lead was judged.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings,
        [int]$Votes = 3
    )

    begin {
        $all = New-Object 'System.Collections.Generic.List[object]'
        $codeRules = '^(callsites\.|tls-bypass\.|deser\.|xxe\.|webview2\.)'
        $leadConf  = @('Inferred', 'Unverified')   # skeptic triages LEADS only
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
You are a skeptical senior application-security reviewer performing an ADVERSARIAL second
pass over a static finding. A static scanner flagged the method below; scanners over-report.
Your job is to try to REFUTE the finding by reading the decompiled .NET CIL (IL) literally.
DEFAULT to 'not-real'. Answer 'real' ONLY if the IL clearly shows the weakness is genuinely
present. If the IL is short, ambiguous, or does not contain the dangerous construct, answer
'not-real' or 'uncertain' -- never 'real' on a guess.

Reason about the IL opcodes literally. Key opcodes:
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
5) XXE: real only if a DtdProcessing setter is fed the constant 2 (Parse) or a non-null
   XmlResolver is assigned; Prohibit(0)/Ignore(1)/null is not-real.

Reply with ONLY this JSON (no prose, no code fences):
{"verdict":"real|not-real|uncertain","confidence":"high|medium|low","reason":"one concise sentence grounded in the specific opcodes you saw"}
'@
    }

    process { foreach ($f in $Findings) { $all.Add($f) } }

    end {
        foreach ($f in $all) {
            # Pass through: LLM/Cecil unavailable, non-code-construct rule, non-lead (a
            # deterministic tier is never second-guessed by the model), or no readable DLL.
            if (-not $llmOk -or -not $cecilOk) { $f; continue }
            if ($f.RuleId -notmatch $codeRules) { $f; continue }
            if ("$($f.Confidence)" -notin $leadConf) { $f; continue }
            if (-not $f.File -or -not (Test-Path -LiteralPath $f.File)) { $f; continue }
            if ($f.File -notmatch '\.(dll|exe)$') { $f; continue }

            # Symbol hint (regex alternation) + optional signature match for the
            # robust TLS path. The cert-validation callback can have any name, so
            # we identify it by its delegate signature (X509Chain + SslPolicyErrors).
            $hint = $null; $sigMatch = $null; $callsApi = $null
            switch -Regex ($f.RuleId) {
                'tls-bypass|disabled-cert' {
                    $hint = 'CertificateValidation|CertValidation|ValidateCert|RemoteCertificate|ServerCertificate'
                    $sigMatch = @('X509Chain', 'SslPolicyErrors')
                }
                'deser'    { $hint = 'Deserialize|ReadObject|FromJson|FromXml' }
                'xxe'      { $hint = 'XmlReader|LoadXml|XmlDocument|XmlResolver|DtdProcessing' }
                'webview2' { $hint = 'WebMessageReceived|CoreWebView2|WebResource' }
                'callsites' {
                    # Generic callsite rules name the WEAKNESS, not a method, so a name
                    # match never lands -- locate the enclosing method by the sink API it
                    # INVOKES (the same shared sink map the deterministic verifier uses).
                    $suffix = ($f.RuleId -split '\.', 2)[-1]
                    $hint = $suffix
                    try { $callsApi = Get-TcpkCallsiteSinkApiRegex $suffix } catch {}
                }
                default    { $hint = ($f.RuleId -split '\.')[-1] }
            }

            $methods = $null
            try {
                if ($sigMatch) {
                    $methods = Get-TcpkMethodIl -DllPath $f.File -SymbolHint $hint -SignatureContains $sigMatch -MaxMethods 2
                } elseif ($callsApi) {
                    $methods = Get-TcpkMethodIl -DllPath $f.File -SymbolHint $hint -CallsApi $callsApi -MaxMethods 2
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
            $verd = $null
            try { $verd = Invoke-TcpkLlmSkepticVote -System $systemPrompt -User $userPrompt -Votes $Votes } catch {
                $f.Description = "$($f.Description) [LLM skeptic pass errored: $($_.Exception.Message)]"
                $f; continue
            }

            # Default-refuted-if-uncertain, and never override deterministic proof:
            #   real majority     -> promote to Confirmed (LLM)  (lead becomes PROVEN)
            #   not-real majority -> demote to Likely-FP (LLM)   (drops out of the lead pile)
            #   unresolved        -> leave the finding AS the lead it was (still needs triage)
            switch ($verd.Tier) {
                'Confirmed (LLM)' { $f.Confidence = 'Confirmed (LLM)' }
                'Likely-FP (LLM)' { $f.Confidence = 'Likely-FP (LLM)' }
                default           { }   # Uncertain: keep the original lead Confidence
            }
            $reasonTxt = if ($verd.Reasons.Count) { (($verd.Reasons | Select-Object -First 2) -join ' | ') } else { 'no parseable model reason' }
            $f.Description = "$($f.Description) [LLM skeptic: $($verd.Real) real / $($verd.NotReal) not-real / $($verd.Abstain) abstain of $($verd.Cast) votes (majority $($verd.Majority)) -> $($verd.Tier). $reasonTxt. Advisory only; deterministic evidence intact; severity unchanged.]"
            $f
        }
    }
}
