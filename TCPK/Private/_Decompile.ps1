# Mono.Cecil bridge: extract IL / method bodies from .NET assemblies for the
# LLM code-judgment layer. Uses the Mono.Cecil that ships with the ILSpy install.
# Degrades gracefully (returns $null) if Cecil isn't available.

$script:TcpkCecilLoaded = $false

function Initialize-TcpkCecil {
    [CmdletBinding()] param()
    if ($script:TcpkCecilLoaded) { return $true }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\ILSpy\Mono.Cecil.dll",
        "$env:ProgramFiles\ILSpy\Mono.Cecil.dll",
        (Join-Path $script:TcpkRoot '..\tools\ILSpy\Mono.Cecil.dll')
    )
    $cecil = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $cecil) { return $false }
    try {
        Add-Type -Path $cecil -ErrorAction Stop
        $script:TcpkCecilLoaded = $true
        return $true
    } catch {
        # Already loaded in this session is fine
        if ([Mono.Cecil.AssemblyDefinition] -as [type]) { $script:TcpkCecilLoaded = $true; return $true }
        return $false
    }
}

function Test-TcpkCecilAvailable { Initialize-TcpkCecil }

# Find a method whose name (or a method that references a token) matches a needle,
# and return its disassembled IL as text. Returns $null if not found.
# $SymbolHint: the symbol the finding flagged (e.g. a property/method name).
function Get-TcpkMethodIl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$SymbolHint,
        [string[]]$SignatureContains,   # type-name fragments that must ALL appear in param types
        [int]$MaxMethods = 3
    )
    if (-not (Initialize-TcpkCecil)) { return $null }
    if (-not (Test-Path -LiteralPath $DllPath)) { return $null }

    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath) } catch { return $null }

    $results = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                $isMatch = $false

                # 1) Match by method name (SymbolHint treated as a regex alternation, case-insensitive)
                if ($m.Name -match "(?i)$SymbolHint") { $isMatch = $true }

                # 2) Match by signature: a method whose parameter types contain ALL the
                #    given fragments (e.g. X509Chain + SslPolicyErrors = a cert callback,
                #    regardless of its name). This is the robust path for TLS findings.
                if (-not $isMatch -and $SignatureContains) {
                    $paramTypes = ($m.Parameters | ForEach-Object { $_.ParameterType.FullName }) -join ' '
                    $allPresent = $true
                    foreach ($frag in $SignatureContains) {
                        if ($paramTypes -notmatch [regex]::Escape($frag)) { $allPresent = $false; break }
                    }
                    if ($allPresent) { $isMatch = $true }
                }

                # 3) Or by an operand referencing the symbol (e.g. set_X callback assignment)
                if (-not $isMatch) {
                    foreach ($ins in $m.Body.Instructions) {
                        if ($null -ne $ins.Operand -and ($ins.Operand.ToString() -match "(?i)$SymbolHint")) {
                            $isMatch = $true; break
                        }
                    }
                }
                if (-not $isMatch) { continue }

                # Prefer SMALL methods for the signature path -- the actual callback
                # lambda is tiny; skip giant async state machines that merely reference it.
                if ($SignatureContains -and $m.Body.Instructions.Count -gt 40 -and $m.Name -notmatch "(?i)$SymbolHint") { continue }

                $sb = New-Object Text.StringBuilder
                [void]$sb.AppendLine("// $($t.FullName)::$($m.Name)")
                [void]$sb.AppendLine("// returns $($m.ReturnType.Name), $($m.Body.Instructions.Count) IL instructions")
                foreach ($ins in $m.Body.Instructions) {
                    $op = $ins.OpCode.Name
                    $arg = if ($null -ne $ins.Operand) { " $($ins.Operand)" } else { '' }
                    [void]$sb.AppendLine(("  {0,-12}{1}" -f $op, $arg))
                    if ($sb.Length -gt 6000) { [void]$sb.AppendLine('  ... (truncated)'); break }
                }
                $results.Add([pscustomobject]@{
                    Type = $t.FullName; Method = $m.Name; Il = $sb.ToString()
                })
                if ($results.Count -ge $MaxMethods) { break }
            }
            if ($results.Count -ge $MaxMethods) { break }
        }
    } finally {
        $asm.Dispose()
    }
    if ($results.Count -eq 0) { return $null }
    return $results
}

# Locate the TLS certificate-validation callback by signature (a method whose
# parameters include SslPolicyErrors -- the RemoteCertificateValidationCallback /
# ServerCertificateCustomValidationCallback shape), regardless of its compiler-
# generated name. Returns the IL via Get-TcpkMethodIl, or $null.
function Get-TcpkCertCallbackIl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DllPath)
    Get-TcpkMethodIl -DllPath $DllPath `
        -SymbolHint 'Validate|Validation|Callback|RemoteCertificate|ServerCertificate' `
        -SignatureContains @('SslPolicyErrors')
}

# Conditional-branch and comparison opcodes (Mono.Cecil OpCode.Name values,
# lowercase, including the short '.s' forms). Presence of any of these means the
# method makes a runtime decision, so it is NOT an unconditional bypass.
$script:TcpkIlConditionalOps = @(
    'brfalse','brfalse.s','brtrue','brtrue.s',
    'beq','beq.s','bge','bge.s','bge.un','bge.un.s',
    'bgt','bgt.s','bgt.un','bgt.un.s','ble','ble.s','ble.un','ble.un.s',
    'blt','blt.s','blt.un','blt.un.s','bne.un','bne.un.s','switch'
)
$script:TcpkIlCompareOps = @('ceq','cgt','cgt.un','clt','clt.un')

# Deterministic Phase-2 verdict on a cert-validation callback's IL.
# Input is the IL text produced by Get-TcpkMethodIl (header lines prefixed with
# //, one instruction per line). Renders 'unconditional-true' ONLY when the body
# provably cannot return false: returns Boolean, loads constant 1 (true), returns,
# and contains no conditional branch and no comparison opcode. Never throws.
#
# This is the bytecode proof that turns a tls-bypass.* / callsites.* finding from
# Inferred to Confirmed: e.g. `(sender,cert,chain,errors) => true` compiles to
# `ldc.i4.1 ; ret`, which provably accepts every certificate.
function Test-TcpkIlReturnsTrueUnconditionally {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Il)

    $isBool    = $false
    $hasRet    = $false
    $hasOne    = $false
    $hasZero   = $false
    $branchOp  = $null
    $compareOp = $null
    $ops       = New-Object System.Collections.Generic.List[string]

    foreach ($raw in ($Il -split "`r?`n")) {
        $line = $raw.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('//')) {
            if ($line -match 'returns\s+Boolean\b') { $isBool = $true }
            continue
        }
        $tok = $line -split '\s+', 2
        $op  = $tok[0].ToLowerInvariant()
        $arg = if ($tok.Count -gt 1) { $tok[1].Trim() } else { '' }
        if ($op -eq 'nop') { continue }
        $ops.Add($op)

        switch ($op) {
            'ret'      { $hasRet  = $true; continue }
            'ldc.i4.1' { $hasOne  = $true; continue }
            'ldc.i4.0' { $hasZero = $true; continue }
            { $_ -eq 'ldc.i4' -or $_ -eq 'ldc.i4.s' } {
                if ($arg -match '^-?\d+') {
                    $n = [int]$matches[0]
                    if     ($n -eq 1) { $hasOne  = $true }
                    elseif ($n -eq 0) { $hasZero = $true }
                }
                continue
            }
        }
        if (-not $branchOp  -and $script:TcpkIlConditionalOps -contains $op) { $branchOp  = $op }
        if (-not $compareOp -and $script:TcpkIlCompareOps     -contains $op) { $compareOp = $op }
    }

    $verdict = 'inconclusive'
    $reason  = 'could not prove the return value from the IL.'
    if (-not $isBool) {
        $verdict = 'not-bool'
        $reason  = 'method does not return Boolean; not a cert-validation callback shape this prover handles.'
    }
    elseif ($branchOp) {
        $verdict = 'conditional'
        $reason  = "contains conditional branch '$branchOp'; validation is customized, not an unconditional bypass."
    }
    elseif ($compareOp) {
        $verdict = 'conditional'
        $reason  = "contains comparison '$compareOp'; the result depends on a runtime check, not an unconditional true."
    }
    elseif ($hasZero) {
        $verdict = 'returns-false-possible'
        $reason  = 'loads constant 0 (false) on some path; cannot prove it always returns true.'
    }
    elseif ($hasOne -and $hasRet) {
        $verdict = 'unconditional-true'
        $reason  = 'body loads constant 1 (true) and returns, with no conditional branch or comparison: the callback accepts every certificate unconditionally.'
    }

    [pscustomobject]@{
        Verdict    = $verdict
        Reason     = $reason
        IsBool     = $isBool
        HasReturn  = $hasRet
        LoadsTrue  = $hasOne
        LoadsFalse = $hasZero
        BranchOp   = $branchOp
        CompareOp  = $compareOp
        Opcodes    = ($ops -join ' ')
    }
}

# Scan every method body in an assembly for a call / callvirt / newobj instruction
# whose target references $TypeFragment (matched, case-insensitively, against the
# target method's declaring-type full name) and, optionally, $MethodName. This is
# the deterministic Phase-2 proof that a dangerous API is actually INVOKED, not
# merely present as a string in the binary (which is all a substring scan shows).
# Returns a list of @{ Type; Method; Op; Target } call sites, or $null.
function Get-TcpkCallSites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$TypeFragment,
        [string]$MethodName,
        [int]$Max = 20
    )
    if (-not (Initialize-TcpkCecil)) { return $null }
    if (-not (Test-Path -LiteralPath $DllPath)) { return $null }

    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath) } catch { return $null }

    $callOps  = @('call','callvirt','newobj')
    $typeRx   = "(?i)$([regex]::Escape($TypeFragment))"
    $methodRx = if ($MethodName) { "(?i)$([regex]::Escape($MethodName))" } else { $null }
    $results  = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                foreach ($ins in $m.Body.Instructions) {
                    if ($callOps -notcontains $ins.OpCode.Name) { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    $declType = $mref.DeclaringType.FullName
                    if ($declType -notmatch $typeRx) { continue }
                    if ($methodRx -and ($mref.Name -notmatch $methodRx)) { continue }
                    $results.Add([pscustomobject]@{
                        Type   = $t.FullName
                        Method = $m.Name
                        Op     = $ins.OpCode.Name
                        Target = "$declType::$($mref.Name)"
                    })
                    if ($results.Count -ge $Max) { break }
                }
                if ($results.Count -ge $Max) { break }
            }
            if ($results.Count -ge $Max) { break }
        }
    } finally {
        if ($asm) { $asm.Dispose() }
    }
    if ($results.Count -eq 0) { return $null }
    return $results
}

# Deterministic, shape-based TLS certificate-validation-bypass detector. Scans every
# method of an assembly for the REAL callback shape - a method that returns Boolean AND
# has a System.Net.Security.SslPolicyErrors parameter (the RemoteCertificate/
# ServerCertificateCustomValidationCallback delegate signature) - builds its IL and runs
# Test-TcpkIlReturnsTrueUnconditionally. Also flags the BCL accept-all validator
# (HttpClientHandler.DangerousAcceptAnyServerCertificateValidator). Finds the callback
# wherever it lives (incl. sibling assemblies / compiler lambdas), which name-only
# heuristics miss. Returns @() if Cecil is unavailable.
#
# Each result is a rich location record so the analyst can jump straight to it in
# ILSpy / dnSpy (no guessing which assembly, no searching for un-typeable lambda names):
#   File       - the assembly file the callback actually lives in
#   Assembly   - module name
#   Namespace  - declaring namespace (or '(global namespace)')
#   Type       - declaring type full name (incl. nested '/' for display classes)
#   Method     - method name (may be a compiler lambda like '<Connect>b__5_0')
#   Signature  - readable signature: 'Boolean Name(Object, X509Chain, SslPolicyErrors)'
#   Token      - metadata token, e.g. 0x06000123 (dnSpy: Ctrl+D, paste to navigate)
#   Enclosing  - for a lambda, the user-written method it was declared in (searchable)
#   Kind       - 'unconditional-true' or 'dangerous-accept'
#   Reason     - the IL-proof explanation
#   Il         - the disassembled method body (the proof)
#   AssignedAt - list of 'Type::Method' sites that wire the callback up (ldftn/newobj)
function Get-TcpkTlsCallbackVerdicts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DllPath)
    if (-not (Initialize-TcpkCecil)) { return @() }
    if (-not (Test-Path -LiteralPath $DllPath)) { return @() }
    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath) } catch { return @() }

    $fileName = Split-Path -Leaf $DllPath
    $hits = New-Object 'System.Collections.Generic.List[object]'   # interim: holds Cecil refs

    try {
        # Flatten all methods once (reused for the assignment-site pass below).
        $allMethods = New-Object 'System.Collections.Generic.List[object]'
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) { $allMethods.Add([pscustomobject]@{ T = $t; M = $m }) }
        }

        foreach ($pair in $allMethods) {
            $t = $pair.T; $m = $pair.M
            if (-not $m.HasBody) { continue }

            # (1) BCL accept-all validator assigned anywhere in the body
            $dangerous = $false
            foreach ($ins in $m.Body.Instructions) {
                if ("$($ins.Operand)" -match 'DangerousAcceptAnyServerCertificateValidator') { $dangerous = $true; break }
            }
            if ($dangerous) {
                $hits.Add([pscustomobject]@{ Def = $m; Type = $t; Kind = 'dangerous-accept'
                    Reason = 'assigns HttpClientHandler.DangerousAcceptAnyServerCertificateValidator (accepts every server certificate).'
                    Il = $null })
            }

            # (2) real callback shape: returns Boolean AND takes an SslPolicyErrors arg
            $hasSpe = $false
            foreach ($p in $m.Parameters) { if ("$($p.ParameterType.FullName)" -match 'SslPolicyErrors') { $hasSpe = $true; break } }
            if ("$($m.ReturnType.FullName)" -eq 'System.Boolean' -and $hasSpe) {
                $lines  = New-Object 'System.Collections.Generic.List[string]'
                $ilBody = New-Object 'System.Collections.Generic.List[string]'
                $lines.Add("// $($t.FullName)::$($m.Name)")
                $lines.Add("// returns $($m.ReturnType.Name)")
                foreach ($ins in $m.Body.Instructions) {
                    $txt = ("{0} {1}" -f $ins.OpCode.Name, "$($ins.Operand)").TrimEnd()
                    $lines.Add($txt); $ilBody.Add($txt)
                }
                $verdict = Test-TcpkIlReturnsTrueUnconditionally -Il ($lines -join "`n")
                if ($verdict.Verdict -eq 'unconditional-true') {
                    $hits.Add([pscustomobject]@{ Def = $m; Type = $t; Kind = 'unconditional-true'
                        Reason = $verdict.Reason; Il = ($ilBody -join "`n") })
                }
            }
        }

        # Assignment-site pass: find where each flagged callback is wired up (loaded as a
        # function pointer / passed to a delegate ctor / assigned via a set_ accessor).
        # This is the line of code the analyst is usually hunting for.
        $assignMap = @{}
        foreach ($h in $hits) { $assignMap[$h.Def.FullName] = (New-Object 'System.Collections.Generic.List[string]') }
        if ($assignMap.Count -gt 0) {
            $refOps = @('ldftn','ldvirtftn','newobj','call','callvirt')
            foreach ($pair in $allMethods) {
                $cm = $pair.M
                if (-not $cm.HasBody) { continue }
                foreach ($ins in $cm.Body.Instructions) {
                    if ($refOps -notcontains $ins.OpCode.Name) { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    if ($assignMap.ContainsKey($mref.FullName)) {
                        $site = "$($pair.T.FullName)::$($cm.Name)"
                        if (-not $assignMap[$mref.FullName].Contains($site)) { $assignMap[$mref.FullName].Add($site) }
                    }
                }
            }
        }

        # Materialize to plain strings (safe to use after Dispose).
        $out = New-Object 'System.Collections.Generic.List[object]'
        foreach ($h in $hits) {
            $m = $h.Def; $t = $h.Type
            $ns  = if ($t.Namespace) { $t.Namespace } else { '(global namespace)' }
            $ps  = ($m.Parameters | ForEach-Object { $_.ParameterType.Name }) -join ', '
            $sig = "$($m.ReturnType.Name) $($m.Name)($ps)"
            $tok = '0x{0:X8}' -f $m.MetadataToken.ToInt32()
            $enclosing = if ($m.Name -match '^<([^>]+)>') { $matches[1] } else { $null }
            $assigned = if ($assignMap.ContainsKey($m.FullName)) { $assignMap[$m.FullName].ToArray() } else { @() }
            $out.Add([pscustomobject]@{
                File       = $fileName
                Assembly   = $asm.MainModule.Name
                Namespace  = $ns
                Type       = $t.FullName
                Method     = $m.Name
                Signature  = $sig
                Token      = $tok
                Enclosing  = $enclosing
                Kind       = $h.Kind
                Reason     = $h.Reason
                Il         = $h.Il
                AssignedAt = $assigned
            })
        }
        return $out.ToArray()
    } finally {
        if ($asm) { $asm.Dispose() }
    }
}
