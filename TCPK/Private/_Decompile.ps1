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

# --- per-run assembly cache ---------------------------------------------------
# Verification calls Get-TcpkCallsiteUsage once PER SINK, so a single DLL with a
# multi-sink rule (e.g. command-execution: Process/ProcessStartInfo/CreateProcess/
# WinExec/ShellExecute) was re-parsed 5x. Cache the parsed AssemblyDefinition per
# path so it is read once; Clear-TcpkCecilCache disposes them at the audit boundary.
$script:TcpkCecilAsmCache = @{}

function Get-TcpkCecilAssembly {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$DllPath)
    if (-not (Initialize-TcpkCecil)) { return $null }
    if (-not (Test-Path -LiteralPath $DllPath)) { return $null }
    $key = $DllPath
    try { $key = (Resolve-Path -LiteralPath $DllPath -ErrorAction Stop).Path } catch { }
    if ($script:TcpkCecilAsmCache.ContainsKey($key)) { return $script:TcpkCecilAsmCache[$key] }
    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($key) } catch { $asm = $null }
    if ($asm) { $script:TcpkCecilAsmCache[$key] = $asm }
    return $asm
}

# Per-run caches of the interprocedural taint sets (tainted-returning methods and
# tainted fields), keyed by the same resolved path as the assembly cache (each computed
# once, reused across every sink).
$script:TcpkTaintedReturningCache = @{}
$script:TcpkTaintedFieldCache = @{}

# Dispose every cached assembly and reset. Called at the audit boundary so file
# handles are released and a fresh run never reuses a stale parse.
function Clear-TcpkCecilCache {
    foreach ($a in @($script:TcpkCecilAsmCache.Values)) { try { if ($a) { $a.Dispose() } } catch { } }
    $script:TcpkCecilAsmCache = @{}
    $script:TcpkTaintedReturningCache = @{}
    $script:TcpkTaintedFieldCache = @{}
}

# Find a method whose name (or a method that references a token) matches a needle,
# and return its disassembled IL as text. Returns $null if not found.
# $SymbolHint: the symbol the finding flagged (e.g. a property/method name).
function Get-TcpkMethodIl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$SymbolHint,
        [string[]]$SignatureContains,   # type-name fragments that must ALL appear in param types
        [string]$CallsApi,              # regex on a CALL target (DeclaringType::Name) -- locate a method by the sink it INVOKES
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

                # 4) Or by a CALL to a sink API (the method INVOKES the dangerous API) --
                #    the robust path for generic callsites.* findings whose own method name
                #    says nothing (e.g. command-execution: find the method that calls
                #    Process::Start). Matches only call/callvirt/newobj TARGETS, so it is
                #    precise -- not any operand text.
                if (-not $isMatch -and $CallsApi) {
                    foreach ($ins in $m.Body.Instructions) {
                        if ($ins.OpCode.Name -notin 'call','callvirt','newobj') { continue }
                        $cr = $ins.Operand -as [Mono.Cecil.MethodReference]
                        if ($cr -and ("$($cr.DeclaringType.FullName)::$($cr.Name)" -match $CallsApi)) { $isMatch = $true; break }
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

# Return the Int32 a constant-int load (ldc.i4*) pushes, or $null if the instruction is
# not a constant int. Handles the packed forms (ldc.i4.0..8, ldc.i4.m1) and the operand
# forms (ldc.i4, ldc.i4.s). Used to read the concrete enum/bool argument fed to a setter.
function Get-TcpkIlI4Value {
    param($Ins)
    if ($null -eq $Ins) { return $null }
    switch ($Ins.OpCode.Name) {
        'ldc.i4.0'  { return 0 }
        'ldc.i4.1'  { return 1 }
        'ldc.i4.2'  { return 2 }
        'ldc.i4.3'  { return 3 }
        'ldc.i4.4'  { return 4 }
        'ldc.i4.5'  { return 5 }
        'ldc.i4.6'  { return 6 }
        'ldc.i4.7'  { return 7 }
        'ldc.i4.8'  { return 8 }
        'ldc.i4.m1' { return -1 }
        'ldc.i4'    { try { return [int]$Ins.Operand } catch { return $null } }
        'ldc.i4.s'  { try { return [int]$Ins.Operand } catch { return $null } }
        default     { return $null }
    }
}

# Deterministic XXE detection from IL. A text scan sees the setter/type NAME but not the
# argument VALUE, so it cannot tell DtdProcessing.Parse (unsafe) from Prohibit/Ignore
# (safe), nor a real XmlResolver from the null-resolver mitigation. This reads the constant
# fed to each dangerous System.Xml setter and only reports a PROVEN-unsafe construct:
#   set_DtdProcessing(2 = Parse)   set_ProhibitDtd(0 = false)   set_XmlResolver(newobj resolver)
# The value argument of a 1-arg instance setter is the value-producing instruction right
# before the call (this is pushed first, the argument last), skipping nop. Returns one
# verdict per proven construct, materialized to plain strings so results survive Dispose.
function Get-TcpkXxeVerdicts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DllPath)
    if (-not (Initialize-TcpkCecil)) { return @() }
    if (-not (Test-Path -LiteralPath $DllPath)) { return @() }
    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath) } catch { return @() }

    $fileName = Split-Path -Leaf $DllPath
    $hits = New-Object 'System.Collections.Generic.List[object]'   # interim: holds Cecil refs

    try {
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                foreach ($ins in $m.Body.Instructions) {
                    $opn = $ins.OpCode.Name
                    if ($opn -ne 'call' -and $opn -ne 'callvirt') { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    $sink = $mref.Name
                    if ($sink -ne 'set_DtdProcessing' -and $sink -ne 'set_XmlResolver' -and $sink -ne 'set_ProhibitDtd') { continue }
                    $declFull = "$($mref.DeclaringType.FullName)"
                    if ($declFull -notmatch '^System\.Xml\.') { continue }

                    # Value argument = value-producing instruction immediately before the call.
                    $arg = $ins.Previous
                    while ($arg -and $arg.OpCode.Name -eq 'nop') { $arg = $arg.Previous }
                    if ($null -eq $arg) { continue }

                    $kind = $null; $reason = $null
                    if ($sink -eq 'set_DtdProcessing') {
                        # DtdProcessing enum: Prohibit=0, Ignore=1, Parse=2. Only Parse is unsafe.
                        if ((Get-TcpkIlI4Value $arg) -eq 2) {
                            $kind = 'dtd-processing-parse'
                            $reason = "$declFull.DtdProcessing is set to Parse (ldc.i4.2): DTD processing is enabled."
                        }
                    } elseif ($sink -eq 'set_ProhibitDtd') {
                        # Legacy XmlReaderSettings/XmlTextReader.ProhibitDtd: false (0) allows DTDs.
                        if ((Get-TcpkIlI4Value $arg) -eq 0) {
                            $kind = 'prohibitdtd-false'
                            $reason = "$declFull.ProhibitDtd is set to false (ldc.i4.0): DTD processing is enabled."
                        }
                    } elseif ($sink -eq 'set_XmlResolver') {
                        # A non-null resolver enables external entity fetch. Setting it to null
                        # (ldnull) is the mitigation, not a finding. XmlSecureResolver is also a
                        # mitigation wrapper, so exclude it.
                        if ($arg.OpCode.Name -eq 'newobj') {
                            $ctor = $arg.Operand -as [Mono.Cecil.MethodReference]
                            $rt = if ($ctor) { "$($ctor.DeclaringType.FullName)" } else { '' }
                            if ($rt -match '(XmlUrlResolver|XmlPreloadedResolver)' -or ($rt -match 'XmlResolver' -and $rt -notmatch 'XmlSecureResolver')) {
                                $kind = 'external-xml-resolver'
                                $reason = "$declFull.XmlResolver is assigned a non-null $($ctor.DeclaringType.Name): external entity resolution is enabled."
                            }
                        }
                    }
                    if (-not $kind) { continue }

                    # IL proof snippet: up to 4 instructions ending at the sink call.
                    $back = New-Object 'System.Collections.Generic.List[object]'
                    $p = $ins; $c = 0
                    while ($p -and $c -lt 4) { $back.Insert(0, $p); $p = $p.Previous; $c++ }
                    $snip = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($bi in $back) {
                        $bo = if ($null -ne $bi.Operand) { " $($bi.Operand)" } else { '' }
                        $snip.Add(("  {0,-12}{1}" -f $bi.OpCode.Name, $bo))
                    }
                    $hits.Add([pscustomobject]@{ Type = $t; Method = $m; Kind = $kind; Reason = $reason; Il = ($snip -join "`n") })
                }
            }
        }

        # Per-method escalation: a single method that BOTH enables DTD and assigns a non-null
        # resolver has a full external-entity read primitive (file disclosure / SSRF) on the
        # same parser -> CRITICAL. Either alone is HIGH. Keyed per method, not per type, so a
        # DTD-enabling method and a separate resolver-setting method do not cross-escalate.
        $methFlags = @{}
        foreach ($h in $hits) {
            $mk = "$($h.Type.FullName)::$($h.Method.Name)"
            if (-not $methFlags.ContainsKey($mk)) { $methFlags[$mk] = [pscustomobject]@{ Dtd = $false; Resolver = $false } }
            if ($h.Kind -eq 'dtd-processing-parse' -or $h.Kind -eq 'prohibitdtd-false') { $methFlags[$mk].Dtd = $true }
            if ($h.Kind -eq 'external-xml-resolver') { $methFlags[$mk].Resolver = $true }
        }

        # Materialize to plain strings (safe after Dispose).
        $out = New-Object 'System.Collections.Generic.List[object]'
        foreach ($h in $hits) {
            $t = $h.Type; $m = $h.Method
            $mk = "$($t.FullName)::$($m.Name)"
            $sev = if ($methFlags[$mk].Dtd -and $methFlags[$mk].Resolver) { 'CRITICAL' } else { 'HIGH' }
            $ns  = if ($t.Namespace) { $t.Namespace } else { '(global namespace)' }
            $tok = '0x{0:X8}' -f $m.MetadataToken.ToInt32()
            $out.Add([pscustomobject]@{
                File      = $fileName
                Assembly  = $asm.MainModule.Name
                Namespace = $ns
                Type      = $t.FullName
                Method    = $m.Name
                Token     = $tok
                Kind      = $h.Kind
                Reason    = $h.Reason
                Severity  = $sev
                Il        = $h.Il
            })
        }
        return $out.ToArray()
    } finally {
        if ($asm) { $asm.Dispose() }
    }
}

# Constant vs dynamic IL load opcodes (for the argument-source heuristic below).
$script:TcpkIlConstLoads = @(
    'ldstr','ldnull','ldc.i4','ldc.i4.s','ldc.i4.m1',
    'ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8',
    'ldc.i8','ldc.r4','ldc.r8'
)
$script:TcpkIlDynLoads = @(
    'ldarg.0','ldarg.1','ldarg.2','ldarg.3','ldarg','ldarg.s','ldarga','ldarga.s',
    'ldloc.0','ldloc.1','ldloc.2','ldloc.3','ldloc','ldloc.s','ldloca','ldloca.s',
    'ldfld','ldflda','ldsfld','ldsflda','ldelem','ldelem.ref','ldelema','ldobj','call','callvirt'
)

# External-INPUT source APIs (matched against a call target's "DeclaringType::Method").
# A bounded taint signal: if the method that feeds a dangerous sink also pulls data
# from one of these (file/console/env/registry/network/IPC/HTTP-request), the dynamic
# argument is treated as potentially attacker-influenced ('tainted'), not just internal.
$script:TcpkIlSourceApiRx = '(?i)(System\.IO\.File::(Read|Open)|StreamReader::(ReadToEnd|ReadLine|Read)|ReadAllText|ReadAllBytes|ReadAllLines|Console::(ReadLine|Read|get_In)|Environment::(GetEnvironmentVariable|ExpandEnvironmentStrings|GetCommandLineArgs)|Microsoft\.Win32\.Registry|RegistryKey::(GetValue|OpenSubKey)|WebClient::(DownloadString|DownloadData|OpenRead)|HttpClient::(GetString|GetByteArray|GetStream|Get|Send|PostAsync)|ReadAsStringAsync|ReadAsByteArrayAsync|ReadAsStream|NamedPipe|PipeStream::Read|Socket::(Receive|Read)|SqlDataReader|HttpRequest(Base)?::(get_Form|get_QueryString|get_Params|get_Item|get_InputStream)|::get_QueryString|HttpListenerRequest|FileDialog::get_FileName|Clipboard::(GetText|GetData|GetImage|GetFileDropList|GetContent)|DataObject::GetData|DragEventArgs::get_Data|::(Deserialize|DeserializeObject|ReadObject))'

# --- interprocedural taint helpers -------------------------------------------
# Resolve the local-variable slot index an ldloc/stloc opcode refers to (-1 if the
# instruction is not a local load/store). Handles both the packed forms (ldloc.0..3)
# and the operand forms (ldloc / ldloc.s -> VariableDefinition.Index).
function Get-TcpkIlLocalIndex {
    param($Ins)
    switch ($Ins.OpCode.Name) {
        'ldloc.0' { return 0 } 'ldloc.1' { return 1 } 'ldloc.2' { return 2 } 'ldloc.3' { return 3 }
        'stloc.0' { return 0 } 'stloc.1' { return 1 } 'stloc.2' { return 2 } 'stloc.3' { return 3 }
    }
    if ($Ins.OpCode.Name -in 'ldloc','ldloc.s','stloc','stloc.s') {
        $v = $Ins.Operand -as [Mono.Cecil.Cil.VariableDefinition]
        if ($v) { return $v.Index }
    }
    return -1
}

# Build (cached per assembly) the set of "tainted-returning" methods: value-returning
# methods whose body transitively reaches an external-input source API. This is the
# interprocedural backbone -- it lets a sink fed by the RESULT of another method
# (var x = ReadConfig(); Process.Start(x)) be recognised as tainted even though the
# source read lives in a different method. Bounded to a 3-pass fixpoint over the call
# graph so it always terminates quickly even on pathological recursion.
function Get-TcpkTaintedReturningMethods {
    [CmdletBinding()] param([Parameter(Mandatory)]$Asm, [Parameter(Mandatory)][string]$Key)
    # ,return the set (comma-wrap) so PowerShell does NOT unroll the HashSet to its elements
    if ($script:TcpkTaintedReturningCache.ContainsKey($Key)) { return ,$script:TcpkTaintedReturningCache[$Key] }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $callOps = @('call','callvirt','newobj')
    $valueMethods = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($t in $Asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                $rt = ''; try { $rt = "$($m.ReturnType.FullName)" } catch { }
                if ($rt -eq 'System.Void' -or $rt -eq '') { continue }  # only value-returning methods carry taint OUT
                $direct = $false
                $calls = New-Object 'System.Collections.Generic.List[string]'
                foreach ($ins in $m.Body.Instructions) {
                    if ($callOps -notcontains $ins.OpCode.Name) { continue }
                    $r = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if (-not $r) { continue }
                    if ("$($r.DeclaringType.FullName)::$($r.Name)" -match $script:TcpkIlSourceApiRx) { $direct = $true }
                    $calls.Add("$($r.FullName)")
                }
                if ($direct) { [void]$set.Add("$($m.FullName)") }
                $valueMethods.Add([pscustomobject]@{ Full = "$($m.FullName)"; Calls = $calls })
            }
        }
        # Transitive closure: a value-returning method that calls a tainted-returning
        # method is itself tainted-returning. Fixpoint capped at 3 passes.
        for ($pass = 0; $pass -lt 3; $pass++) {
            $changed = $false
            foreach ($vm in $valueMethods) {
                if ($set.Contains($vm.Full)) { continue }
                foreach ($c in $vm.Calls) { if ($set.Contains($c)) { [void]$set.Add($vm.Full); $changed = $true; break } }
            }
            if (-not $changed) { break }
        }
    } catch { }
    $script:TcpkTaintedReturningCache[$Key] = $set
    return ,$set
}

# Forward intra-method dataflow: which local slots end up holding external-input-
# derived ("tainted") values. A local is tainted when assigned directly from (a) a
# source-API or tainted-returning call, (b) a caller parameter in a reachable method,
# or (c) another already-tainted local. Iterated to a 3-pass fixpoint so assignment
# order does not matter. Deliberately PRECISE (direct assignment only) to avoid
# re-introducing false positives -- it completes the interprocedural signal so a
# cross-method source can reach a sink through an intermediate local.
function Get-TcpkMethodTaintedLocals {
    [CmdletBinding()] param([Parameter(Mandatory)]$Instrs, [bool]$Reachable, $TaintedReturning, $TaintedFields)
    $tl = New-Object 'System.Collections.Generic.HashSet[int]'
    if ($null -eq $TaintedReturning) { $TaintedReturning = New-Object 'System.Collections.Generic.HashSet[string]' }
    if ($null -eq $TaintedFields)    { $TaintedFields    = New-Object 'System.Collections.Generic.HashSet[string]' }
    for ($pass = 0; $pass -lt 3; $pass++) {
        $changed = $false
        for ($k = 1; $k -lt $Instrs.Count; $k++) {
            $st = $Instrs[$k]
            if ($st.OpCode.Name -notlike 'stloc*') { continue }
            $li = Get-TcpkIlLocalIndex $st
            if ($li -lt 0 -or $tl.Contains($li)) { continue }
            # nearest preceding value-producing instruction (skip nop/dup/conv/box)
            $p = $k - 1
            while ($p -ge 0) {
                $pnm = $Instrs[$p].OpCode.Name
                if ($pnm -eq 'nop' -or $pnm -eq 'dup' -or $pnm -eq 'box' -or $pnm -like 'conv.*') { $p--; continue }
                break
            }
            if ($p -lt 0) { continue }
            $pin = $Instrs[$p]; $pn = $pin.OpCode.Name; $isT = $false
            if ($pn -eq 'call' -or $pn -eq 'callvirt' -or $pn -eq 'newobj') {
                $pr = $pin.Operand -as [Mono.Cecil.MethodReference]
                if ($pr -and ("$($pr.DeclaringType.FullName)::$($pr.Name)" -match $script:TcpkIlSourceApiRx -or $TaintedReturning.Contains("$($pr.FullName)"))) { $isT = $true }
            }
            elseif ($pn -in 'ldarg.1','ldarg.2','ldarg.3','ldarg.s','ldarg') { if ($Reachable) { $isT = $true } }
            elseif ($pn -like 'ldloc*') {
                $pli = Get-TcpkIlLocalIndex $pin
                if ($pli -ge 0 -and $tl.Contains($pli)) { $isT = $true }
            }
            elseif ($pn -eq 'ldfld' -or $pn -eq 'ldsfld') {
                $fr = $pin.Operand -as [Mono.Cecil.FieldReference]
                if ($fr -and $TaintedFields.Contains("$($fr.FullName)")) { $isT = $true }
            }
            if ($isT) { [void]$tl.Add($li); $changed = $true }
        }
        if (-not $changed) { break }
    }
    return ,$tl
}

# Build (cached per assembly) the set of "tainted FIELDS": instance/static fields that
# get ASSIGNED an external-input-derived value anywhere in the assembly (stfld/stsfld
# whose stored value is a source / tainted-returning call, a caller parameter, or a
# tainted local). A field is the classic cross-method carrier -- input is stashed in a
# field in one method (Configure) and read into a sink in another (Run) -- so tracking
# it lets the taint follow. Bounded 2-pass fixpoint (field <- field). PRECISE: direct
# assignment only, to avoid re-introducing false positives.
function Get-TcpkTaintedFields {
    [CmdletBinding()] param([Parameter(Mandatory)]$Asm, [Parameter(Mandatory)][string]$Key)
    if ($script:TcpkTaintedFieldCache.ContainsKey($Key)) { return ,$script:TcpkTaintedFieldCache[$Key] }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $tr  = $null
    try { $tr = Get-TcpkTaintedReturningMethods -Asm $Asm -Key $Key } catch { }
    if ($null -eq $tr) { $tr = New-Object 'System.Collections.Generic.HashSet[string]' }
    try {
        $methods = New-Object 'System.Collections.Generic.List[object]'
        foreach ($t in $Asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) { if ($m.HasBody) { $methods.Add($m) } }
        }
        for ($pass = 0; $pass -lt 2; $pass++) {
            $changed = $false
            foreach ($m in $methods) {
                $instrs = @($m.Body.Instructions)
                # field-aware tainted locals for this method (uses the set built so far).
                # Reachable=$true is a deliberate, slightly-permissive proxy: we lack the
                # call graph in this pass, and the field indirection is itself the strong
                # signal, so treat a param-fed store as a possible taint carrier.
                $tl = Get-TcpkMethodTaintedLocals -Instrs $instrs -Reachable $true -TaintedReturning $tr -TaintedFields $set
                for ($k = 1; $k -lt $instrs.Count; $k++) {
                    $st = $instrs[$k]
                    if ($st.OpCode.Name -ne 'stfld' -and $st.OpCode.Name -ne 'stsfld') { continue }
                    $fr = $st.Operand -as [Mono.Cecil.FieldReference]
                    if (-not $fr) { continue }
                    $fk = "$($fr.FullName)"
                    if ($set.Contains($fk)) { continue }
                    $p = $k - 1
                    while ($p -ge 0) {
                        $pnm = $instrs[$p].OpCode.Name
                        if ($pnm -eq 'nop' -or $pnm -eq 'dup' -or $pnm -eq 'box' -or $pnm -like 'conv.*') { $p--; continue }
                        break
                    }
                    if ($p -lt 0) { continue }
                    $pin = $instrs[$p]; $pn = $pin.OpCode.Name; $isT = $false
                    if ($pn -eq 'call' -or $pn -eq 'callvirt' -or $pn -eq 'newobj') {
                        $pr = $pin.Operand -as [Mono.Cecil.MethodReference]
                        if ($pr -and ("$($pr.DeclaringType.FullName)::$($pr.Name)" -match $script:TcpkIlSourceApiRx -or $tr.Contains("$($pr.FullName)"))) { $isT = $true }
                    }
                    elseif ($pn -in 'ldarg.1','ldarg.2','ldarg.3','ldarg.s','ldarg') { $isT = $true }
                    elseif ($pn -like 'ldloc*') {
                        $pli = Get-TcpkIlLocalIndex $pin
                        if ($pli -ge 0 -and $tl.Contains($pli)) { $isT = $true }
                    }
                    elseif ($pn -eq 'ldfld' -or $pn -eq 'ldsfld') {
                        $fr2 = $pin.Operand -as [Mono.Cecil.FieldReference]
                        if ($fr2 -and $set.Contains("$($fr2.FullName)")) { $isT = $true }
                    }
                    if ($isT) { [void]$set.Add($fk); $changed = $true }
                }
            }
            if (-not $changed) { break }
        }
    } catch { }
    $script:TcpkTaintedFieldCache[$Key] = $set
    return ,$set
}

# Callsite sink map: callsites.<suffix> -> the sink type(s)/method(s) to look for and
# whether the dangerous ARGUMENT carries external input (injection-class). SHARED by the
# deterministic verifier (Confirm-TcpkCallsiteUsage) and the LLM judge, so the two never
# drift on which APIs count as sinks. Each sink: T = type fragment (managed BCL) OR, with
# Mo, a method-name fragment; M = a SINGLE method-name token (it is regex-ESCAPED, so an
# alternation 'A|B' would never match -- split into two sinks); Mo = match by called
# METHOD name (any declaring type), for P/Invoke sinks.
function Get-TcpkCallsiteSinkMap {
    @{
        'command-execution'          = @{ Inj = $true;  Sinks = @(@{T='System.Diagnostics.Process'},@{T='System.Diagnostics.ProcessStartInfo'},@{T='CreateProcess';Mo=$true},@{T='WinExec';Mo=$true},@{T='ShellExecute';Mo=$true}) }
        'sql-command-construction'   = @{ Inj = $true;  Sinks = @(@{T='SqlCommand'},@{T='OleDbCommand'},@{T='OdbcCommand'},@{T='MySqlCommand'},@{T='NpgsqlCommand'},@{T='SqliteCommand'},@{T='SQLiteCommand'},@{T='System.Data.Common.DbCommand'},@{T='System.Data.IDbCommand'},@{T='System.Data.Common.DbDataAdapter'}) }
        'ssrf-request-build'         = @{ Inj = $true;  Sinks = @(@{T='System.Net.WebRequest'},@{T='System.Net.Http.HttpClient'},@{T='System.Net.Http.HttpMessageInvoker'},@{T='System.Net.WebClient'},@{T='System.Net.Http.HttpRequestMessage'},@{T='RestClient'}) }
        'nosql-command-construction' = @{ Inj = $true;  Sinks = @(@{T='MongoCollection'},@{T='IMongoCollection'},@{T='BsonJavaScript'},@{T='FilterDefinition'},@{T='LiteCollection'}) }
        'ldap-query'                 = @{ Inj = $true;  Sinks = @(@{T='System.DirectoryServices.DirectorySearcher'},@{T='System.DirectoryServices.DirectoryEntry'}) }
        'xaml-objectdataprovider-rce'= @{ Inj = $true;  Sinks = @(@{T='XamlReader'},@{T='XamlServices'},@{T='ObjectDataProvider'}) }
        'path-traversal-build'       = @{ Inj = $true;  Sinks = @(@{T='System.IO.Path';M='Combine'},@{T='System.IO.Path';M='GetFullPath'},@{T='ZipFile'}) }
        'reflection-load'            = @{ Inj = $true;  Sinks = @(@{T='System.Reflection.Assembly';M='Load'},@{T='System.Reflection.Assembly';M='LoadFrom'},@{T='System.Reflection.Assembly';M='LoadFile'},@{T='System.Reflection.Assembly';M='UnsafeLoadFrom'},@{T='System.Activator';M='CreateInstanceFrom'},@{T='System.AppDomain';M='Load'}) }
        'weak-symmetric-crypto'      = @{ Inj = $false; Sinks = @(@{T='DESCryptoServiceProvider'},@{T='TripleDESCryptoServiceProvider'},@{T='RC2CryptoServiceProvider'},@{T='Cryptography.DES'},@{T='Cryptography.TripleDES'},@{T='Cryptography.RC2'}) }
        'weak-hash-md5-sha1'         = @{ Inj = $false; Sinks = @(@{T='Cryptography.MD5'},@{T='MD5CryptoServiceProvider'},@{T='SHA1Managed'},@{T='SHA1CryptoServiceProvider'},@{T='Cryptography.SHA1'}) }
        'weak-rng'                   = @{ Inj = $false; Sinks = @(@{T='System.Random'}) }
        'base64-as-encryption'       = @{ Inj = $false; Sinks = @(@{T='System.Convert';M='ToBase64String'},@{T='System.Convert';M='FromBase64String'}) }
        'env-var-path-use'           = @{ Inj = $false; Sinks = @(@{T='System.Environment';M='GetEnvironmentVariable'},@{T='System.Environment';M='ExpandEnvironmentStrings'}) }
        'input-capture'              = @{ Inj = $false; Sinks = @(@{T='SetWindowsHookEx';Mo=$true},@{T='GetAsyncKeyState';Mo=$true},@{T='GetKeyboardState';Mo=$true},@{T='keybd_event';Mo=$true},@{T='RegisterRawInputDevices';Mo=$true},@{T='BitBlt';Mo=$true},@{T='PrintWindow';Mo=$true},@{T='CopyFromScreen';Mo=$true}) }
        'token-impersonation'        = @{ Inj = $false; Sinks = @(@{T='LogonUser';Mo=$true},@{T='ImpersonateLoggedOnUser';Mo=$true},@{T='ImpersonateNamedPipeClient';Mo=$true},@{T='SetThreadToken';Mo=$true},@{T='DuplicateTokenEx';Mo=$true},@{T='WindowsIdentity';M='Impersonate'}) }
        'clipboard-access'           = @{ Inj = $false; Sinks = @(@{T='System.Windows.Forms.Clipboard'},@{T='System.Windows.Clipboard'},@{T='OpenClipboard';Mo=$true},@{T='GetClipboardData';Mo=$true},@{T='SetClipboardData';Mo=$true}) }
    }
}

# Build a case-insensitive regex over a callsite suffix's sink API name fragments (the
# type leaf, e.g. Process, or the method token, e.g. Combine) for Get-TcpkMethodIl
# -CallsApi -- so the LLM judge can locate the method that INVOKES the sink. $null if
# the suffix is not a known sink family.
function Get-TcpkCallsiteSinkApiRegex {
    param([Parameter(Mandatory)][string]$Suffix)
    $spec = (Get-TcpkCallsiteSinkMap)[$Suffix]
    if (-not $spec) { return $null }
    $frags = New-Object 'System.Collections.Generic.List[string]'
    foreach ($s in $spec.Sinks) {
        if ($s.M) { [void]$frags.Add([regex]::Escape("$($s.M)")) }
        else      { [void]$frags.Add([regex]::Escape((("$($s.T)") -split '\.')[-1])) }
    }
    $uniq = @($frags | Where-Object { $_ } | Select-Object -Unique)
    if (-not $uniq.Count) { return $null }
    '(?i)(' + ($uniq -join '|') + ')'
}

# Deterministic usage analysis for a dangerous-API "sink". Loads the assembly with
# Cecil and answers three questions a substring scan cannot:
#   1) Is the API ACTUALLY invoked (call/callvirt/newobj), or did the rule match a
#      mere string/type reference?  (CallSiteCount)
#   2) Is the enclosing method REACHABLE -- public / virtual / entry point / event-
#      handler-shaped / has any in-assembly caller?  (AnyReachable)
#   3) For an injection-class sink, is the argument a hardcoded CONSTANT (ldstr/ldc:
#      not attacker-controllable), DYNAMIC (non-constant, internal), or TAINTED --
#      external input plausibly reaches it?  (AllConstant / AnyDynamic / AnyTainted)
#
# The argument check is a bounded backward scan over the IL preceding the call -- a
# heuristic, deliberately biased SAFE: any dynamic load in the window => 'dynamic'
# (we only call it 'constant' when NO dynamic source is present), so a real bug is
# never demoted on a miss. Taint is INTERPROCEDURAL: a sink is tainted not only when
# its own method reads a source (or a reachable method's parameter feeds it), but
# also when the value comes from another method that reads input and returns it --
# directly inline (Process.Start(ReadConfig())) or through a local (var x =
# ReadConfig(); Process.Start(x)). The cross-method signal is built by
# Get-TcpkTaintedReturningMethods (a cached, 3-hop fixpoint over the call graph) and
# completed per method by Get-TcpkMethodTaintedLocals (tainted-local dataflow), both
# kept PRECISE (direct assignment from a known source/tainted-returning call only) so
# the win in recall does not re-introduce false positives. $null if Cecil unavailable.
function Get-TcpkCallsiteUsage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$TypeFragment,
        [string]$MethodName,
        [switch]$Injection,
        [switch]$MethodOnly,   # match by the called METHOD name (any declaring type) -- for P/Invoke sinks
        [int]$Max = 60
    )
    if (-not (Initialize-TcpkCecil)) { return $null }
    if (-not (Test-Path -LiteralPath $DllPath)) { return $null }
    $asm = $null
    $asm = Get-TcpkCecilAssembly $DllPath
    if ($null -eq $asm) { return $null }

    # interprocedural taint backbone: methods that read external input and return it,
    # so a sink fed by the result of such a method (possibly several hops away) is
    # recognised as tainted. Computed once per assembly and cached.
    $key = $DllPath; try { $key = (Resolve-Path -LiteralPath $DllPath -ErrorAction Stop).Path } catch { }
    $taintedReturning = $null
    try { $taintedReturning = Get-TcpkTaintedReturningMethods -Asm $asm -Key $key } catch { }
    if ($null -eq $taintedReturning) { $taintedReturning = New-Object 'System.Collections.Generic.HashSet[string]' }
    # cross-method carrier: fields that hold external input (set in one method, read in
    # another). Built once per assembly and cached.
    $taintedFields = $null
    try { $taintedFields = Get-TcpkTaintedFields -Asm $asm -Key $key } catch { }
    if ($null -eq $taintedFields) { $taintedFields = New-Object 'System.Collections.Generic.HashSet[string]' }

    $callOps = @('call','callvirt','newobj')
    $refOps  = @('call','callvirt','newobj','ldftn','ldvirtftn')
    $typeRx   = "(?i)$([regex]::Escape($TypeFragment))"
    $methodRx = if ($MethodName) { "(?i)$([regex]::Escape($MethodName))" } else { $null }
    $entry = $null; try { $entry = $asm.MainModule.EntryPoint } catch { }
    $handlerRx = '^(On[A-Z]|.*_(Click|Load|Closing|Closed|Changed|Tick|SelectionChanged|TextChanged)$|Handle|btn|Button_|Page_|Window_|Execute$|CanExecute$)'

    try {
        $allMethods = New-Object 'System.Collections.Generic.List[object]'
        $called = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                $allMethods.Add([pscustomobject]@{ T = $t; M = $m })
                if (-not $m.HasBody) { continue }
                foreach ($ins in $m.Body.Instructions) {
                    if ($refOps -notcontains $ins.OpCode.Name) { continue }
                    $r = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($r) { [void]$called.Add($r.FullName) }
                }
            }
        }

        $sites = New-Object 'System.Collections.Generic.List[object]'
        foreach ($pair in $allMethods) {
            $t = $pair.T; $m = $pair.M
            if (-not $m.HasBody) { continue }
            $instrs = @($m.Body.Instructions)

            # Does this method pull from a known external-input source? (taint signal)
            $methodHasSource = $false
            foreach ($ci in $instrs) {
                if ($callOps -notcontains $ci.OpCode.Name) { continue }
                $cr = $ci.Operand -as [Mono.Cecil.MethodReference]
                if ($cr -and ("$($cr.DeclaringType.FullName)::$($cr.Name)" -match $script:TcpkIlSourceApiRx)) { $methodHasSource = $true; break }
            }

            # reachability is a property of the method, not the call site -- compute once
            $reachMethod = $m.IsPublic -or $m.IsVirtual -or ($entry -and $entry -eq $m) -or
                           $called.Contains($m.FullName) -or ("$($m.Name)" -match $handlerRx)
            # interprocedural tainted locals, computed lazily on the first injection sink
            $taintedLocals = $null

            for ($i = 0; $i -lt $instrs.Count; $i++) {
                $ins = $instrs[$i]
                if ($callOps -notcontains $ins.OpCode.Name) { continue }
                $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                if ($null -eq $mref) { continue }
                if ($MethodOnly) {
                    if ("$($mref.Name)" -notmatch $typeRx) { continue }
                } else {
                    if ("$($mref.DeclaringType.FullName)" -notmatch $typeRx) { continue }
                    if ($methodRx -and ("$($mref.Name)" -notmatch $methodRx)) { continue }
                }

                $reach = $reachMethod

                $argKind = 'n/a'
                if ($Injection) {
                    if ($null -eq $taintedLocals) {
                        $taintedLocals = Get-TcpkMethodTaintedLocals -Instrs $instrs -Reachable ([bool]$reachMethod) -TaintedReturning $taintedReturning -TaintedFields $taintedFields
                    }
                    $nargs = 0; try { $nargs = $mref.Parameters.Count } catch { }
                    $seenDyn = $false; $seenConst = $false; $sawParam = $false
                    $sawTaintLocal = $false; $sawSourceCall = $false; $sawTaintField = $false; $win = 0
                    for ($j = $i - 1; $j -ge 0 -and $win -lt ($nargs + 5); $j--) {
                        $op = $instrs[$j].OpCode.Name
                        if ($op -eq 'nop' -or $op -eq 'dup' -or $op -like 'conv.*' -or $op -eq 'box') { continue }
                        if ($script:TcpkIlDynLoads -contains $op) {
                            $seenDyn = $true; $win++
                            # a parameter load (not ldarg.0/'this') = caller-supplied input
                            if ($op -in 'ldarg.1','ldarg.2','ldarg.3','ldarg.s','ldarg') { $sawParam = $true }
                            # interprocedural: the arg is a local that holds external input
                            elseif ($op -like 'ldloc*') {
                                $li2 = Get-TcpkIlLocalIndex $instrs[$j]
                                if ($li2 -ge 0 -and $taintedLocals.Contains($li2)) { $sawTaintLocal = $true }
                            }
                            # inline: the arg is the direct result of a source / tainted-returning call
                            elseif ($op -in 'call','callvirt') {
                                $cr2 = $instrs[$j].Operand -as [Mono.Cecil.MethodReference]
                                if ($cr2 -and ("$($cr2.DeclaringType.FullName)::$($cr2.Name)" -match $script:TcpkIlSourceApiRx -or $taintedReturning.Contains("$($cr2.FullName)"))) { $sawSourceCall = $true }
                            }
                            # interprocedural: the arg is a field that holds external input
                            # (set in another method -- the classic cross-method carrier)
                            elseif ($op -in 'ldfld','ldsfld') {
                                $fr3 = $instrs[$j].Operand -as [Mono.Cecil.FieldReference]
                                if ($fr3 -and $taintedFields.Contains("$($fr3.FullName)")) { $sawTaintField = $true }
                            }
                            continue
                        }
                        if ($script:TcpkIlConstLoads -contains $op) { $seenConst = $true; $win++; continue }
                        # a store / branch / return marks a statement boundary
                        if ($op -match '^(st|br|ret|leave|switch|throw|endfinally)') { break }
                    }
                    if ($seenDyn) {
                        # tainted = external input plausibly reaches the sink: the method reads
                        # an external source; a tainted local, a tainted field, or a source /
                        # tainted-returning call result feeds the sink (interprocedural); or a
                        # reachable method's own parameter feeds it. Otherwise 'dynamic'.
                        $tainted = $methodHasSource -or $sawSourceCall -or $sawTaintLocal -or $sawTaintField -or ($sawParam -and $reachMethod)
                        $argKind = if ($tainted) { 'tainted' } else { 'dynamic' }
                    }
                    elseif ($seenConst) { $argKind = 'constant' }
                    else { $argKind = 'unknown' }
                }

                $sites.Add([pscustomobject]@{
                    Enclosing = "$($t.FullName)::$($m.Name)"
                    Reachable = [bool]$reach
                    ArgKind   = $argKind
                    Target    = "$($mref.DeclaringType.Name)::$($mref.Name)"
                })
                if ($sites.Count -ge $Max) { break }
            }
            if ($sites.Count -ge $Max) { break }
        }

        $tnt = @($sites | Where-Object { $_.ArgKind -eq 'tainted' }).Count
        $dyn = @($sites | Where-Object { $_.ArgKind -in 'dynamic','tainted' }).Count
        $con = @($sites | Where-Object { $_.ArgKind -eq 'constant' }).Count
        return [pscustomobject]@{
            CallSiteCount = $sites.Count
            AnyReachable  = [bool](@($sites | Where-Object { $_.Reachable }).Count)
            AnyDynamic    = [bool]$dyn
            AnyTainted    = [bool]$tnt
            AllConstant   = ($sites.Count -gt 0 -and $dyn -eq 0 -and $con -gt 0)
            Sites         = $sites.ToArray()
        }
    } finally {
        # $asm is cached by Get-TcpkCecilAssembly; disposed at the audit boundary
        # (Clear-TcpkCecilCache) -- do NOT dispose here or the next sink reuses a dead handle.
    }
}
