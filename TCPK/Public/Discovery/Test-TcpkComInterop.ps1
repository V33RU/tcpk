function Test-TcpkComInterop {
<#
.SYNOPSIS
    A72. The target's own COM consumption: [ComImport] RCW surface and late-bound activation.

.DESCRIPTION
    WHY THIS EXISTS. Every COM detector in TCPK inspects the SERVER side: registry CLSID
    entries, AppID RunAs, DCOM machine defaults, hijackable InprocServer32 paths. None of
    them read the CLIENT. That leaves the question an audit of a managed thick client
    actually needs answered: which COM objects does this application activate, and is the
    identity of the object it activates something an attacker can influence?

    Two passes over the shipping IL.

    PASS A, the RCW surface. Types carrying [ComImport] (TypeAttributes.Import) are the COM
    interfaces this assembly binds to, and their [Guid] attributes name the IIDs. This is
    the client-side counterpart to the registry hijack checks: each CLSID the application
    activates is a class whose registration is a hijack target, so the inventory is what
    tells you which registrations matter for this product.

    PASS B, late-bound activation. Resolving a class at runtime by name is a far sharper
    issue than a compile-time reference, because the name can come from configuration, a
    file, or a message:

      Type.GetTypeFromProgID / GetTypeFromCLSID  then Activator.CreateInstance
      Marshal.GetActiveObject   attaches to an object already in the Running Object Table
      Marshal.BindToMoniker     parses a moniker string, which can name a file, an object,
                                or "new:<CLSID>", and activates whatever it names

    LITERAL ARGUMENT GATE. A hardcoded ProgID is normal application code and is reported at
    INFO. A ProgID or moniker built at runtime is the one worth reading, because that is the
    shape where a value from config or input selects what gets instantiated. The gate walks
    back from the call instruction to see whether the argument is an ldstr constant.

    Presence of a call is not proof the argument is attacker-controlled. These are
    Confirmed (IL) observations of the shipping bytecode; completing the chain means
    tracing the argument to an external source.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $asm = Get-TcpkCecilAssembly -DllPath $pe.FullName
        if (-not $asm) { continue }
        $mod = $null
        try { $mod = $asm.MainModule } catch { $mod = $null }
        if (-not $mod) { continue }

        $types = @()
        try { $types = @($mod.GetTypes()) } catch { $types = @() }
        if ($types.Count -eq 0) { continue }

        $rcw = New-Object 'System.Collections.Generic.List[string]'
        $rcwCount = 0
        $lateBound = New-Object 'System.Collections.Generic.List[string]'
        $lateDynamic = 0
        $monikerHits = New-Object 'System.Collections.Generic.List[string]'
        $monikerDynamic = 0
        $rotHits = New-Object 'System.Collections.Generic.List[string]'

        foreach ($t in $types) {
            # ---- PASS A: [ComImport] RCW interfaces ---------------------------
            $isImport = $false
            try { $isImport = [bool]$t.IsImport } catch { $isImport = $false }
            if ($isImport) {
                $rcwCount++
                if ($rcw.Count -lt 8) {
                    $guid = ''
                    try {
                        foreach ($ca in $t.CustomAttributes) {
                            if ("$($ca.AttributeType.FullName)" -ne 'System.Runtime.InteropServices.GuidAttribute') { continue }
                            if ($ca.ConstructorArguments.Count -gt 0) { $guid = "$($ca.ConstructorArguments[0].Value)" }
                            break
                        }
                    } catch { }
                    if ($guid) { $rcw.Add("$($t.FullName) {$guid}") } else { $rcw.Add("$($t.FullName)") }
                }
            }

            # ---- PASS B: late-bound activation call sites ---------------------
            $methods = @()
            try { $methods = @($t.Methods) } catch { continue }
            foreach ($m in $methods) {
                if (-not $m.HasBody) { continue }
                $instrs = $null
                try { $instrs = $m.Body.Instructions } catch { continue }
                if (-not $instrs) { continue }

                foreach ($ins in $instrs) {
                    $opn = ''
                    try { $opn = "$($ins.OpCode.Name)" } catch { continue }
                    if ($opn -ne 'call' -and $opn -ne 'callvirt') { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    $decl = ''
                    try { $decl = "$($mref.DeclaringType.FullName)" } catch { continue }
                    $name = "$($mref.Name)"

                    $kind = ''
                    if ($decl -eq 'System.Type' -and ($name -eq 'GetTypeFromProgID' -or $name -eq 'GetTypeFromCLSID')) {
                        $kind = 'late'
                    } elseif ($decl -eq 'System.Runtime.InteropServices.Marshal' -and $name -eq 'BindToMoniker') {
                        $kind = 'moniker'
                    } elseif ($decl -eq 'System.Runtime.InteropServices.Marshal' -and $name -eq 'GetActiveObject') {
                        $kind = 'rot'
                    }
                    if (-not $kind) { continue }

                    # Is the argument a compile-time constant? Walk back past nop.
                    $prev = $ins.Previous
                    while ($prev -and "$($prev.OpCode.Name)" -eq 'nop') { $prev = $prev.Previous }
                    $isLiteral = $false
                    $literal = ''
                    if ($prev) {
                        $po = "$($prev.OpCode.Name)"
                        if ($po -eq 'ldstr') {
                            $isLiteral = $true
                            try { $literal = "$($prev.Operand)" } catch { }
                        }
                    }
                    $site = "$($t.FullName)::$($m.Name)"
                    $argTxt = 'runtime-built argument'
                    if ($isLiteral) { $argTxt = "literal '$literal'" }

                    switch ($kind) {
                        'late' {
                            if (-not $isLiteral) { $lateDynamic++ }
                            if ($lateBound.Count -lt 8) { $lateBound.Add("$site -> $name ($argTxt)") }
                        }
                        'moniker' {
                            if (-not $isLiteral) { $monikerDynamic++ }
                            if ($monikerHits.Count -lt 6) { $monikerHits.Add("$site -> BindToMoniker ($argTxt)") }
                        }
                        'rot' {
                            if ($rotHits.Count -lt 6) { $rotHits.Add("$site -> GetActiveObject ($argTxt)") }
                        }
                    }
                }
            }
        }

        # ---- findings --------------------------------------------------------
        if ($rcwCount -gt 0) {
            New-TcpkFinding -Module 'static' -RuleId 'com.interop-rcw-surface' `
                -Severity 'INFO' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) binds $rcwCount COM interface(s) via [ComImport]" `
                -File $pe.FullName -Evidence (($rcw -join '; ') + $(if ($rcwCount -gt $rcw.Count) { " (+$($rcwCount - $rcw.Count) more)" } else { '' })) `
                -Description ('The assembly declares COM interop interfaces, so it activates COM classes at ' +
                    'runtime. This is the client-side half of the COM picture: TCPK''s other COM checks read ' +
                    'the registry to find hijackable registrations, and this says which classes THIS product ' +
                    'actually consumes, which is what decides whether such a registration matters here. Each ' +
                    'CLSID the application activates is a hijack target: a per-user registration under ' +
                    'HKCU shadows the machine one, and a writable InprocServer32 path loads attacker code ' +
                    'into this process. Cross-reference with the COM hijack findings for these classes.') `
                -Fix 'No action for the inventory itself. Use it to prioritise the COM hijack findings: a hijackable registration for a CLSID this product never activates is lower priority than one it activates at startup.'
        }

        if ($lateBound.Count -gt 0) {
            $sev = 'INFO'
            if ($lateDynamic -gt 0) { $sev = 'MEDIUM' }
            $dynNote = ''
            if ($lateDynamic -gt 0) {
                $dynNote = " $lateDynamic of these resolve the class from a value built at runtime rather " +
                    'than a literal. That is the shape where a ProgID or CLSID from configuration, a file, or ' +
                    'a message decides which COM object gets instantiated in this process, so the argument ' +
                    'should be traced to its source.'
            }
            New-TcpkFinding -Module 'static' -RuleId 'com.late-bound-activation' `
                -Severity $sev -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) activates COM classes by name at runtime" `
                -File $pe.FullName -Evidence ($lateBound -join '; ') `
                -Cwe @('CWE-470') `
                -Description ('The assembly resolves a COM class by ProgID or CLSID at runtime and ' +
                    'instantiates it, rather than binding to a type at compile time. Late-bound activation ' +
                    'means the identity of the code that ends up running in this process is decided by a ' +
                    'value, and whoever controls that value controls which registered class is loaded.' +
                    $dynNote) `
                -Fix 'Prefer an early-bound interop reference to a known type. Where late binding is required, resolve the ProgID or CLSID from a fixed internal allowlist rather than from configuration or input, and verify the resolved server path before activation.'
        }

        if ($monikerHits.Count -gt 0) {
            $sev = 'MEDIUM'
            if ($monikerDynamic -gt 0) { $sev = 'HIGH' }
            New-TcpkFinding -Module 'static' -RuleId 'com.bind-to-moniker' `
                -Severity $sev -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) activates objects through Marshal.BindToMoniker" `
                -File $pe.FullName -Evidence ($monikerHits -join '; ') `
                -Cwe @('CWE-470', 'CWE-20') `
                -Description ('Marshal.BindToMoniker parses a moniker string and returns whatever object it ' +
                    'names. A moniker is far more than an object id: it can reference a file to be opened by ' +
                    'its registered handler, an item inside a running document, a composite of several ' +
                    'monikers, or "new:<CLSID>" to construct a class directly. A moniker string that an ' +
                    'attacker influences is therefore close to arbitrary object activation inside this ' +
                    'process, and the parsing itself happens before any check the application might make on ' +
                    'the result.') `
                -Fix 'Do not build a moniker from untrusted input. If the application needs to open a document, resolve and validate the path yourself and use a specific, typed API rather than handing a string to the moniker parser.'
        }

        if ($rotHits.Count -gt 0) {
            New-TcpkFinding -Module 'static' -RuleId 'com.get-active-object' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) attaches to a running COM object from the ROT" `
                -File $pe.FullName -Evidence ($rotHits -join '; ') `
                -Cwe @('CWE-349', 'CWE-829') `
                -Description ('Marshal.GetActiveObject retrieves an object another process has published in ' +
                    'the Running Object Table, instead of creating a fresh one. The application therefore ' +
                    'binds to an instance it did not create and whose provider it has not authenticated. Any ' +
                    'process running in the same session that registers under that ProgID first is handed ' +
                    'the connection, so a local attacker can present a substitute object and receive ' +
                    'whatever the application sends it, including credentials or document content, while ' +
                    'returning values the application treats as trusted.') `
                -Fix 'Prefer creating your own instance over attaching to an arbitrary published one. If attaching is required, authenticate the object before use (verify the hosting process identity and image signature) and do not send secrets to an instance whose provider has not been established.'
        }
    }
}
