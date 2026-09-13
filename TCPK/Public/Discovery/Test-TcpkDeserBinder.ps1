function Test-TcpkDeserBinder {
<#
.SYNOPSIS
    A71. Whether a .NET deserialization sink is actually guarded by a SerializationBinder.

.DESCRIPTION
    WHY THIS EXISTS. Test-TcpkDeserialization proves a formatter type is REFERENCED, and
    Confirm-TcpkDeserialization proves Deserialize() is INVOKED. Neither answers the
    question that decides whether the sink is exploitable: is the set of types the
    formatter will instantiate restricted?

    BinaryFormatter, SoapFormatter and NetDataContractSerializer reconstruct whatever type
    the serialized stream names. That is the whole bug class: an attacker supplies a stream
    naming a gadget type whose deserialization callback executes code. The one in-band
    control is a SerializationBinder assigned to the formatter's Binder property, which
    gets to approve or reject each type name before it is bound. With a binder that
    allowlists expected types the sink is hardened. With no binder at all it is not.

    This walks the IL for both halves and reports the combination:

      deser.binder-absent    HIGH   Confirmed (IL)  A Deserialize / ReadObject call site
                                                     exists on a type-reconstructing
                                                     formatter, and set_Binder is never
                                                     called ANYWHERE in the assembly. The
                                                     sink accepts any type the stream names.

      deser.binder-present   INFO   Confirmed (IL)  A binder IS assigned somewhere in the
                                                     assembly. De-escalation evidence, with
                                                     the honest caveat below.

    ASSEMBLY-WIDE, NOT PER-METHOD, AND WHY. A binder is very often assigned in a factory or
    a constructor rather than beside the Deserialize call, so "no set_Binder in this method"
    proves nothing. Absence is therefore only reported when the setter appears nowhere in
    the assembly, which is a much stronger statement and is what makes this Confirmed (IL).

    WHAT THIS DOES NOT PROVE. A binder existing somewhere is not proof that it guards THIS
    call site, nor that its implementation is restrictive (a binder that returns
    Type.GetType(typeName) unconditionally is decoration, not a control). deser.binder-present
    is deliberately INFO and says to read the binder, rather than clearing the sink.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Formatters that reconstruct arbitrary types named by the stream AND expose a
    # Binder property. LosFormatter / ObjectStateFormatter are deliberately out of
    # scope here: they have no Binder and are guarded by MAC validation instead, which
    # is a different control and a different finding.
    $formatters = @{
        'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter' = 'BinaryFormatter'
        'System.Runtime.Serialization.Formatters.Soap.SoapFormatter'     = 'SoapFormatter'
        'System.Runtime.Serialization.NetDataContractSerializer'         = 'NetDataContractSerializer'
    }
    $sinkMethods = @('Deserialize', 'UnsafeDeserialize', 'UnsafeDeserializeMethodResponse', 'ReadObject')

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

        $binderSetFor = @{}                                          # formatter FullName -> $true
        $sites = New-Object 'System.Collections.Generic.List[object]'

        foreach ($t in $types) {
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

                    $declName = ''
                    try { $declName = "$($mref.DeclaringType.FullName)" } catch { continue }
                    if (-not $formatters.ContainsKey($declName)) { continue }
                    $mName = "$($mref.Name)"

                    if ($mName -eq 'set_Binder') {
                        $binderSetFor[$declName] = $true
                        continue
                    }
                    if ($sinkMethods -contains $mName) {
                        $tok = ''
                        try { $tok = "0x{0:X8}" -f $m.MetadataToken.ToInt32() } catch { }
                        $sites.Add([pscustomobject]@{
                            Formatter = $declName
                            Friendly  = $formatters[$declName]
                            Site      = "$($t.FullName)::$($m.Name)"
                            Call      = $mName
                            Token     = $tok
                        })
                    }
                }
            }
        }

        if ($sites.Count -eq 0) { continue }

        # Group the call sites by formatter so one finding covers one formatter.
        $byFormatter = @{}
        foreach ($s in $sites) {
            if (-not $byFormatter.ContainsKey($s.Formatter)) {
                $byFormatter[$s.Formatter] = New-Object 'System.Collections.Generic.List[object]'
            }
            $byFormatter[$s.Formatter].Add($s)
        }

        foreach ($fq in $byFormatter.Keys) {
            $group = $byFormatter[$fq]
            $friendly = $formatters[$fq]
            $sampleList = New-Object 'System.Collections.Generic.List[string]'
            foreach ($s in $group) {
                if ($sampleList.Count -ge 6) { break }
                $sampleList.Add("$($s.Site) -> $($s.Call)() $($s.Token)")
            }
            $samples = $sampleList -join '; '

            if ($binderSetFor.ContainsKey($fq)) {
                New-TcpkFinding -Module 'static' -RuleId 'deser.binder-present' `
                    -Severity 'INFO' -Confidence 'Confirmed (IL)' `
                    -Title "$($pe.Name): $friendly sink with a SerializationBinder assigned" `
                    -File $pe.FullName `
                    -Evidence ("set_Binder called in this assembly; $($group.Count) sink call site(s): $samples") `
                    -Cwe @('CWE-502') `
                    -Description ("A $friendly deserialization call site exists and this assembly does " +
                        'assign a SerializationBinder, which is the control that restricts which types the ' +
                        'formatter will reconstruct. That is the hardened shape, so this is reported as ' +
                        'de-escalation evidence rather than as a defect. Two things it does NOT establish: ' +
                        'that the binder is wired to THIS call site (it may be assigned on a different ' +
                        'formatter instance), and that the binder is restrictive. A BindToType that ends in ' +
                        'an unconditional Type.GetType(typeName) allowlists everything and is decoration. ' +
                        'Read the binder implementation before treating this sink as closed.') `
                    -Fix 'Confirm the binder is assigned on every formatter instance that deserializes untrusted input, and that BindToType allowlists an explicit set of expected types and throws on anything else rather than falling through to Type.GetType.'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'deser.binder-absent' `
                    -Severity 'HIGH' -Confidence 'Confirmed (IL)' `
                    -Title "$($pe.Name): $friendly deserializes with no SerializationBinder anywhere in the assembly" `
                    -File $pe.FullName `
                    -Evidence ("no set_Binder call in this assembly; $($group.Count) sink call site(s): $samples") `
                    -Cwe @('CWE-502', 'CWE-913') `
                    -Description ("A $friendly call site reconstructs objects from a serialized stream, and " +
                        'the setter for its Binder property is never called anywhere in this assembly. The ' +
                        'formatter therefore instantiates whatever type the incoming stream names, which is ' +
                        'the precondition for the entire deserialization gadget bug class: an attacker who ' +
                        'controls the stream supplies a type whose deserialization callback executes code, ' +
                        'and no allowlist rejects it. This is stronger than a reference scan or a call-site ' +
                        'scan, both of which are silent about whether a restriction exists. It is read from ' +
                        'the shipping IL, so it re-reads identically. What it does not establish is that ' +
                        'attacker-controlled data reaches this call site; trace the stream argument to an ' +
                        'external source to complete the chain.') `
                    -Fix ("Stop using $friendly on untrusted input. It cannot be made safe by configuration " +
                        'and Microsoft has documented BinaryFormatter as obsolete for exactly this reason. ' +
                        'Move to a contract-based serializer that does not carry type information in the ' +
                        'payload (System.Text.Json, protobuf, or DataContractSerializer with an explicit ' +
                        'KnownTypes list). If the format cannot change immediately, assign a ' +
                        'SerializationBinder whose BindToType allowlists an explicit set of types and throws ' +
                        'on everything else, and authenticate the stream before deserializing it.')
            }
        }
    }
}
