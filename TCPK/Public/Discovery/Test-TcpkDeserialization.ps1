function Test-TcpkDeserialization {
<#
.SYNOPSIS
    A10. Static heuristic for unsafe .NET deserialization patterns.

.DESCRIPTION
    Substring-scans every PE for tokens from Data\secrets.json (deser_tokens
    section): BinaryFormatter, NetDataContractSerializer, SoapFormatter,
    LosFormatter, ObjectStateFormatter, TypeNameHandling, etc. Framework
    files get downgraded to INFO so the report doesn't drown in noise from
    the .NET BCL itself.

    Limitations:
      - A token match proves the type is REFERENCED, not that it is INVOKED.
        Confidence is Confirmed for first-party, Inferred for framework.
        The Verify layer (Phase 10) will decompile and confirm Deserialize()
        call sites.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $tokens = (Get-TcpkData).deser_tokens

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $isFramework = Test-TcpkIsFrameworkFile $pe.Name
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($t in $tokens) {
            if (-not $text.Contains($t.token)) { continue }

            $sev   = if ($isFramework) { 'INFO' } else { $t.severity }
            # A token match proves the type is REFERENCED, not INVOKED. Both
            # first-party and framework stay Inferred until Confirm-TcpkDeserialization
            # locates an actual Deserialize() call site in the IL.
            $conf  = 'Inferred'
            $title = if ($isFramework) { "$($t.title) (framework, informational)" } else { $t.title }

            New-TcpkFinding -Module 'static' -RuleId "deser.$($t.token.ToLowerInvariant())" `
                -Severity $sev -Confidence $conf `
                -Title $title -File $pe.FullName `
                -Description $t.description `
                -Cwe @('CWE-502') `
                -Fix 'Use TypeNameHandling.None / allowlisted KnownTypes / System.Text.Json polymorphism. Confirm runtimeconfig.json EnableUnsafeBinaryFormatterSerialization=false.'
        }

        # ---- deser.newtonsoft-typenamehandling-unsafe ---------------------------
        # The existing 'TypeNameHandling' token fires on the PROPERTY name; here we
        # look for the DANGEROUS VALUES (.All / .Auto / .Objects / .Arrays) which enable
        # polymorphic deserialization and turn any received JSON into arbitrary type
        # instantiation - the ObjectDataProvider / WindowsIdentity RCE gadget chain.
        if ([regex]::IsMatch($text, '(?i)TypeNameHandling\s*[.=]\s*(All|Auto|Objects|Arrays)\b')) {
            $val = ([regex]::Match($text, '(?i)TypeNameHandling\s*[.=]\s*(All|Auto|Objects|Arrays)\b')).Groups[1].Value
            New-TcpkFinding -Module 'static' -RuleId 'deser.newtonsoft-typenamehandling-unsafe' `
                -Severity ($(if ($isFramework) { 'INFO' } else { 'HIGH' })) -Confidence 'Inferred' `
                -Title "Newtonsoft.Json TypeNameHandling.$val in $($pe.Name)" `
                -File $pe.FullName -Evidence "TypeNameHandling.$val (polymorphic deserialization)" `
                -Cwe @('CWE-502') `
                -Description ("The assembly references TypeNameHandling.$val, which tells Newtonsoft.Json " +
                    'to accept a $type property in incoming JSON and instantiate any CLR type that name ' +
                    'resolves to. Public gadget chains (ObjectDataProvider, WindowsIdentity, PSObject) turn ' +
                    'this into arbitrary code execution when the attacker controls the JSON payload. ' +
                    'Inferred because the token match does not prove the setting is applied to a real ' +
                    'incoming-JSON call site; Confirm-TcpkDeserialization + the IL prover close it.') `
                -Fix 'Set TypeNameHandling to None. If polymorphic serialization is genuinely required, use a SerializationBinder that allow-lists the exact types the app expects. Do not read $type from untrusted JSON.'
        }

        # ---- deser.yamldotnet-object-target -------------------------------------
        # YamlDotNet is safe by default (Deserialize<ConcreteType>), but Deserialize<object>
        # or Deserialize<dynamic> lets attacker-supplied YAML instantiate any type.
        if ([regex]::IsMatch($text, '(?i)\.Deserialize\s*<\s*(object|dynamic)\s*>\s*\(')) {
            New-TcpkFinding -Module 'static' -RuleId 'deser.yamldotnet-object-target' `
                -Severity ($(if ($isFramework) { 'INFO' } else { 'HIGH' })) -Confidence 'Inferred' `
                -Title "YamlDotNet .Deserialize<object> / <dynamic> in $($pe.Name)" `
                -File $pe.FullName -Evidence 'Deserialize<object|dynamic>(' `
                -Cwe @('CWE-502') `
                -Description ('YamlDotNet is safe when the target type is a concrete DTO. A call to ' +
                    'Deserialize<object>() or Deserialize<dynamic>() defeats that: attacker YAML can ' +
                    'reference any assembly-qualified type name with a !<> tag, and the deserializer ' +
                    'will construct it. Inferred (same reason as the Newtonsoft rule).') `
                -Fix 'Deserialize into a concrete DTO type. If a variant type is really needed, use a discriminated union with a WithTagMapping allow-list.'
        }

        # ---- deser.unsafebinaryformatter-config ---------------------------------
        # .NET 5+ removes BinaryFormatter by default; a project that ships with
        # EnableUnsafeBinaryFormatterSerialization=true has explicitly opted back in.
        # This match is on the STRING in the file, so it will fire on both the .exe
        # and the runtimeconfig.json - the runtimeconfig is the truth, the .exe hit is
        # scope information.
        if ([regex]::IsMatch($text, '(?i)EnableUnsafeBinaryFormatterSerialization\s*[":=]\s*(true|"true"|1)')) {
            New-TcpkFinding -Module 'static' -RuleId 'deser.unsafebinaryformatter-config' `
                -Severity ($(if ($isFramework) { 'INFO' } else { 'HIGH' })) -Confidence 'Confirmed' `
                -Title "EnableUnsafeBinaryFormatterSerialization=true in $($pe.Name)" `
                -File $pe.FullName -Evidence 'EnableUnsafeBinaryFormatterSerialization=true' `
                -Cwe @('CWE-502') `
                -Description ('The project or runtimeconfig has explicitly opted back into ' +
                    'BinaryFormatter after .NET 5+ removed the default. Every historic BinaryFormatter ' +
                    'RCE gadget chain applies. Confirmed for what the config literally says.') `
                -Fix 'Set EnableUnsafeBinaryFormatterSerialization=false, migrate BinaryFormatter call sites to System.Text.Json / MessagePack / protobuf-net (with allow-listed types).'
        }
    }
}
