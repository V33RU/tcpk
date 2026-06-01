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
    }
}
