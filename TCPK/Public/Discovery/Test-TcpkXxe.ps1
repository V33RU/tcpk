function Test-TcpkXxe {
<#
.SYNOPSIS
    A13. XXE indicators in shipped XML + risky XML reader settings in code.

.DESCRIPTION
    Two checks:
      1. Any shipped *.xml / *.xaml / *.xsl(t) / *.xsd that contains a
         DOCTYPE or ENTITY declaration. If that document is parsed at
         runtime with DtdProcessing=Parse, it is an XXE primitive.
      2. Any PE that references risky XML reader settings:
         DtdProcessing.Parse, XmlResolver = new XmlUrlResolver,
         legacy XmlTextReader.ProhibitDtd = false.

.PARAMETER Path
    Folder (recursive) preferred. Single file also works.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # 1. Data: shipped XML with DTD / entity declarations
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        $xmls = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.xml','.xaml','.xsl','.xslt','.xsd' }
        foreach ($f in $xmls) {
            try { $t = [IO.File]::ReadAllText($f.FullName) } catch { continue }
            $m = [regex]::Match($t, '<!DOCTYPE|<!ENTITY')
            if ($m.Success) {
                New-TcpkFinding -Module 'static' -RuleId 'xxe.dtd-or-entity-in-shipped-xml' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Shipped XML contains DOCTYPE/ENTITY" `
                    -File $f.FullName -Evidence ($m.Value + ' ...') `
                    -Cwe @('CWE-611') `
                    -Description 'Triage: if this XML is parsed at runtime with DtdProcessing=Parse, an XXE primitive exists.' `
                    -Fix 'Strip the DOCTYPE/ENTITY declaration; ensure XmlReaderSettings.DtdProcessing=Prohibit.'
            }
        }
    }

    # 2. Code: risky XML reader settings in .NET DLLs
    $bad = @(
        @{ Rx='DtdProcessing\s*=\s*DtdProcessing\.Parse'
           Sev='HIGH'
           Title='XmlReaderSettings allows DTD parsing -- XXE primitive' },
        @{ Rx='XmlResolver\s*=\s*new\s+XmlUrlResolver'
           Sev='HIGH'
           Title='XmlResolver assigned XmlUrlResolver -- external entity fetch enabled' },
        @{ Rx='ProhibitDtd\s*=\s*false'
           Sev='HIGH'
           Title='Legacy XmlTextReader.ProhibitDtd=false -- XXE primitive' }
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($b in $bad) {
            $m = [regex]::Match($text, $b.Rx)
            if (-not $m.Success) { continue }
            # Regex over PE text proves the setting STRING is present, not that it is
            # applied to a reader that parses untrusted input. Inferred until the
            # data flow is confirmed.
            New-TcpkFinding -Module 'static' -RuleId ('xxe.' + ($b.Rx -replace '\W','_')) `
                -Severity $b.Sev -Confidence 'Inferred' `
                -Title $b.Title -File $pe.FullName -Evidence $m.Value `
                -Cwe @('CWE-611','CWE-827') `
                -Fix 'Set DtdProcessing=Prohibit and XmlResolver=null on every XmlReaderSettings instance.'
        }

        # 3. Deterministic IL proof: read the actual constant fed to each XML setter, so
        # DtdProcessing.Parse (unsafe) is told apart from Prohibit/Ignore (safe) and a real
        # XmlResolver from the null-resolver mitigation. This is what actually detects XXE
        # in a compiled assembly -- the source-string regexes above rarely survive C#
        # compilation (they become ldc.i4.2 + set_DtdProcessing). Confidence 'Confirmed (IL)'.
        foreach ($v in (Get-TcpkXxeVerdicts -DllPath $pe.FullName)) {
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add($v.Reason)
            $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy - the setter is here):')
            $ev.Add("  Assembly : $($v.Assembly)")
            $ev.Add("  Namespace: $($v.Namespace)")
            $ev.Add("  Type     : $($v.Type)")
            $ev.Add("  Method   : $($v.Method)")
            $ev.Add("  MD token : $($v.Token)")
            $ev.Add('')
            $ev.Add('IL PROOF (the setter and the constant it is fed):')
            $ev.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId ('xxe.' + $v.Kind) `
                -Severity $v.Severity -Confidence 'Confirmed (IL)' `
                -Title "XXE primitive proven from IL: $($v.Type)::$($v.Method) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") `
                -Cwe @('CWE-611') `
                -Description 'Proven from IL: this method configures its XML parser to process DTDs / external entities (the exact setter and its constant argument are in the Evidence). If attacker-controlled XML reaches this parser, it enables local file disclosure, SSRF, or entity-expansion DoS. The misconfiguration is proven deterministically; whether untrusted XML reaches the reader determines exploitability.' `
                -Fix 'Set XmlReaderSettings.DtdProcessing=Prohibit (or Ignore) and XmlResolver=null. On XmlDocument set XmlResolver=null. Never assign XmlUrlResolver when parsing untrusted input.'
        }
    }
}
