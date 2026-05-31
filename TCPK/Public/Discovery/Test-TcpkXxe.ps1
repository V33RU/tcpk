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
            New-TcpkFinding -Module 'static' -RuleId ('xxe.' + ($b.Rx -replace '\W','_')) `
                -Severity $b.Sev -Confidence 'Confirmed' `
                -Title $b.Title -File $pe.FullName -Evidence $m.Value `
                -Cwe @('CWE-611','CWE-827') `
                -Fix 'Set DtdProcessing=Prohibit and XmlResolver=null on every XmlReaderSettings instance.'
        }
    }
}
