function Test-TcpkCsvInjection {
<#
.SYNOPSIS
    A39. CSV / formula injection risk (CWE-1236): data exported to CSV/Excel without
    neutralizing leading formula characters.

.DESCRIPTION
    If an app exports user-influenced data to CSV/XLSX and a field begins with = + - @
    (or tab/CR), spreadsheet apps interpret it as a FORMULA -- enabling data
    exfiltration (=WEBSERVICE/=HYPERLINK) or, in older Excel, command execution
    (=cmd|'/c ...'!A0). The fix is to prefix such fields with a single quote / use the
    library's injection-sanitisation.

    This flags first-party code that uses a CLEAR CSV/Excel export sink (CsvHelper,
    ClosedXML, EPPlus, NPOI, Office Interop, or an explicit *Csv* export) but shows NO
    formula-neutralisation marker. Heuristic, Confidence=Inferred, LOW severity -- a
    triage lead: confirm whether the exported fields can be user-controlled and are
    not sanitised. (Framework files skipped; binary + shipped JS/TS scanned.)

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Clear export-to-spreadsheet sinks (specific libraries / explicit CSV export).
    $exportMarkers = @(
        'CsvHelper', 'CsvWriter', 'WriteRecords', 'WriteRecord',
        'ClosedXML', 'XLWorkbook',
        'OfficeOpenXml', 'ExcelPackage',
        'NPOI', 'XSSFWorkbook', 'HSSFWorkbook',
        'Microsoft.Office.Interop.Excel',
        'WriteCsv', 'ToCsv', 'ExportCsv', 'ExportToCsv', 'json2csv', 'papaparse'
    )
    # Markers that indicate the app ALREADY neutralises formula injection.
    $neutralizeMarkers = @(
        'SanitizeForInjection', 'InjectionOptions', 'InjectionCharacters',  # CsvHelper anti-injection
        'SanitizeForCsv', 'CsvSanitiz', 'EscapeFormula', 'FormulaInjection',
        'CsvInjection', 'SanitizeCell', 'NeutralizeFormula', 'SanitizeFormula'
    )

    $exportFiles = New-Object System.Collections.Generic.List[string]
    $neutralized = $false

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if ($neutralizeMarkers | Where-Object { $text.Contains($_) }) { $neutralized = $true }
        if ($exportMarkers   | Where-Object { $text.Contains($_) }) { $exportFiles.Add($pe.Name) }
    }

    # Shipped JS/TS (Electron) export libraries too.
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($item -and $item.PSIsContainer) {
        $js = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in '.js', '.mjs', '.cjs', '.ts' -and $_.Length -lt 4MB }
        foreach ($f in $js) {
            $t = $null; try { $t = [IO.File]::ReadAllText($f.FullName) } catch { continue }
            if (-not $t) { continue }
            if ($neutralizeMarkers | Where-Object { $t.Contains($_) }) { $neutralized = $true }
            if (('json2csv','papaparse','ToCsv','exportToCsv','writeToString') | Where-Object { $t.Contains($_) }) { $exportFiles.Add($f.Name) }
        }
    }

    $files = @($exportFiles | Select-Object -Unique)
    if ($files.Count -and -not $neutralized) {
        New-TcpkFinding -Module 'static' -RuleId 'csv.formula-injection-risk' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'CSV/Excel export without formula-injection neutralization' `
            -File ($files -join ', ') `
            -Evidence ("export sink present ($($files.Count) file(s)); no formula-neutralization marker found") `
            -Cwe @('CWE-1236') `
            -Impact 'If an exported field is user-influenced and starts with a formula character, opening the file lets an attacker exfiltrate data (=WEBSERVICE / =HYPERLINK) or, in older Excel with DDE enabled, run commands on the reviewer machine. Risk depends on whether the exported fields are attacker-controlled.' `
            -Description 'The app exports data to CSV/Excel but no formula-character neutralization was seen. If any exported field can be user-controlled and starts with = + - @ (or tab/CR), a spreadsheet will execute it as a formula (=WEBSERVICE / =HYPERLINK for data exfiltration; =cmd|... for command execution in older Excel). Confirm the export path: are the fields user-influenced, and are leading formula characters escaped?' `
            -Fix "Prefix any cell that starts with = + - @ (tab, CR) with a single quote, or enable the library's injection sanitisation (e.g. CsvHelper SanitizeForInjection)."
    }
}
