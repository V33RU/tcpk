# Pure-PowerShell .xlsx writer. An .xlsx is a ZIP of OOXML parts; we build the
# minimal valid set with System.IO.Compression (built into .NET 4.5+ / PS 5.1).
# No third-party module, no Excel install required.
#
# New-TcpkXlsx -Path <file.xlsx> -Sheets <array of sheet specs>
#   sheet spec = [ordered]@{
#       Name    = 'Findings'                     # <= 31 chars, no : \ / ? * [ ]
#       Headers = @('Severity','Title', ...)     # string[]
#       Rows    = @( @('CRITICAL','...'), ... )  # array of string[] (one per row)
#       Widths  = @(12, 60, ...)                 # optional column widths
#   }
# Cells whose exact value is a known severity/status get an automatic fill.

Add-Type -AssemblyName System.IO.Compression          -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

# value (exact, case-insensitive) -> cellXfs style index (see styles.xml below)
$script:TcpkXlsxStyleByValue = @{
    'CRITICAL'=2; 'HIGH'=3; 'MEDIUM'=4; 'LOW'=5; 'INFO'=6
    'YES'=7; 'PRESENT'=7; 'OK'=7; 'HARDENED'=7; 'SIGNED'=7; 'ENABLED'=7; 'PASS'=7
    'NO'=8; 'MISSING'=8; 'WEAK'=8; 'UNSIGNED'=8; 'DISABLED'=8; 'FAIL'=8; 'NOTSIGNED'=8
    'N/A'=6; 'PARTIAL'=9
}

function ConvertTo-TcpkXlsxColLetter([int]$n) {
    $s = ''
    while ($n -gt 0) { $m = ($n - 1) % 26; $s = [char](65 + $m) + $s; $n = [int][Math]::Floor(($n - 1) / 26) }
    return $s
}

function ConvertTo-TcpkXlsxText([string]$t) {
    if ($null -eq $t) { return '' }
    $t = $t -replace "`r`n", "`n" -replace "`r", "`n"     # normalize to LF (Excel in-cell line break)
    $t = $t -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
    $t = $t -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''   # strip illegal control chars (keeps \n = \x0A)
    return $t
}

function New-TcpkXlsx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Sheets
    )

    # ---------- styles.xml (fonts / fills / cellXfs) ----------
    $stylesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3">
<font><sz val="11"/><color theme="1"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF1A1A1A"/><name val="Calibri"/></font>
</fonts>
<fills count="10">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF34495E"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF9B0000"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC0392B"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFE67E22"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF27AE60"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFBDC3C7"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF2ECC71"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF1C40F"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="10">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="1" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="1" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="5" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="6" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="7" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="8" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="2" fillId="9" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
'@

    # ---------- per-sheet worksheet XML ----------
    $sheetXmls = @()
    $idx = 0
    foreach ($sh in $Sheets) {
        $idx++
        $headers = @($sh.Headers)
        # Normalize rows via explicit enumeration -- @($list) on a generic List can
        # throw "Argument types do not match" in PS 5.1; foreach is safe for any enumerable.
        $rows = New-Object System.Collections.ArrayList
        if ($null -ne $sh.Rows) { foreach ($rr in $sh.Rows) { [void]$rows.Add($rr) } }
        $nCols   = $headers.Count

        # column widths (explicit, or heuristic from content, capped)
        $widths = if ($sh.Widths) { @($sh.Widths) } else {
            for ($c = 0; $c -lt $nCols; $c++) {
                $maxLen = "$($headers[$c])".Length
                foreach ($r in $rows) { $v = if ($c -lt @($r).Count) { "$($r[$c])" } else { '' }; if ($v.Length -gt $maxLen) { $maxLen = $v.Length } }
                [Math]::Min(70, [Math]::Max(9, $maxLen + 2))
            }
        }
        $colsXml = '<cols>'
        for ($c = 0; $c -lt $nCols; $c++) { $colsXml += ('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>' -f ($c + 1), $widths[$c]) }
        $colsXml += '</cols>'

        $sb = New-Object System.Text.StringBuilder
        # header row (r=1), style 1
        [void]$sb.Append('<row r="1">')
        for ($c = 0; $c -lt $nCols; $c++) {
            $ref = (ConvertTo-TcpkXlsxColLetter ($c + 1)) + '1'
            [void]$sb.Append(('<c r="{0}" t="inlineStr" s="1"><is><t xml:space="preserve">{1}</t></is></c>' -f $ref, (ConvertTo-TcpkXlsxText "$($headers[$c])")))
        }
        [void]$sb.Append('</row>')

        $rowNum = 1
        foreach ($r in $rows) {
            $rowNum++
            $cells = @($r)
            [void]$sb.Append(('<row r="{0}">' -f $rowNum))
            for ($c = 0; $c -lt $nCols; $c++) {
                $val = if ($c -lt $cells.Count) { "$($cells[$c])" } else { '' }
                $ref = (ConvertTo-TcpkXlsxColLetter ($c + 1)) + $rowNum
                $style = 0
                $key = $val.ToUpperInvariant()
                if ($script:TcpkXlsxStyleByValue.ContainsKey($key)) { $style = $script:TcpkXlsxStyleByValue[$key] }
                # numeric cells -> number value (only if short pure-int/decimal)
                if ($val -match '^-?\d+(\.\d+)?$' -and $val.Length -le 15) {
                    [void]$sb.Append(('<c r="{0}" s="{1}"><v>{2}</v></c>' -f $ref, $style, $val))
                } else {
                    [void]$sb.Append(('<c r="{0}" t="inlineStr" s="{1}"><is><t xml:space="preserve">{2}</t></is></c>' -f $ref, $style, (ConvertTo-TcpkXlsxText $val)))
                }
            }
            [void]$sb.Append('</row>')
        }

        $lastCol = ConvertTo-TcpkXlsxColLetter ([Math]::Max(1, $nCols))
        $dim = "A1:{0}{1}" -f $lastCol, ([Math]::Max(1, $rows.Count + 1))
        $ws = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
              '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
              ('<dimension ref="{0}"/>' -f $dim) +
              '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>' +
              '<sheetFormatPr defaultRowHeight="15"/>' +
              $colsXml +
              '<sheetData>' + $sb.ToString() + '</sheetData>' +
              ('<autoFilter ref="A1:{0}1"/>' -f $lastCol) +
              '</worksheet>'
        $sheetXmls += $ws
    }

    # ---------- workbook.xml + rels + content types ----------
    $sheetsTags = ''
    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $name = ConvertTo-TcpkXlsxText "$($Sheets[$i].Name)"
        if ($name.Length -gt 31) { $name = $name.Substring(0, 31) }
        $sheetsTags += ('<sheet name="{0}" sheetId="{1}" r:id="rId{1}"/>' -f $name, ($i + 1))
    }
    $workbookXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
        '<sheets>' + $sheetsTags + '</sheets></workbook>'

    $stylesRid = $Sheets.Count + 1
    $relItems = ''
    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $relItems += ('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{0}.xml"/>' -f ($i + 1))
    }
    $relItems += ('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' -f $stylesRid)
    $workbookRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + $relItems + '</Relationships>'

    $overrides = ''
    for ($i = 0; $i -lt $Sheets.Count; $i++) {
        $overrides += ('<Override PartName="/xl/worksheets/sheet{0}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' -f ($i + 1))
    }
    $contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
        '<Default Extension="xml" ContentType="application/xml"/>' +
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        $overrides + '</Types>'

    $rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
        '</Relationships>'

    # ---------- zip it ----------
    Confirm-TcpkParentDir -FilePath $Path
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $enc = New-Object System.Text.UTF8Encoding($false)
    $fs = [System.IO.File]::Create($Path)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        function _Add($zip, $name, $content, $enc) {
            $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $st = $entry.Open()
            $bytes = $enc.GetBytes($content)
            $st.Write($bytes, 0, $bytes.Length)
            $st.Dispose()
        }
        _Add $zip '[Content_Types].xml'        $contentTypes $enc
        _Add $zip '_rels/.rels'                $rootRels     $enc
        _Add $zip 'xl/workbook.xml'            $workbookXml  $enc
        _Add $zip 'xl/_rels/workbook.xml.rels' $workbookRels $enc
        _Add $zip 'xl/styles.xml'              $stylesXml    $enc
        for ($i = 0; $i -lt $sheetXmls.Count; $i++) {
            _Add $zip ("xl/worksheets/sheet{0}.xml" -f ($i + 1)) $sheetXmls[$i] $enc
        }
    } finally {
        $zip.Dispose()
        $fs.Dispose()
    }
    return $Path
}
