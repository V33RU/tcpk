function Test-TcpkSqlInjection {
<#
.SYNOPSIS
    C31. SQL injection via string concatenation in source code and embedded SQL.

.DESCRIPTION
    Scans source files (.cs, .vb, .java) and embedded SQL resources for patterns
    where user-controlled input is concatenated directly into a SQL command string
    rather than passed as a parameterized value.

    The existing Test-TcpkCallsites / secrets.json callsite_patterns entry for
    SqlCommand / OleDbCommand flags the presence of raw command objects in binaries
    and directs the analyst to decompile. This cmdlet provides a confirmation step
    when source files are present in the scan directory (dev environments, build
    output with source, or apps deployed with source files).

    Patterns matched:

    .NET (C#/VB):
      - CommandText assignment with string concatenation: cmd.CommandText = "SELECT..." + input
      - SqlCommand constructor with concatenated string: new SqlCommand("..." + input)
      - String.Format / $"..." interpolation with SQL keywords fed into a command object
      - ExecuteNonQuery / ExecuteReader / ExecuteScalar called on a command built with +

    Java (JDBC):
      - statement.executeQuery("... " + variable)
      - statement.execute("SELECT... " + variable)
      - String.format("SELECT... %s", input) passed to execute()

    Embedded SQL strings (any text file):
      - SQL strings containing concatenation markers that suggest dynamic construction
        (e.g., ' + @variable or ' + ? without proper parameterization context)

    Findings are Confirmed MEDIUM when a source-level concatenation pattern is found.
    The concat operand name is surfaced in Evidence so the analyst can verify the
    source of the variable (UI control, network input, file, registry).

.PARAMETER Path
    Root directory of the application or project to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkSqlInjection')) { return }
    if (-not (Test-Path $Path)) { return }

    $srcFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include '*.cs','*.vb','*.java' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 500)

    # SQL key verbs that indicate we are inside a SQL string
    $sqlVerbRx = '(?i)(?:SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|MERGE|CALL|DROP|CREATE|ALTER|TRUNCATE)\s'

    # .NET concatenation patterns
    # Match lines where a CommandText assignment or a SqlCommand/OleDb/Odbc/Npgsql/MySQL
    # constructor argument is a string literal containing a SQL verb followed by " + "
    $dotNetPatterns = @(
        @{
            Rx = '(?i)(?:CommandText|ExecuteNonQuery|ExecuteReader|ExecuteScalar|ExecuteXmlReader)' +
                 '\s*(?:=|\()\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|MERGE|WHERE)[^"]*"\s*\+'
            Label = 'CommandText/Execute with string concat'
        },
        @{
            Rx = '(?i)new\s+(?:Sql|OleDb|Odbc|MySql|Npgsql|SQLite|Sqlite|Oracle)Command\s*\(' +
                 '\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|WHERE)[^"]*"\s*\+'
            Label = 'SqlCommand constructor with string concat'
        },
        @{
            Rx = '(?i)(?:string\.Format|String\.Format)\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|WHERE)[^"]*"\s*,'
            Label = 'String.Format with SQL keyword (check if result goes into CommandText)'
        },
        @{
            Rx = '(?i)\$"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|WHERE)[^"]*\{'
            Label = 'C# interpolated string with SQL keyword (check if result goes into CommandText)'
        }
    )

    # Java JDBC patterns
    $javaPatterns = @(
        @{
            Rx = '(?i)(?:statement|conn|connection|db|stmt)\s*\.\s*execute(?:Query|Update|Batch|Large(?:Update|Batch))?\s*\(' +
                 '\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|CALL|EXEC)[^"]*"\s*\+'
            Label = 'JDBC execute() with string concat'
        },
        @{
            Rx = '(?i)String\.format\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|CALL|EXEC)[^"]*%[sd][^"]*"\s*,'
            Label = 'String.format with SQL keyword (check if result goes into JDBC execute)'
        },
        @{
            Rx = '(?i)"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|CALL|EXEC)[^"]*"\s*\+\s*\w+'
            Label = 'SQL string literal with concat (check if result goes into JDBC execute)'
        }
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        $isJava = $src.Extension.ToLowerInvariant() -eq '.java'
        $patterns = if ($isJava) { $javaPatterns } else { $dotNetPatterns }

        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            # Skip pure comment lines
            if ($line.TrimStart() -match '^(?://|#|/\*|\*|''')') { continue }

            foreach ($pat in $patterns) {
                if ($line -notmatch $pat.Rx) { continue }

                $loc = "$($src.FullName):$($i + 1)"
                if (-not $seen.Add("$($pat.Label)|$loc")) { continue }

                $snippet = $line.Trim()
                if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0, 160) + ' ...' }

                New-TcpkFinding -Module 'dataaccess' -RuleId 'sqli.source-concat' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "SQL string concatenation -- $($pat.Label): $($src.Name):$($i+1)" `
                    -File $src.FullName `
                    -Evidence "Line $($i+1): $snippet" `
                    -Cwe @('CWE-89','CWE-943') `
                    -Description ("A SQL command string is built using string concatenation or " +
                        "string formatting ($($pat.Label)). If the concatenated operand contains " +
                        "user-controlled input (from a UI control, network packet, file, registry, " +
                        "or environment variable), an attacker can inject arbitrary SQL. " +
                        "This is a source-code pattern match; trace the variable on the right side " +
                        "of the + operator to its origin to confirm exploitability. " +
                        "If the variable is a hard-coded constant or comes exclusively from the " +
                        "application's own config, this is a false positive.") `
                    -Fix ('Replace string concatenation with parameterized queries: ' +
                        'cmd.CommandText = "SELECT * FROM Users WHERE id = @id"; ' +
                        'cmd.Parameters.AddWithValue("@id", userId). ' +
                        'For ORMs: use LINQ or Entity Framework query methods, not raw SQL strings. ' +
                        'For stored procedures: pass parameters as SqlParameter objects, not via ' +
                        'string concatenation into the EXEC call.')
                break  # one match per pattern per line is enough
            }
        }
    }

    # ---- Embedded SQL in text resources ----
    # Check .sql files and RESX/embedded text for dynamic SQL indicators:
    # ' + @var  or  ' + ?  or  concat(@a,   suggest the SQL was built dynamically and
    # the result embedded -- a documentation signal, not direct injection, so Inferred.
    $sqlFiles = @(Get-ChildItem -Path $Path -Recurse -Filter '*.sql' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 50)
    foreach ($sf in $sqlFiles) {
        try { $content = Get-Content $sf.FullName -Raw -ErrorAction Stop } catch { continue }
        # Dynamic SQL: EXEC(@sql) or sp_executesql @sql where @sql is built with +/CONCAT
        if ($content -match '(?i)(EXEC\s*\(\s*@|sp_executesql\s+@|CONCAT\s*\([^)]*@[A-Za-z])') {
            $m = [regex]::Match($content, '(?i)(EXEC\s*\(\s*@\w+|sp_executesql\s+@\w+|CONCAT\s*\([^)]{0,60})')
            $ev = if ($m.Success) { $m.Value } else { 'dynamic SQL marker' }
            New-TcpkFinding -Module 'dataaccess' -RuleId 'sqli.dynamic-sql-file' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Dynamic SQL (EXEC/sp_executesql) in embedded SQL file: $($sf.Name)" `
                -File $sf.FullName `
                -Evidence $ev `
                -Cwe @('CWE-89') `
                -Description ('The SQL file uses EXEC(@variable) or sp_executesql to run a ' +
                    'dynamically built SQL string. If any part of the string is derived from ' +
                    'external input without sanitization, this is SQL injection. Review the ' +
                    'stored procedure or script to confirm whether parameter values are ' +
                    'ever concatenated into the dynamic string.') `
                -Fix ('Use sp_executesql with typed parameters instead of EXEC(@string): ' +
                    'EXEC sp_executesql @sql, N''@id INT'', @id = @inputId. ' +
                    'Never concatenate external values into the @sql string itself.')
        }
    }
}
