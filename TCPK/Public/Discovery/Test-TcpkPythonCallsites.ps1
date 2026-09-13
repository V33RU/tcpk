function Test-TcpkPythonCallsites {
<#
.SYNOPSIS
    A64. Unsafe callsite scan over shipped Python source (.py / .pyw). Complements
    Test-TcpkCallsites (which is .NET IL only). Real gap in TCPK today: any Python
    that ships in the install tree (Electron helper, PyInstaller-bundled main,
    scripted post-install, PowerShell-hosted engine, or a Linux userland alongside
    a Windows companion) is invisible to the callsite prover.

.DESCRIPTION
    Every shipped .py / .pyw is scanned for the following dangerous shapes. Each
    match is a per-line finding; comments (`#` at start of a stripped line) and
    docstrings are ignored via a simple state machine.

    Rules:
      py.callsite.eval                   HIGH    Confirmed  eval( on any argument
      py.callsite.exec                   HIGH    Confirmed  exec(
      py.callsite.pickle-load            HIGH    Confirmed  pickle.load / .loads /
                                                             cPickle equivalents
      py.callsite.subprocess-shell       HIGH    Confirmed  subprocess.{run,call,
                                                             Popen,check_call,
                                                             check_output}(...,
                                                             shell=True)
      py.callsite.os-system              HIGH    Confirmed  os.system(
      py.callsite.yaml-unsafe            HIGH    Confirmed  yaml.load(x) without
                                                             Loader=SafeLoader, or
                                                             with Loader=Loader /
                                                             FullLoader / UnsafeLoader
      py.callsite.marshal-loads          MEDIUM  Confirmed  marshal.loads(
      py.callsite.compile-exec           MEDIUM  Confirmed  compile(...) fed to
                                                             exec / eval on the
                                                             same line
      py.callsite.shell-true-var         HIGH    Confirmed  shell=True paired with
                                                             an interpolated var
                                                             (f-string or +) in the
                                                             command arg. Same line.
      py.callsite.sqli-concat            MEDIUM  Inferred   cursor.execute("SELECT
                                                             ... " + var) or an
                                                             f-string with an SQL
                                                             keyword and a variable
                                                             substitution

    Confidence is Confirmed for the presence of the dangerous shape. Whether the
    argument is actually attacker-controlled is a taint question the static
    scanner cannot answer; that stays Inferred for the SQL rule (where the pattern
    itself is more ambiguous) and Confirmed for the rest (the dangerous API is
    dangerous even with a hard-coded arg, because next commit that arg may vary).

    Skips:
      * Third-party frameworks under site-packages / dist-packages / vendor /
        _vendor / node_modules / .venv / venv (per prior discipline in
        Test-TcpkJsSourceMap and Test-TcpkSecureStringUsage).
      * File extensions other than .py / .pyw.

.PARAMETER Path
    Install directory or single .py file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Skip:
    #   * CPython STDLIB shipped in the interpreter (any /python[0-9.]+/ segment plus
    #     the classic stdlib-only module directories that appear at the same layer)
    #   * Debian dist-packages and any vendored-lib subtree
    #   * pyc caches
    #   * pip / setuptools bundled _vendor trees
    # Every non-stdlib .py under the install tree that speaks a dangerous callsite
    # is a real first-party finding. Without this filter the rule fires on
    # OS-shipped pdb.py / logging.py / gettext.py / lib2to3 fixers and drowns the
    # report.
    $vendorSkipRx = '(?i)[\\/](python[0-9]+(?:\.[0-9]+)?[\\/](lib|lib64)|lib[\\/]python[0-9]+(?:\.[0-9]+)?|site-packages|dist-packages|_vendor|vendor|node_modules|\.venv|venv|__pycache__|idlelib|lib2to3|pyshared|ensurepip)[\\/]'

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object {
                           $_.Extension -in '.py','.pyw' -and
                           $_.Length -lt 524288 -and
                           -not ($_.FullName -match $vendorSkipRx)
                       })
        } catch { return }
    } elseif ($item.Extension -in '.py','.pyw') {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    # Per-rule pattern table. Each entry names the shape, severity, confidence, CWE
    # and one-line rationale used in the finding's Description.
    $rules = @(
        @{ Id='py.callsite.eval';           Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_.])eval\s*\(';
           Cwe=@('CWE-95','CWE-94');
           Why='eval() executes any Python expression its string argument names. When the argument is derived from a file, socket, user input, or config, this is RCE-by-design.' }
        @{ Id='py.callsite.exec';           Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_.])exec\s*\(';
           Cwe=@('CWE-95','CWE-94');
           Why='exec() runs any Python statements its string argument names. Same failure mode as eval, wider grammar.' }
        @{ Id='py.callsite.pickle-load';    Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_])(cPickle|pickle|_pickle|dill)\.loads?\s*\(';
           Cwe=@('CWE-502');
           Why='pickle.load / .loads deserializes arbitrary Python objects, and the pickle format is Turing-complete during load. A pickle from any untrusted source is arbitrary code.' }
        @{ Id='py.callsite.os-system';      Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_.])os\.system\s*\(';
           Cwe=@('CWE-78');
           Why='os.system spawns a shell that interprets metacharacters in its argument. Every interpolation into that argument is a command-injection surface.' }
        @{ Id='py.callsite.marshal-loads';  Sev='MEDIUM'; Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_])marshal\.loads?\s*\(';
           Cwe=@('CWE-502');
           Why='marshal.load deserializes CPython code objects. Attacker-controlled marshal input can produce a code object that runs at load time.' }
        @{ Id='py.callsite.subprocess-shell'; Sev='HIGH'; Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_])subprocess\.(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput)\s*\([^)]{0,400}shell\s*=\s*True';
           Cwe=@('CWE-78');
           Why='subprocess.* with shell=True routes the command line through a shell. Any variable-interpolated segment is a command-injection surface.' }
        @{ Id='py.callsite.yaml-unsafe';    Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)(?<![A-Za-z0-9_])yaml\.load\s*\((?:(?![Ss]afe[Ll]oader).)*(?:\)|,\s*Loader\s*=\s*(?:yaml\.)?(?:Loader|FullLoader|UnsafeLoader)\b)';
           Cwe=@('CWE-502');
           Why='yaml.load without Loader=SafeLoader (or with Loader / FullLoader / UnsafeLoader) instantiates arbitrary Python types listed by ! tags. RCE via crafted YAML.' }
        @{ Id='py.callsite.compile-exec';   Sev='MEDIUM'; Conf='Confirmed';
           Rx='(?m)compile\s*\([^)]{0,200}\)\s*[)\]}]?\s*(?://|#|$)?[^\r\n]{0,80}?(?:exec|eval)\s*\(';
           Cwe=@('CWE-95');
           Why='compile() followed by exec / eval on the same statement is the classic "run a dynamic string" pattern; same failure mode as eval / exec.' }
        @{ Id='py.callsite.shell-true-var'; Sev='HIGH';   Conf='Confirmed';
           Rx='(?m)subprocess\.[A-Za-z_]+\s*\(\s*(?:f["'']|["''][^"''\r\n]*"\s*\+|[^,\r\n]*[+%]\s*[a-zA-Z_])[^)]{0,200}shell\s*=\s*True';
           Cwe=@('CWE-78');
           Why='subprocess.*(shell=True) with an interpolated / concatenated command string is command injection when any interpolated segment comes from outside the process.' }
        @{ Id='py.callsite.sqli-concat';    Sev='MEDIUM'; Conf='Inferred';
           Rx='(?im)\.execute\s*\(\s*(?:f["'']|["''][^"''\r\n]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"''\r\n]*"\s*\+\s*[a-zA-Z_]|(?:SELECT|INSERT|UPDATE|DELETE)[^"''\r\n]*%\s*[a-zA-Z_])';
           Cwe=@('CWE-89');
           Why='cursor.execute() with a string built via + or an f-string that also carries an SQL keyword is the classic SQL-injection shape; parametrised queries pass ? / :name / %s placeholders, not concatenation.' }
    )

    foreach ($f in $files) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }

        # Strip triple-quoted docstrings and single-line comments so a `# eval(` in a
        # comment or an inline `"""example: eval(x)"""` docstring does not fire. The
        # replacement preserves newlines so line numbers still line up.
        $stripped = [regex]::Replace($body, '"""[\s\S]*?"""', { param($m) $m.Value -replace '[^\r\n]','' })
        $stripped = [regex]::Replace($stripped, "'''[\s\S]*?'''", { param($m) $m.Value -replace '[^\r\n]','' })
        $stripped = [regex]::Replace($stripped, '(?m)^\s*#.*$', '')

        # Rules where a literal-only argument is NOT dangerous. eval("2+2") in an
        # embedded interpreter is fine; eval(user_input) is not. Skip when the entire
        # argument up to the next unescaped `)` is a bare quoted string literal.
        $literalArgOk = @('py.callsite.eval','py.callsite.exec','py.callsite.os-system')

        foreach ($rule in $rules) {
            $seenLines = New-Object 'System.Collections.Generic.HashSet[int]'
            foreach ($m in [regex]::Matches($stripped, $rule.Rx)) {
                # Line number of the match
                $lineNo = ($stripped.Substring(0, $m.Index) -split "`n").Count
                if ($seenLines.Contains($lineNo)) { continue }
                [void]$seenLines.Add($lineNo)
                $snip = $m.Value
                if ($snip.Length -gt 160) { $snip = $snip.Substring(0, 160) + '...' }
                $snip = ($snip -replace '[\r\n]+',' ').Trim()

                # Arg-shape gate. Peek at up to 200 chars past the opening `(` and check
                # whether the argument is a pure string literal followed by `)` or `,`.
                # Skip only when literal-only is unambiguous.
                if ($literalArgOk -contains $rule.Id) {
                    $tailStart = $m.Index + $m.Length
                    $tailLen   = [Math]::Min(200, $stripped.Length - $tailStart)
                    if ($tailLen -gt 0) {
                        $tail = $stripped.Substring($tailStart, $tailLen)
                        if ($tail -match '^\s*(?:["'']([^"''\r\n]*)["'']|r["'']([^"''\r\n]*)["''])\s*[,\)]') {
                            continue
                        }
                    }
                }
                New-TcpkFinding -Module 'discovery' -RuleId $rule.Id `
                    -Severity $rule.Sev -Confidence $rule.Conf `
                    -Title "$($f.Name):$lineNo $($rule.Id) - $snip" `
                    -File "$($f.FullName):$lineNo" `
                    -Evidence $snip `
                    -Cwe $rule.Cwe `
                    -Description $rule.Why `
                    -Fix 'Replace the dangerous callsite: ast.literal_eval for structured parsing (not eval), json / msgpack / MessagePack for untrusted deserialization (not pickle / marshal), subprocess.run(list_of_args, shell=False), yaml.safe_load(), parameterised queries (cursor.execute(sql, params)). If the input is truly trusted (a constant literal), refactor to avoid the API entirely so an audit reader does not have to prove it.'
            }
        }
    }
}
