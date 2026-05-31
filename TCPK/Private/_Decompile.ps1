# Mono.Cecil bridge: extract IL / method bodies from .NET assemblies for the
# LLM code-judgment layer. Uses the Mono.Cecil that ships with the ILSpy install.
# Degrades gracefully (returns $null) if Cecil isn't available.

$script:TcpkCecilLoaded = $false

function Initialize-TcpkCecil {
    [CmdletBinding()] param()
    if ($script:TcpkCecilLoaded) { return $true }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\ILSpy\Mono.Cecil.dll",
        "$env:ProgramFiles\ILSpy\Mono.Cecil.dll",
        (Join-Path $script:TcpkRoot '..\tools\ILSpy\Mono.Cecil.dll')
    )
    $cecil = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $cecil) { return $false }
    try {
        Add-Type -Path $cecil -ErrorAction Stop
        $script:TcpkCecilLoaded = $true
        return $true
    } catch {
        # Already loaded in this session is fine
        if ([Mono.Cecil.AssemblyDefinition] -as [type]) { $script:TcpkCecilLoaded = $true; return $true }
        return $false
    }
}

function Test-TcpkCecilAvailable { Initialize-TcpkCecil }

# Find a method whose name (or a method that references a token) matches a needle,
# and return its disassembled IL as text. Returns $null if not found.
# $SymbolHint: the symbol the finding flagged (e.g. a property/method name).
function Get-TcpkMethodIl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$SymbolHint,
        [string[]]$SignatureContains,   # type-name fragments that must ALL appear in param types
        [int]$MaxMethods = 3
    )
    if (-not (Initialize-TcpkCecil)) { return $null }
    if (-not (Test-Path -LiteralPath $DllPath)) { return $null }

    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath) } catch { return $null }

    $results = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                $isMatch = $false

                # 1) Match by method name (SymbolHint treated as a regex alternation, case-insensitive)
                if ($m.Name -match "(?i)$SymbolHint") { $isMatch = $true }

                # 2) Match by signature: a method whose parameter types contain ALL the
                #    given fragments (e.g. X509Chain + SslPolicyErrors = a cert callback,
                #    regardless of its name). This is the robust path for TLS findings.
                if (-not $isMatch -and $SignatureContains) {
                    $paramTypes = ($m.Parameters | ForEach-Object { $_.ParameterType.FullName }) -join ' '
                    $allPresent = $true
                    foreach ($frag in $SignatureContains) {
                        if ($paramTypes -notmatch [regex]::Escape($frag)) { $allPresent = $false; break }
                    }
                    if ($allPresent) { $isMatch = $true }
                }

                # 3) Or by an operand referencing the symbol (e.g. set_X callback assignment)
                if (-not $isMatch) {
                    foreach ($ins in $m.Body.Instructions) {
                        if ($null -ne $ins.Operand -and ($ins.Operand.ToString() -match "(?i)$SymbolHint")) {
                            $isMatch = $true; break
                        }
                    }
                }
                if (-not $isMatch) { continue }

                # Prefer SMALL methods for the signature path -- the actual callback
                # lambda is tiny; skip giant async state machines that merely reference it.
                if ($SignatureContains -and $m.Body.Instructions.Count -gt 40 -and $m.Name -notmatch "(?i)$SymbolHint") { continue }

                $sb = New-Object Text.StringBuilder
                [void]$sb.AppendLine("// $($t.FullName)::$($m.Name)")
                [void]$sb.AppendLine("// returns $($m.ReturnType.Name), $($m.Body.Instructions.Count) IL instructions")
                foreach ($ins in $m.Body.Instructions) {
                    $op = $ins.OpCode.Name
                    $arg = if ($null -ne $ins.Operand) { " $($ins.Operand)" } else { '' }
                    [void]$sb.AppendLine(("  {0,-12}{1}" -f $op, $arg))
                    if ($sb.Length -gt 6000) { [void]$sb.AppendLine('  ... (truncated)'); break }
                }
                $results.Add([pscustomobject]@{
                    Type = $t.FullName; Method = $m.Name; Il = $sb.ToString()
                })
                if ($results.Count -ge $MaxMethods) { break }
            }
            if ($results.Count -ge $MaxMethods) { break }
        }
    } finally {
        $asm.Dispose()
    }
    if ($results.Count -eq 0) { return $null }
    return $results
}
