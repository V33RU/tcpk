# Delta-debugging (ddmin) reduction shared by the fuzz and crash-triage cmdlets.
#
# WHY THIS EXISTS. TCPK's own reporting standard says a raw fuzz corpus is not a finding:
# Phase 2 has to distill a crash down to a deterministic MINIMAL trigger that a vendor can
# reproduce from the writeup alone. Invoke-TcpkInputFuzz saved the entire mutated file and
# stopped, so every crash it reported shipped a non-minimal artifact that nobody could
# triage without redoing the work. This is the reduction step that closes that gap.
#
# Each test costs a process launch, so every loop here is bounded by a test budget rather
# than run to a fixpoint. A partially reduced input is still a far better artifact than the
# original, and the caller reports how much reduction was achieved instead of implying the
# result is provably minimal.

# Exit codes that mean the process died on a fault rather than returning normally.
#
# Both spellings are listed on purpose. Process.ExitCode is a signed Int32 (-1073741819),
# while the NTSTATUS constants are usually written unsigned (0xC0000005). PowerShell parses
# 0xC0000005 as a Long (3221225477) because it does not fit in Int32, so a comparison
# against the signed ExitCode silently fails unless both forms are present.
function Test-TcpkIsCrashExit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Code)

    if ($null -eq $Code) { return $false }
    $c = [int64]0
    try { $c = [int64]$Code } catch { return $false }

    $crashCodes = @(
        -1073741819, 3221225477,   # 0xC0000005 ACCESS_VIOLATION
        -1073740791, 3221226505,   # 0xC0000409 STACK_BUFFER_OVERRUN / __fastfail
        -1073741676, 3221225620,   # 0xC0000094 INTEGER_DIVIDE_BY_ZERO
        -1073741682, 3221225614,   # 0xC000008E FLOAT_DIVIDE_BY_ZERO
        -1073741795, 3221225501,   # 0xC000001D ILLEGAL_INSTRUCTION
        -1073740940, 3221226356,   # 0xC0000374 HEAP_CORRUPTION
        -1073741571, 3221225725,   # 0xC00000FD STACK_OVERFLOW
        -1073741811, 3221225485    # 0xC000000D INVALID_PARAMETER
    )
    return ($crashCodes -contains $c)
}

# Invoke a caller-supplied oracle and coerce whatever it emits to a single boolean.
# A scriptblock that writes to the pipeline as well as returning can produce an array,
# and treating that array as $true would make the minimizer accept every candidate and
# "reduce" the input to nothing. Take the last emitted value only.
function Invoke-TcpkMinimizeOracle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Test,
        [Parameter(Mandatory)][byte[]]$Candidate
    )
    $r = $null
    try { $r = & $Test $Candidate } catch { return $false }
    if ($null -eq $r) { return $false }
    if ($r -is [array]) {
        if ($r.Count -eq 0) { return $false }
        $r = $r[$r.Count - 1]
    }
    return [bool]$r
}

# ddmin over a byte array.
#
# Standard delta debugging: split the current input into N chunks and try removing each
# one. A removal that still reproduces is kept and the granularity is relaxed; a full pass
# with no successful removal doubles the granularity. Stops when the granularity exceeds
# the input length (nothing left to subdivide) or the test budget runs out.
#
# The Test scriptblock receives one [byte[]] argument and must return $true when the
# candidate STILL reproduces the original effect. It is the caller's job to make that test
# specific: an oracle that accepts any crash will happily reduce one bug's input into a
# different bug's input.
#
# PS 5.1 NOTE: every slice here is built with [Array]::Copy into a pre-allocated byte[].
# The idiomatic $buf[0..($n-1)] returns [object[]] rather than [byte[]], and an empty
# range like 0..-1 silently becomes a descending 0,-1 range, which both corrupt the data.
function Invoke-TcpkDeltaMinimize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][scriptblock]$Test,
        [int]$MaxTests = 60,
        [int]$MinLength = 1
    )

    $cur = $Bytes
    if ($null -eq $cur -or $cur.Length -le $MinLength) {
        return [pscustomobject]@{ Bytes = $cur; Tests = 0; Reduced = $false; BudgetExhausted = $false }
    }

    $tests = 0
    $n = 2
    $anyReduction = $false

    while ($cur.Length -gt $MinLength -and $tests -lt $MaxTests) {
        $chunk = [int][Math]::Ceiling($cur.Length / [double]$n)
        if ($chunk -lt 1) { break }
        $reducedThisPass = $false

        for ($i = 0; $i -lt $n; $i++) {
            if ($tests -ge $MaxTests) { break }
            $start = $i * $chunk
            if ($start -ge $cur.Length) { break }
            $len = [Math]::Min($chunk, $cur.Length - $start)
            $candLen = $cur.Length - $len
            if ($candLen -lt $MinLength) { continue }

            $cand = New-Object 'byte[]' $candLen
            if ($start -gt 0) { [Array]::Copy($cur, 0, $cand, 0, $start) }
            $tailLen = $cur.Length - ($start + $len)
            if ($tailLen -gt 0) { [Array]::Copy($cur, ($start + $len), $cand, $start, $tailLen) }

            $tests++
            if (Invoke-TcpkMinimizeOracle -Test $Test -Candidate $cand) {
                $cur = $cand
                $reducedThisPass = $true
                $anyReduction = $true
                # Relax granularity: after a successful removal the remaining input is
                # smaller, so restart the pass at a coarser split rather than continuing
                # with stale chunk boundaries.
                $n = [Math]::Max(2, $n - 1)
                break
            }
        }

        if (-not $reducedThisPass) {
            if ($n -ge $cur.Length) { break }
            $n = [Math]::Min($cur.Length, $n * 2)
        }
    }

    return [pscustomobject]@{
        Bytes           = $cur
        Tests           = $tests
        Reduced         = $anyReduction
        BudgetExhausted = ($tests -ge $MaxTests)
    }
}
