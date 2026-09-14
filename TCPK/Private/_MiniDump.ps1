# Minidump exception-record reader.
#
# Reads only what is needed to grade a fault, and nothing else. A minidump is a header, a
# stream directory, and a set of streams; the exception record lives in stream 6 and carries
# the three fields that do all the classification work:
#
#   ExceptionCode          which fault
#   ExceptionInformation[0] access type on an access violation: 0 read, 1 write, 8 execute
#   ExceptionInformation[1] the faulting address
#
# No CONTEXT parsing, no thread walk, no memory streams. Those are architecture-specific and
# none of them are needed to answer "is this a write primitive or a null dereference", which
# is the question that separates a real memory-safety bug from the most common fuzz result.
#
# Every offset is bounds-checked against the stream length and any failure returns $null for
# the caller to handle, matching the discipline in _PeReader.ps1.

function Read-TcpkMiniDumpException {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DumpPath)

    if (-not (Test-Path -LiteralPath $DumpPath)) { return $null }
    $fs = $null; $br = $null
    try {
        $fs = [System.IO.File]::Open($DumpPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $br = New-Object System.IO.BinaryReader($fs)
        $len = $fs.Length
        if ($len -lt 32) { return $null }

        if ($br.ReadUInt32() -ne 0x504D444D) { return $null }   # 'MDMP'
        [void]$br.ReadUInt32()                                   # Version
        $nStreams = [int]$br.ReadUInt32()
        $dirRva   = [int64]$br.ReadUInt32()
        if ($nStreams -le 0 -or $nStreams -gt 4096) { return $null }
        if ($dirRva -le 0 -or ($dirRva + ($nStreams * 12)) -gt $len) { return $null }

        # Locate stream type 6 (ExceptionStream) in the directory.
        $excRva = [int64]0; $excSize = [int64]0
        $fs.Position = $dirRva
        for ($i = 0; $i -lt $nStreams; $i++) {
            $type = [int]$br.ReadUInt32()
            $size = [int64]$br.ReadUInt32()
            $rva  = [int64]$br.ReadUInt32()
            if ($type -eq 6) { $excRva = $rva; $excSize = $size; break }
        }
        if ($excRva -le 0 -or ($excRva + 40) -gt $len) { return $null }

        $fs.Position = $excRva
        $threadId = [int]$br.ReadUInt32()
        [void]$br.ReadUInt32()                                   # alignment
        $code     = [int64]$br.ReadUInt32()
        [void]$br.ReadUInt32()                                   # ExceptionFlags
        [void]$br.ReadUInt64()                                   # nested ExceptionRecord ptr
        $addr     = [uint64]$br.ReadUInt64()                      # ExceptionAddress
        $nParams  = [int]$br.ReadUInt32()
        [void]$br.ReadUInt32()                                   # alignment

        $access = -1; $faultAddr = [uint64]0
        if ($nParams -ge 1 -and ($fs.Position + 8) -le $len) { $access    = [int64]$br.ReadUInt64() }
        if ($nParams -ge 2 -and ($fs.Position + 8) -le $len) { $faultAddr = [uint64]$br.ReadUInt64() }

        return [pscustomobject]@{
            ThreadId         = $threadId
            ExceptionCode    = $code
            ExceptionAddress = $addr
            AccessType       = $access       # 0 read, 1 write, 8 execute; -1 unknown
            FaultAddress     = $faultAddr
            ParamCount       = $nParams
        }
    } catch {
        return $null
    } finally {
        if ($br) { try { $br.Dispose() } catch { } }
        if ($fs) { try { $fs.Dispose() } catch { } }
    }
}

# Grade a parsed exception record. Returns severity, a short class name, and the reasoning
# that goes into the finding.
#
# The near-null rule is the reason this exists. An access violation below the first 64 KB of
# the address space is a null or small-offset-from-null dereference: that page is reserved
# and can never be mapped, so the fault is a crash and nothing more. It is also the single
# most common result of dumb fuzzing. Reporting it at the same severity as a controlled
# write is what makes a crash list useless to a vendor.
function Get-TcpkFaultGrade {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Exc)

    $code = [int64]$Exc.ExceptionCode
    $fa   = [uint64]$Exc.FaultAddress
    $acc  = [int64]$Exc.AccessType

    # 0xC0000005 ACCESS_VIOLATION
    if ($code -eq 3221225477 -or $code -eq -1073741819) {
        if ($fa -lt 65536) {
            return [pscustomobject]@{ Severity = 'LOW'; Class = 'near-null-dereference'
                Why = ("The faulting address 0x{0:X} is inside the first 64 KB, which Windows reserves and " -f $fa) +
                      'never maps. A dereference there is a crash and cannot be steered into a read or write ' +
                      'of useful memory, because no allocation can be placed at that address to meet it. ' +
                      'This is a robustness defect and a denial of service, not a memory-corruption ' +
                      'primitive, and it is the most common single outcome of dumb fuzzing.' }
        }
        if ($acc -eq 1) {
            return [pscustomobject]@{ Severity = 'HIGH'; Class = 'write-access-violation'
                Why = ("A WRITE to unmapped address 0x{0:X}. The faulting operand is a destination, so the " -f $fa) +
                      'code was computing where to write and got it wrong. If any part of that address or ' +
                      'the written value derives from input, this is a candidate write primitive, which is ' +
                      'the strongest of the memory-safety outcomes.' }
        }
        if ($acc -eq 8) {
            return [pscustomobject]@{ Severity = 'HIGH'; Class = 'execute-access-violation'
                Why = ("An attempt to EXECUTE at 0x{0:X}, which DEP refused. Control flow reached an " -f $fa) +
                      'address holding no executable code, meaning a code pointer was corrupted or ' +
                      'miscomputed rather than data being mishandled.' }
        }
        return [pscustomobject]@{ Severity = 'MEDIUM'; Class = 'read-access-violation'
            Why = ("A READ from unmapped address 0x{0:X}. Out-of-bounds reads disclose adjacent memory " -f $fa) +
                  'when they land somewhere mapped rather than faulting, so the same defect can be an ' +
                  'information leak on inputs that miss by less.' }
    }
    if ($code -eq 3221226356 -or $code -eq -1073740940) {   # 0xC0000374 heap corruption
        return [pscustomobject]@{ Severity = 'HIGH'; Class = 'heap-corruption'
            Why = 'The heap manager detected corrupted metadata. The damage happened earlier than this ' +
                  'fault, so the reported address is where it was noticed and not where it was caused. ' +
                  'Heap metadata corruption has historically been exploitable and should be treated as ' +
                  'more serious than the crash location suggests.' }
    }
    if ($code -eq 3221226505 -or $code -eq -1073740791) {   # 0xC0000409 fast fail
        return [pscustomobject]@{ Severity = 'MEDIUM'; Class = 'security-check-failure'
            Why = 'A compiler-inserted security check fired and terminated the process deliberately. ' +
                  'That is the mitigation working: a stack cookie or bounds check caught the overflow ' +
                  'before it could be used. The underlying defect is real, but the mitigation converted ' +
                  'it from a potential takeover into a controlled stop.' }
    }
    if ($code -eq 3221225725 -or $code -eq -1073741571) {   # 0xC00000FD stack overflow
        return [pscustomobject]@{ Severity = 'LOW'; Class = 'stack-exhaustion'
            Why = 'The stack guard page was hit, usually unbounded recursion on attacker-shaped input. ' +
                  'A denial of service rather than a corruption primitive: the guard page is the ' +
                  'mechanism working as designed.' }
    }
    if ($code -eq 3221225620 -or $code -eq -1073741676 -or $code -eq 3221225614 -or $code -eq -1073741682) {
        return [pscustomobject]@{ Severity = 'LOW'; Class = 'divide-by-zero'
            Why = 'An arithmetic fault. A robustness defect with no path to memory corruption; an ' +
                  'unvalidated divisor reached the operation.' }
    }
    return [pscustomobject]@{ Severity = 'MEDIUM'; Class = 'unclassified-fault'
        Why = ("Fault code 0x{0:X} is outside the set this grades. The process died on a fault rather " -f $code) +
              'than exiting, so the defect is real, but its class has not been established here.' }
}
