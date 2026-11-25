# Pure-PowerShell PE reader.
# Returns: Path, IsPE32Plus, Machine, DllCharacteristics, Imports[], DelayImports[].
# Returns $null on any parse error (graceful - caller must check).
# CONTRACT: Imports[] and DelayImports[] are arrays of lower-case DLL NAME STRINGS
# ('kernel32.dll'). Read the element itself: there is no .DllName or .Module property.
# Function names per DLL come from Get-TcpkPeFunctionImports below.
# Fixes the bugs from TCAWin v2's _ReadPe (no bounds checks, foreach-then-bare-literal).

function Read-TcpkPe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $fs = $null
    $br = $null
    try {
        $fs = [IO.File]::OpenRead($Path)
        $br = [IO.BinaryReader]::new($fs)

        if ($fs.Length -lt 0x80) { return $null }

        # MZ header -> PE offset at 0x3C
        $fs.Position = 0x3C
        $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt ($fs.Length - 24)) { return $null }

        # PE signature
        $fs.Position = $peOff
        if ($br.ReadUInt32() -ne 0x00004550) { return $null }

        # COFF header
        $machine = $br.ReadUInt16()
        $numSec  = $br.ReadUInt16()

        # Optional header size at COFF+16
        $fs.Position = $peOff + 4 + 16
        $optHdrSize = $br.ReadUInt16()

        # Optional header magic (PE32 = 0x10b, PE32+ = 0x20b)
        $fs.Position = $peOff + 24
        $magic = $br.ReadUInt16()
        $isPE32Plus = ($magic -eq 0x20B)

        # SizeOfCode (optional header +4). Resource-only DLLs (.mui, satellite
        # resource assemblies) have SizeOfCode = 0 -- no executable code, so PE
        # mitigation flags on them are meaningless (no attack surface).
        $fs.Position = $peOff + 24 + 4
        $sizeOfCode = $br.ReadUInt32()

        # DllCharacteristics offset relative to optional header start (PE32: +70, PE32+: +70 too)
        $fs.Position = $peOff + 24 + 70
        $dllChar = $br.ReadUInt16()

        # Data directories start: PE32 = optHdr+96, PE32+ = optHdr+112
        $ddRva = if ($isPE32Plus) { $peOff + 24 + 112 } else { $peOff + 24 + 96 }
        if (($ddRva + 16) -gt $fs.Length) {
            return [pscustomobject]@{
                Path=$Path; IsPE32Plus=$isPE32Plus; Machine=$machine
                DllCharacteristics=$dllChar; SizeOfCode=$sizeOfCode; Imports=@()
                DelayImports=@()
                SectionNames=@(); Exports=@(); SafeSeh='N/A'; StackCookie='N/A'
            }
        }
        $fs.Position = $ddRva + 0   # Export Directory (data dir index 0)
        $exportRva = $br.ReadUInt32()
        $null      = $br.ReadUInt32()
        $importRva = $br.ReadUInt32()   # Import Directory (index 1)
        $null      = $br.ReadUInt32()
        # Load Config Directory (index 10) -> offset ddRva + 80
        $loadCfgRva = 0
        if (($ddRva + 84) -le $fs.Length) { $fs.Position = $ddRva + 80; $loadCfgRva = $br.ReadUInt32() }
        # Delay Import Descriptor (index 13) -> offset ddRva + 104. Delay-loaded DLLs
        # resolve at FIRST CALL from the process search path rather than at load time,
        # which is a wider hijack window than the normal import table, so they are
        # parsed separately and reported separately.
        $delayRva = 0
        if (($ddRva + 108) -le $fs.Length) { $fs.Position = $ddRva + 104; $delayRva = $br.ReadUInt32() }

        # ImageBase. Only needed to normalise pre-VS2005 delay descriptors, which store
        # virtual addresses instead of RVAs. PE32: optHdr+28 (4 bytes). PE32+: optHdr+24
        # (8 bytes, no BaseOfData field).
        $imageBase = [uint64]0
        if ($isPE32Plus) {
            if (($peOff + 24 + 32) -le $fs.Length) { $fs.Position = $peOff + 24 + 24; $imageBase = $br.ReadUInt64() }
        } else {
            if (($peOff + 24 + 32) -le $fs.Length) { $fs.Position = $peOff + 24 + 28; $imageBase = [uint64]$br.ReadUInt32() }
        }

        # Section table starts at peOff + 4 (sig) + 20 (COFF) + optHdrSize
        $secOff = $peOff + 4 + 20 + $optHdrSize
        $secs = New-Object 'System.Collections.Generic.List[object]'
        $sectionNames = New-Object 'System.Collections.Generic.List[string]'
        for ($i = 0; $i -lt $numSec; $i++) {
            $base = $secOff + ($i * 40)
            if (($base + 40) -gt $fs.Length) { break }
            $fs.Position = $base
            $nameBytes = $br.ReadBytes(8)                       # 8-byte section name
            $sname = ([Text.Encoding]::ASCII.GetString($nameBytes)).Trim([char]0).Trim()
            if ($sname) { $sectionNames.Add($sname) }
            $vs = $br.ReadUInt32()         # VirtualSize
            $va = $br.ReadUInt32()         # VirtualAddress (RVA base)
            $null = $br.ReadUInt32()       # SizeOfRawData (unused)
            $rp = $br.ReadUInt32()         # PointerToRawData
            $secs.Add([pscustomobject]@{ VA=$va; VSize=$vs; RawPtr=$rp })
        }

        # RVA -> file offset
        function _RvaToFile($rva, $secs) {
            foreach ($s in $secs) {
                if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) {
                    return $s.RawPtr + ($rva - $s.VA)
                }
            }
            return -1
        }

        $imports = New-Object 'System.Collections.Generic.List[string]'

        if ($importRva -ne 0) {
            $iOff = _RvaToFile $importRva $secs
            if ($iOff -ge 0) {
                $entryIdx = 0
                while ($entryIdx -lt 1000) {     # safety cap
                    $descStart = $iOff + ($entryIdx * 20)
                    if (($descStart + 20) -gt $fs.Length) { break }
                    $fs.Position = $descStart
                    $null    = $br.ReadUInt32()  # OriginalFirstThunk
                    $null    = $br.ReadUInt32()  # TimeDateStamp
                    $null    = $br.ReadUInt32()  # ForwarderChain
                    $nameRva = $br.ReadUInt32()  # Name RVA  <- what we want
                    $null    = $br.ReadUInt32()  # FirstThunk
                    if ($nameRva -eq 0) { break }    # null terminator = end of import table

                    $nOff = _RvaToFile $nameRva $secs
                    if ($nOff -lt 0 -or $nOff -ge $fs.Length) {
                        $entryIdx++; continue
                    }
                    $fs.Position = $nOff
                    $bs = New-Object 'System.Collections.Generic.List[byte]'
                    while ($fs.Position -lt $fs.Length) {
                        $b = $br.ReadByte()
                        if ($b -eq 0) { break }
                        $bs.Add($b)
                        if ($bs.Count -gt 256) { break }    # malformed name, give up
                    }
                    $name = [Text.Encoding]::ASCII.GetString($bs.ToArray()).ToLowerInvariant()
                    if ($name) { $imports.Add($name) }
                    $entryIdx++
                }
            }
        }

        # --- Delay-load imports (data directory 13) ---
        # ImgDelayDescr is 8 DWORDs (32 bytes):
        #   grAttrs, rvaDLLName, rvaHmod, rvaIAT, rvaINT, rvaBoundIAT, rvaUnloadIAT, dwTimeStamp
        # grAttrs bit 0 (dlattrRva) SET   -> the rva* fields are true RVAs (VS2005+, and
        #                                    effectively everything built this century).
        # grAttrs bit 0 CLEAR             -> they are VIRTUAL ADDRESSES (VC6-era linkers),
        #                                    so subtract ImageBase to recover the RVA.
        # Terminator is a zero rvaDLLName, matching how the normal import walk above ends.
        $delayImports = New-Object 'System.Collections.Generic.List[string]'
        if ($delayRva -ne 0) {
            $dOff = _RvaToFile $delayRva $secs
            if ($dOff -ge 0) {
                $dIdx = 0
                while ($dIdx -lt 1000) {     # safety cap, same as the import walk
                    $descStart = $dOff + ($dIdx * 32)
                    if (($descStart + 32) -gt $fs.Length) { break }
                    $fs.Position = $descStart
                    $grAttrs  = $br.ReadUInt32()   # grAttrs
                    $nameAddr = $br.ReadUInt32()   # rvaDLLName  <- what we want
                    if ($nameAddr -eq 0) { break }

                    $dNameRva = $nameAddr
                    if (($grAttrs -band 0x1) -eq 0) {
                        # Legacy VA form. Without a usable ImageBase, or if the address is
                        # below it, the value cannot be normalised -- skip rather than guess.
                        if ($imageBase -eq 0 -or [uint64]$nameAddr -le $imageBase) { $dIdx++; continue }
                        $dNameRva = [uint32]([uint64]$nameAddr - $imageBase)
                    }

                    $dnOff = _RvaToFile $dNameRva $secs
                    if ($dnOff -lt 0 -or $dnOff -ge $fs.Length) { $dIdx++; continue }
                    $fs.Position = $dnOff
                    $dbs = New-Object 'System.Collections.Generic.List[byte]'
                    while ($fs.Position -lt $fs.Length) {
                        $b = $br.ReadByte()
                        if ($b -eq 0) { break }
                        $dbs.Add($b)
                        if ($dbs.Count -gt 256) { break }    # malformed name, give up
                    }
                    $dName = [Text.Encoding]::ASCII.GetString($dbs.ToArray()).ToLowerInvariant()
                    if ($dName) { $delayImports.Add($dName) }
                    $dIdx++
                }
            }
        }

        # --- Export names (Export Directory) ---
        $exports = New-Object 'System.Collections.Generic.List[string]'
        if ($exportRva -ne 0) {
            $eOff = _RvaToFile $exportRva $secs
            if ($eOff -ge 0 -and ($eOff + 40) -le $fs.Length) {
                $fs.Position = $eOff + 24; $numNames = $br.ReadUInt32()       # NumberOfNames
                $fs.Position = $eOff + 32; $namesRva = $br.ReadUInt32()       # AddressOfNames
                $namesOff = _RvaToFile $namesRva $secs
                if ($namesOff -ge 0 -and $numNames -gt 0 -and $numNames -lt 100000) {
                    $cap = [Math]::Min([int]$numNames, 100)
                    for ($k = 0; $k -lt $cap; $k++) {
                        $fs.Position = $namesOff + ($k * 4)
                        if (($fs.Position + 4) -gt $fs.Length) { break }
                        $nrva = $br.ReadUInt32()
                        $noff = _RvaToFile $nrva $secs
                        if ($noff -lt 0 -or $noff -ge $fs.Length) { continue }
                        $fs.Position = $noff
                        $bs = New-Object 'System.Collections.Generic.List[byte]'
                        while ($fs.Position -lt $fs.Length) { $b = $br.ReadByte(); if ($b -eq 0) { break }; $bs.Add($b); if ($bs.Count -gt 256) { break } }
                        $en = [Text.Encoding]::ASCII.GetString($bs.ToArray())
                        if ($en) { $exports.Add($en) }
                    }
                }
            }
        }

        # --- SafeSEH (x86 only; x64 SEH is table-based -> inherently safe) ---
        $safeSeh = 'N/A'
        if (-not $isPE32Plus) {
            if ($dllChar -band 0x0400) { $safeSeh = 'Yes' }   # IMAGE_DLLCHARACTERISTICS_NO_SEH
            elseif ($loadCfgRva -ne 0) {
                $lcOff = _RvaToFile $loadCfgRva $secs
                if ($lcOff -ge 0 -and ($lcOff + 0x48) -le $fs.Length) {
                    $fs.Position = $lcOff + 0x40; $sehTable = $br.ReadUInt32(); $sehCount = $br.ReadUInt32()
                    $safeSeh = if ($sehTable -ne 0 -and $sehCount -gt 0) { 'Yes' } else { 'No' }
                } else { $safeSeh = 'No' }
            } else { $safeSeh = 'No' }
        }

        # --- /GS stack cookie (buffer security check) ---
        # IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie: a non-zero pointer means the
        # binary was built with /GS (stack canaries). Offset 0x3C (PE32) / 0x58
        # (PE32+). Trust it only when the load-config Size field actually covers the
        # field, so a short/old load config does not yield a false positive from
        # adjacent bytes. Same method winchecksec / PESecurity use.
        $stackCookie = 'No'
        if ($loadCfgRva -ne 0) {
            $lcOff2 = _RvaToFile $loadCfgRva $secs
            if ($lcOff2 -ge 0 -and ($lcOff2 + 4) -le $fs.Length) {
                $fs.Position = $lcOff2; $lcSize = $br.ReadUInt32()
                if ($isPE32Plus) {
                    $ckOff = 0x58; $need = $ckOff + 8
                    if ($lcSize -ge $need -and ($lcOff2 + $need) -le $fs.Length) {
                        $fs.Position = $lcOff2 + $ckOff
                        if ($br.ReadUInt64() -ne 0) { $stackCookie = 'Yes' }
                    }
                } else {
                    $ckOff = 0x3C; $need = $ckOff + 4
                    if ($lcSize -ge $need -and ($lcOff2 + $need) -le $fs.Length) {
                        $fs.Position = $lcOff2 + $ckOff
                        if ($br.ReadUInt32() -ne 0) { $stackCookie = 'Yes' }
                    }
                }
            }
        }

        return [pscustomobject]@{
            Path               = $Path
            IsPE32Plus         = $isPE32Plus
            Machine            = $machine
            DllCharacteristics = $dllChar
            SizeOfCode         = $sizeOfCode
            Imports            = $imports.ToArray()
            DelayImports       = $delayImports.ToArray()
            SectionNames       = $sectionNames.ToArray()
            Exports            = $exports.ToArray()
            SafeSeh            = $safeSeh
            StackCookie        = $stackCookie
        }
    } catch {
        return $null
    } finally {
        if ($br) { $br.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

# Parse function-level imports from both the normal and delay-load import tables.
# Returns a PSCustomObject with two hashtables:
#   .Imported      {lowercase-dll-name -> [string[]] function names}
#   .DelayImported {lowercase-dll-name -> [string[]] function names}
# Returns $null on any parse error.  Uses FileShare.ReadWrite so it can read PE files
# that are currently loaded by a running process.
function Get-TcpkPeFunctionImports {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $fs = $null; $br = $null
    try {
        $fs = [System.IO.FileStream]::new($Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $br = [System.IO.BinaryReader]::new($fs)

        if ($fs.Length -lt 0x80) { return $null }

        # MZ -> PE offset
        $fs.Position = 0x3C
        $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt ($fs.Length - 24)) { return $null }

        $fs.Position = $peOff
        if ($br.ReadUInt32() -ne 0x00004550) { return $null }   # "PE\0\0"

        # COFF: machine (skip), numSec
        $null = $br.ReadUInt16()   # Machine
        $numSec = $br.ReadUInt16()

        # Optional header size at COFF+16
        $fs.Position = $peOff + 4 + 16
        $optHdrSize = $br.ReadUInt16()

        # PE32 vs PE32+
        $fs.Position = $peOff + 24
        $magic = $br.ReadUInt16()
        $is64 = ($magic -eq 0x20B)

        # ImageBase (for legacy delay descriptors)
        $imageBase = [uint64]0
        if ($is64) {
            if (($peOff + 24 + 32) -le $fs.Length) { $fs.Position = $peOff + 24 + 24; $imageBase = $br.ReadUInt64() }
        } else {
            if (($peOff + 24 + 32) -le $fs.Length) { $fs.Position = $peOff + 24 + 28; $imageBase = [uint64]$br.ReadUInt32() }
        }

        # Data directories start: PE32 = optHdr+96, PE32+ = optHdr+112
        $ddRva = if ($is64) { $peOff + 24 + 112 } else { $peOff + 24 + 96 }

        $importRva = 0; $delayRva = 0
        if (($ddRva + 8) -le $fs.Length) {
            $fs.Position = $ddRva + 8    # import dir = data directory index 1
            $importRva = $br.ReadUInt32(); $null = $br.ReadUInt32()
        }
        if (($ddRva + 108) -le $fs.Length) {
            $fs.Position = $ddRva + 104  # delay dir = index 13
            $delayRva = $br.ReadUInt32()
        }

        # Section table
        $secOff = $peOff + 4 + 20 + $optHdrSize
        $secs = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $numSec; $i++) {
            $base = $secOff + ($i * 40)
            if (($base + 40) -gt $fs.Length) { break }
            $fs.Position = $base + 8     # skip name
            $vs = $br.ReadUInt32(); $va = $br.ReadUInt32()
            $null = $br.ReadUInt32()     # SizeOfRawData
            $rp = $br.ReadUInt32()
            $secs.Add([pscustomobject]@{ VA=$va; VSize=$vs; RawPtr=$rp })
        }

        function _R2F($rva) {
            foreach ($s in $secs) {
                if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) {
                    return $s.RawPtr + ($rva - $s.VA)
                }
            }
            return -1
        }

        # Read a null-terminated ASCII name from file offset. One ReadBytes call per name
        # rather than one ReadByte per character: a large import table has thousands of names.
        # Same result as before: $null for an empty name or one with no terminator in 256 bytes.
        function _ReadName($off) {
            if ($off -lt 0 -or $off -ge $fs.Length) { return $null }
            $fs.Position = $off
            $buf = $br.ReadBytes(257)
            $end = [Array]::IndexOf($buf, [byte]0)
            if ($end -lt 0) {
                if ($buf.Length -gt 256) { return $null }   # no terminator within 256 bytes
                $end = $buf.Length                           # name runs to the end of the file
            }
            if ($end -eq 0) { return $null }
            return [System.Text.Encoding]::ASCII.GetString($buf, 0, $end)
        }

        # Ordinal flag: the top bit of a thunk (bit 31 on PE32, bit 63 on PE32+). It is built
        # with [Convert] and NOT written as a hex literal: PowerShell reads a hex literal whose
        # top bit is set as a negative signed number (0x80000000 is -2147483648), and casting
        # that to [uint64] throws. That exception used to abort this function on the first
        # thunk, so it returned $null for every PE that has an import table.
        $ordinalFlag = if ($is64) { [Convert]::ToUInt64('8000000000000000', 16) } else { [Convert]::ToUInt64('80000000', 16) }
        $maxNameRva  = [uint64]2147483647     # a by-name thunk carries a 31-bit RVA

        # Total work bound for one file. Each table walk is capped on its own; this stops a
        # crafted file from chaining 1000 descriptors of 4096 thunks each. A real import table
        # is a few thousand thunks, so 50000 is far above any shipping binary and keeps the
        # worst case to a couple of seconds in PowerShell.
        $work = @{ Thunks = 0; Max = 50000 }

        # A name read through the FirstThunk fallback is only kept when it looks like a symbol:
        # an unbound table whose FirstThunk holds something other than hint/name RVAs would
        # otherwise turn arbitrary section bytes into "imported functions".
        $symbolRx = [regex]'^[A-Za-z_?@$][\x21-\x7E]{0,255}$'

        # Walk one import name table. Returns the imported function names (ordinals skipped).
        function _WalkInt($intRva, [bool]$strict = $false) {
            $names = New-Object 'System.Collections.Generic.List[string]'
            $iOff = _R2F $intRva
            if ($iOff -lt 0) { return $names.ToArray() }
            $stride = if ($is64) { 8 } else { 4 }
            $maxEntries = 4096
            for ($k = 0; $k -lt $maxEntries; $k++) {
                if ($work.Thunks -ge $work.Max) { break }
                $work.Thunks++
                $pos = $iOff + ($k * $stride)
                if (($pos + $stride) -gt $fs.Length) { break }
                $fs.Position = $pos
                $thunk = if ($is64) { $br.ReadUInt64() } else { [uint64]$br.ReadUInt32() }
                if ($thunk -eq 0) { break }
                if ($thunk -ge $ordinalFlag) { continue }   # import by ordinal: no name to read
                if ($thunk -gt $maxNameRva)  { continue }   # not a hint/name RVA
                $hinNameOff = _R2F ([uint32]$thunk)
                if ($hinNameOff -lt 0) { continue }
                # IMAGE_IMPORT_BY_NAME: WORD Hint, then BYTE Name[]
                $n = _ReadName ($hinNameOff + 2)
                if (-not $n) { continue }
                if ($strict -and -not $symbolRx.IsMatch($n)) { continue }
                $names.Add($n)
            }
            return $names.ToArray()
        }

        # A DLL can be named by more than one descriptor. Keep the names from every one.
        # Collected in a List per DLL (appending to an array copies it every time, which is
        # quadratic in the number of descriptors naming one DLL) and turned into the string[]
        # the callers expect just before returning.
        function _AddFns($table, $dll, $fns) {
            if (-not $table.ContainsKey($dll)) { $table[$dll] = New-Object 'System.Collections.Generic.List[string]' }
            $table[$dll].AddRange([string[]]$fns)
        }

        $imported      = @{}
        $delayImported = @{}

        # Normal import table
        if ($importRva -ne 0) {
            $iOff = _R2F $importRva
            if ($iOff -ge 0) {
                for ($ei = 0; $ei -lt 1000; $ei++) {
                    $descOff = $iOff + ($ei * 20)
                    if (($descOff + 20) -gt $fs.Length) { break }
                    $fs.Position = $descOff
                    $oft = $br.ReadUInt32()   # OriginalFirstThunk
                    $tds = $br.ReadUInt32()   # TimeDateStamp (non-zero when the image is bound)
                    $null = $br.ReadUInt32()  # ForwarderChain
                    $nRva = $br.ReadUInt32()  # Name RVA (DLL name)
                    $ft  = $br.ReadUInt32()   # FirstThunk
                    if ($nRva -eq 0) { break }
                    $dllName = _ReadName (_R2F $nRva)
                    if (-not $dllName) { continue }
                    $dllName = $dllName.ToLowerInvariant()
                    # The name table is OriginalFirstThunk. Some linkers leave it 0 and keep the
                    # names only in FirstThunk. On disk that array still holds the hint/name RVAs,
                    # unless the image is bound: then it holds addresses, so it is not walked.
                    $intRva = $oft
                    $fallback = $false
                    if ($intRva -eq 0 -and $tds -eq 0) { $intRva = $ft; $fallback = $true }
                    if ($intRva -ne 0) {
                        $fns = _WalkInt $intRva $fallback
                        if ($fns.Count) { _AddFns $imported $dllName $fns }
                    }
                }
            }
        }

        # Delay-load import table
        if ($delayRva -ne 0) {
            $dOff = _R2F $delayRva
            if ($dOff -ge 0) {
                for ($di = 0; $di -lt 1000; $di++) {
                    $descOff = $dOff + ($di * 32)
                    if (($descOff + 32) -gt $fs.Length) { break }
                    $fs.Position = $descOff
                    $grAttrs  = $br.ReadUInt32()
                    $nameAddr = $br.ReadUInt32()
                    $null = $br.ReadUInt32()   # rvaHmod
                    $iatRva = $br.ReadUInt32()
                    $intRva2 = $br.ReadUInt32()
                    if ($nameAddr -eq 0) { break }
                    $dNameRva = $nameAddr
                    if (($grAttrs -band 0x1) -eq 0) {
                        if ($imageBase -eq 0 -or [uint64]$nameAddr -le $imageBase) { continue }
                        $dNameRva = [uint32]([uint64]$nameAddr - $imageBase)
                    }
                    $dllName = _ReadName (_R2F $dNameRva)
                    if (-not $dllName) { continue }
                    $dllName = $dllName.ToLowerInvariant()
                    # Only the delay name table is walked. The delay IAT on disk holds the
                    # addresses of the load thunks, never names, so it is not a fallback.
                    if ($intRva2 -ne 0) {
                        $fns = _WalkInt $intRva2
                        if ($fns.Count) { _AddFns $delayImported $dllName $fns }
                    }
                }
            }
        }

        foreach ($t in @($imported, $delayImported)) {
            foreach ($k in @($t.Keys)) { $t[$k] = $t[$k].ToArray() }
        }

        return [pscustomobject]@{
            Imported      = $imported
            DelayImported = $delayImported
        }
    } catch {
        return $null
    } finally {
        if ($br) { try { $br.Dispose() } catch { } }
        if ($fs) { try { $fs.Dispose() } catch { } }
    }
}

# Extensions a Windows PE image ships under. Beyond .exe / .dll / .sys these are ordinary PE
# images with another name: ActiveX controls (.ocx), Delphi packages (.bpl), Control Panel
# applets (.cpl), screen savers (.scr), legacy drivers (.drv), DirectShow filters (.ax), Excel
# add-ins (.xll), audio codecs (.acm), .com programs, input method editors (.ime) and plug-in
# modules (.vst3, .arx). Leaving them out hid them from every check that walks this
# enumerator. A file that carries one of these names but is not a PE costs nothing: Read-TcpkPe
# returns $null for it. A HashSet, because the test runs once per file per check.
$script:TcpkPeExtensions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($e in '.exe', '.dll', '.sys', '.node', '.pyd',
               '.ocx', '.bpl', '.cpl', '.scr', '.drv', '.ax', '.xll', '.acm', '.com', '.ime', '.vst3', '.arx') {
    [void]$script:TcpkPeExtensions.Add($e)
}

# Convenience: enumerate PEs under a path. Returns FileInfo objects.
function Get-TcpkPeFiles {
    # -ConfigSink: optional list that receives every web.config / applicationHost.config the
    # walk passes, so a check that needs both (Test-TcpkDeserialization) walks the tree once.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.Generic.List[string]]$ConfigSink
    )
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        # NB: Get-ChildItem -Include is SILENTLY IGNORED when -LiteralPath is used,
        # so it would return EVERY file (png/txt/json/...). Filter on the extension
        # explicitly instead. Get-TcpkChildItemSafe (not -Recurse) so a GhostTree/GhostBranch
        # junction loop in the target cannot hang the scan (5.1 Get-ChildItem -Recurse follows
        # junctions; the safe walker never descends into a reparse point).
        # .node (Electron native addons) and .pyd (Python extension modules) are ordinary
        # PE DLLs with normal import tables, just a different extension. Excluding them
        # hid the whole Electron native-addon hijack class, which matters because Squirrel
        # installs to %LOCALAPPDATA% and is therefore user-writable by construction.
        #
        # BUDGET + HEARTBEAT ARE APPLIED HERE, NOT IN THE CALLERS.
        #
        # About 69 checks iterate this enumerator, and instrumenting each one would mean 69
        # edits and 69 chances to forget. Doing it at the single point they all share covers
        # every one of them at once, including any added later -- a new check written the
        # obvious way is bounded and observable without its author doing anything.
        #
        # A caller simply receives a shorter sequence when the deadline passes. That is the
        # correct behaviour for a cooperative budget: the check keeps whatever it already
        # found and returns normally, rather than throwing, which would make Invoke-TcpkAudit
        # discard the whole check's output ($r = & $Block).
        #
        # The shortfall is recorded centrally so it is still reported. A caller that stops
        # early cannot know it did, so the count is kept here and Test-TcpkScanCoverage
        # surfaces it for the audit as a whole.
        $emitted = 0
        $stopped = $false
        foreach ($f in (Get-TcpkChildItemSafe -Path $Path -File)) {
            if ($null -ne $ConfigSink -and ($f.Name -ieq 'web.config' -or $f.Name -ieq 'applicationHost.config')) { $ConfigSink.Add($f.FullName) }
            $ext = $f.Extension
            # ClickOnce publishes every file with a .deploy suffix (app.exe.deploy). The image
            # is classified by the extension underneath it.
            if ($ext -ieq '.deploy' -and $f.Name.Length -gt 7) {
                $ext = [System.IO.Path]::GetExtension($f.Name.Substring(0, $f.Name.Length - 7))
            }
            if (-not $script:TcpkPeExtensions.Contains($ext)) { continue }
            if (Test-TcpkCheckBudgetExpired) { $stopped = $true; break }
            $emitted++
            Write-TcpkHeartbeat -Component 'pe-scan' -Index $emitted -Current $f.Name -CurrentBytes $f.Length
            $f
        }
        if ($stopped) { Add-TcpkScanSkip -Kind 'BudgetStopped' -ItemPath "$Path (after $emitted PE file(s))" }
    } else {
        $item
    }
}
