# Pure-PowerShell PE reader.
# Returns: Path, IsPE32Plus, Machine, DllCharacteristics, Imports[].
# Returns $null on any parse error (graceful - caller must check).
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
                SectionNames=@(); Exports=@(); SafeSeh='N/A'
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

        return [pscustomobject]@{
            Path               = $Path
            IsPE32Plus         = $isPE32Plus
            Machine            = $machine
            DllCharacteristics = $dllChar
            SizeOfCode         = $sizeOfCode
            Imports            = $imports.ToArray()
            SectionNames       = $sectionNames.ToArray()
            Exports            = $exports.ToArray()
            SafeSeh            = $safeSeh
        }
    } catch {
        return $null
    } finally {
        if ($br) { $br.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

# Convenience: enumerate PEs under a path. Returns FileInfo objects.
function Get-TcpkPeFiles {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        # NB: Get-ChildItem -Include is SILENTLY IGNORED when -LiteralPath is used,
        # so it would return EVERY file (png/txt/json/...). Filter on the extension
        # explicitly instead.
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in '.exe', '.dll', '.sys' }
    } else {
        $item
    }
}
