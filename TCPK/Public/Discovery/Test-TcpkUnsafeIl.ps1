function Test-TcpkUnsafeIl {
<#
.SYNOPSIS
    A68. Unsafe / unverifiable IL opcodes and CLR header CorFlags, read from the
    shipping assembly's metadata instead of from source text.

.DESCRIPTION
    WHY THIS EXISTS. Test-TcpkNativeInterop searches the file's raw text for
    C#-SOURCE spellings ('stackalloc', 'Marshal.Copy', 'GCHandle.Alloc'). Those
    strings do not survive compilation:

      * 'stackalloc' is a language keyword. It lowers to the localloc opcode and
        the word itself is gone from the binary.
      * 'Marshal.Copy' is never contiguous in metadata. The type name and the
        member name are separate entries in the #Strings heap, so the dotted form
        the needle looks for does not exist as a run of bytes.

    That detector therefore fires on decompiled source, PDB text and loose script,
    but is effectively blind on a compiled assembly - which is the artifact that
    actually ships. This cmdlet reads what IS in the shipping image.

    UNSAFE / UNVERIFIABLE OPCODES
      localloc   The lowering of stackalloc: a stack allocation whose size is
                 computed at runtime. The classic place an unchecked length
                 becomes a stack overwrite.
      cpblk      Unchecked block copy. memcpy with no bounds check.
      initblk    Unchecked block initialise. memset with no bounds check.
      calli      Indirect call through a function pointer using a caller-supplied
                 signature. Verifiable C# does not emit calli outside function
                 pointer / UnmanagedCallersOnly code, so it is high signal.

    CLR HEADER FLAGS (COMIMAGE_FLAGS, PE data directory 14)
      ILONLY cleared   Mixed-mode assembly: native machine code ships alongside
                       the IL. The native half is outside every managed
                       memory-safety guarantee.
      32BITREQUIRED    The image refuses to load 64-bit, which caps ASLR entropy
                       at the 32-bit address space.

    ATTRIBUTION AND HONESTY. The presence of an opcode is an attack-SURFACE
    observation, not a proven overflow, so severity stays low and the titles state
    what was observed rather than asserting a vulnerability. The value is the
    attribution tier: this is Confirmed (IL) because the opcode and the flag are
    in the shipping bytes and re-read identically on every run, which a source
    string scan can never be.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Cecil reports OpCode.Name in lower case.
    $unsafeOps = [ordered]@{
        'localloc' = 'stack allocation with a runtime-computed size (the lowering of stackalloc)'
        'cpblk'    = 'unchecked block copy, no bounds check'
        'initblk'  = 'unchecked block initialise, no bounds check'
        'calli'    = 'indirect call through a function pointer with a caller-supplied signature'
    }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        # A native PE has no CLI metadata: ReadAssembly fails and this returns null,
        # which is the gate that keeps native binaries out of the managed walk.
        # Initialize-TcpkCecil already logs a single CecilMissing scan-skip when the
        # library is absent, so a null here needs no second report.
        $asm = Get-TcpkCecilAssembly -DllPath $pe.FullName
        if (-not $asm) { continue }

        $mod = $null
        try { $mod = $asm.MainModule } catch { $mod = $null }
        if (-not $mod) { continue }

        # ---- CLR header CorFlags --------------------------------------------
        # POLARITY TRAP: ILOnly SET is the normal, safe case. The finding fires on
        # ILOnly CLEARED. Getting this backwards inverts the entire result.
        $attr = 0
        try { $attr = [int]$mod.Attributes } catch { $attr = 0 }
        $ilOnly = (($attr -band [int][Mono.Cecil.ModuleAttributes]::ILOnly) -ne 0)
        $req32  = (($attr -band [int][Mono.Cecil.ModuleAttributes]::Required32Bit) -ne 0)
        $archName = ''
        try { $archName = "$($mod.Architecture)" } catch { }

        if (-not $ilOnly) {
            New-TcpkFinding -Module 'static' -RuleId 'pe.corflags-mixed-mode' `
                -Severity 'LOW' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) is a mixed-mode assembly (ILONLY cleared)" `
                -File $pe.FullName `
                -Evidence ("ModuleAttributes=0x{0:X}; ILONLY=0; architecture={1}" -f $attr, $archName) `
                -Cwe @('CWE-119') `
                -Description ('The CLR header has COMIMAGE_FLAGS_ILONLY cleared, so this assembly carries ' +
                    'native machine code alongside its IL (C++/CLI, or an embedded native section). The ' +
                    'native half runs outside every managed memory-safety guarantee: no bounds checks, no ' +
                    'type safety, no GC supervision. Managed-only review of this file will miss that code ' +
                    'entirely, and managed decompilers will not show it.') `
                -Fix 'Prefer a pure-IL assembly calling a separately reviewed native library over a mixed-mode image. If mixed mode is required, apply native hardening to the native half (/GS, CFG, DEP, ASLR) and review it with a native toolchain.'
        }

        if ($req32) {
            New-TcpkFinding -Module 'static' -RuleId 'pe.corflags-32bit-required' `
                -Severity 'INFO' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) forces 32-bit load (32BITREQUIRED)" `
                -File $pe.FullName `
                -Evidence ("ModuleAttributes=0x{0:X}; Required32Bit=1; architecture={1}" -f $attr, $archName) `
                -Cwe @('CWE-1327') `
                -Description ('The CLR header sets COMIMAGE_FLAGS_32BITREQUIRED, so the image always loads ' +
                    'as a 32-bit process even on 64-bit Windows. A 32-bit address space gives ASLR far less ' +
                    'entropy to work with than a 64-bit one, and HIGH_ENTROPY_VA cannot apply, so address ' +
                    'layout is materially more predictable to an attacker who gets a memory-disclosure ' +
                    'primitive. This is a posture observation, not a defect on its own.') `
                -Fix 'Build as AnyCPU (or x64) unless a 32-bit-only native dependency genuinely requires it. If the constraint is one dependency, isolate it in a separate 32-bit surrogate process.'
        }

        # ---- Unsafe / unverifiable opcode walk -------------------------------
        $opCounts = @{}
        $sites = New-Object 'System.Collections.Generic.List[string]'
        $types = @()
        try { $types = @($mod.GetTypes()) } catch { $types = @() }

        foreach ($t in $types) {
            $methods = @()
            try { $methods = @($t.Methods) } catch { continue }
            foreach ($m in $methods) {
                if (-not $m.HasBody) { continue }
                $instrs = $null
                try { $instrs = $m.Body.Instructions } catch { continue }
                if (-not $instrs) { continue }
                foreach ($ins in $instrs) {
                    $op = ''
                    try { $op = "$($ins.OpCode.Name)" } catch { continue }
                    if (-not $unsafeOps.Contains($op)) { continue }
                    if ($opCounts.ContainsKey($op)) { $opCounts[$op]++ } else { $opCounts[$op] = 1 }
                    if ($sites.Count -lt 8) {
                        # Type::Method plus the metadata token, so an analyst can jump
                        # straight to it in ILSpy or dnSpy.
                        $tok = ''
                        try { $tok = "0x{0:X8}" -f $m.MetadataToken.ToInt32() } catch { }
                        $sites.Add("$($t.FullName)::$($m.Name) [$op] $tok")
                    }
                }
            }
        }

        if ($opCounts.Count -eq 0) { continue }

        $countTxt = (($opCounts.Keys | Sort-Object) | ForEach-Object { "$_ x$($opCounts[$_])" }) -join ', '
        $meaning  = (($opCounts.Keys | Sort-Object) | ForEach-Object { "$_ = $($unsafeOps[$_])" }) -join '; '

        # calli in first-party code is the higher-signal case: verifiable C# does not
        # emit it outside function-pointer code, so it is called out at LOW while a
        # plain localloc/cpblk/initblk surface stays INFO.
        $sev = 'INFO'
        if ($opCounts.ContainsKey('calli')) { $sev = 'LOW' }

        New-TcpkFinding -Module 'static' -RuleId 'interop.unsafe-il' `
            -Severity $sev -Confidence 'Confirmed (IL)' `
            -Title "$($pe.Name) contains unsafe IL: $countTxt" `
            -File $pe.FullName `
            -Evidence ("$countTxt | " + ($sites -join '; ')) `
            -Cwe @('CWE-119', 'CWE-787') `
            -Description ('The assembly contains IL opcodes that are outside verifiable, memory-safe ' +
                "managed code ($meaning). These are the managed equivalents of raw pointer arithmetic " +
                'and unchecked memcpy: the runtime performs no bounds check on them, so a length or ' +
                'index that an attacker influences reaches memory directly. This is the compiled-code ' +
                'evidence that a source-text scan for "stackalloc" cannot produce, because that keyword ' +
                'lowers to localloc and does not appear in the shipping binary. Presence is an attack ' +
                'surface to review, not a proven overflow: the next step is checking whether the size or ' +
                'index operand at each listed site is attacker-influenced.') `
            -Fix 'Review the size/length operand at each listed call site for attacker influence. Prefer Span<T>/Memory<T> and the bounds-checked BCL copy helpers (Array.Copy, Buffer.BlockCopy, Span.CopyTo) over cpblk/initblk, and cap any stackalloc length with a validated constant before the allocation.'
    }
}
