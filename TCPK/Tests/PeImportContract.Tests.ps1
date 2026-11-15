#requires -Version 5.1
# The shape of what the PE readers return, and the checks that depend on it.
#
# Read-TcpkPe returns Imports / DelayImports as arrays of DLL name STRINGS. Three checks read
# a .DllName or .Module property off those strings and so never matched anything, and
# Get-TcpkPeFunctionImports threw on its own ordinal-flag literal and returned $null for every
# PE with an import table. None of that failed a test, because nothing asserted a positive
# result on a real import table. These cases do.
#
# The fixtures are built here byte by byte (New-TestPe): one section that holds an import
# table and, optionally, a delay-import table. That is enough structure for a PE reader. It is
# not runnable code.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:ModuleRoot = Split-Path $psd1 -Parent

    function New-TestPe {
        param(
            [Parameter(Mandatory)][string]$Path,
            [bool]$Is64 = $true,
            [int]$Subsystem = 3,
            [object[]]$Imports = @(),        # @{ Dll = ''; Names = @(); Ordinals = @(); NoOft = $false }
            [object[]]$DelayImports = @()    # @{ Dll = ''; Names = @() }
        )
        $secRva = 0x1000; $secRaw = 0x400; $secSize = 0x2000
        $buf = New-Object byte[] ($secRaw + $secSize)

        function W16([int]$o, [int]$v)  { $b = [BitConverter]::GetBytes([uint16]$v); [Array]::Copy($b, 0, $buf, $o, 2) }
        function W32([int]$o, [long]$v) { $b = [BitConverter]::GetBytes([uint32]$v); [Array]::Copy($b, 0, $buf, $o, 4) }
        function WStr([int]$o, [string]$s) { $b = [Text.Encoding]::ASCII.GetBytes($s); [Array]::Copy($b, 0, $buf, $o, $b.Length) }

        # DOS header, PE signature
        $buf[0] = 0x4D; $buf[1] = 0x5A
        W32 0x3C 0x80
        $buf[0x80] = 0x50; $buf[0x81] = 0x45
        # COFF header
        $coff = 0x84
        $optSize = 0xE0; $machine = 0x14C; $chars = 0x102
        if ($Is64) { $optSize = 0xF0; $machine = 0x8664; $chars = 0x22 }
        W16 $coff $machine
        W16 ($coff + 2) 1
        W16 ($coff + 16) $optSize
        W16 ($coff + 18) $chars
        # Optional header
        $opt = $coff + 20
        if ($Is64) { W16 $opt 0x20B } else { W16 $opt 0x10B }
        W32 ($opt + 4) 0x200                      # SizeOfCode
        if ($Is64) { W32 ($opt + 24) 0x40000000; W32 ($opt + 28) 1 } else { W32 ($opt + 28) 0x400000 }
        W32 ($opt + 32) 0x1000                    # SectionAlignment
        W32 ($opt + 36) 0x200                     # FileAlignment
        W16 ($opt + 48) 6                         # MajorSubsystemVersion
        W32 ($opt + 56) ($secRva + $secSize)      # SizeOfImage
        W32 ($opt + 60) $secRaw                   # SizeOfHeaders
        W16 ($opt + 68) $Subsystem
        W16 ($opt + 70) 0x0140                    # DYNAMIC_BASE | NX_COMPAT
        $dd = $opt + 96
        if ($Is64) { W32 ($opt + 108) 16; $dd = $opt + 112 } else { W32 ($opt + 92) 16 }
        # Section header
        $sh = $opt + $optSize
        WStr $sh '.rdata'
        W32 ($sh + 8)  $secSize
        W32 ($sh + 12) $secRva
        W32 ($sh + 16) $secSize
        W32 ($sh + 20) $secRaw
        W32 ($sh + 36) 0x40000040

        $stride = 4
        if ($Is64) { $stride = 8 }
        $impCount = @($Imports).Count
        $dlyCount = @($DelayImports).Count
        $impOff = 0
        $dlyOff = ($impCount + 1) * 20
        $cur = $dlyOff + ($dlyCount + 1) * 32     # first free byte in the section

        # Writes one DLL name, its hint/name entries and two thunk arrays. Returns the RVAs.
        function Add-Table($entry) {
            $nameOff = $cur
            WStr ($secRaw + $cur) "$($entry.Dll)"
            $cur = $cur + "$($entry.Dll)".Length + 1
            if ($cur % 2) { $cur++ }
            $thunks = New-Object 'System.Collections.Generic.List[object]'
            foreach ($n in @($entry.Names)) {
                if (-not $n) { continue }
                $hn = $cur
                WStr ($secRaw + $cur + 2) "$n"
                $cur = $cur + 2 + "$n".Length + 1
                if ($cur % 2) { $cur++ }
                $thunks.Add(@{ Rva = ($secRva + $hn); Ord = -1 })
            }
            foreach ($o in @($entry.Ordinals)) {
                if ($null -eq $o) { continue }
                $thunks.Add(@{ Rva = 0; Ord = [int]$o })
            }
            while ($cur % 8) { $cur++ }
            $arrays = @()
            foreach ($pass in 1, 2) {
                $arrOff = $cur
                foreach ($t in $thunks) {
                    $f = $secRaw + $cur
                    if ($t.Ord -ge 0) { W16 $f $t.Ord; $buf[$f + $stride - 1] = 0x80 }   # ordinal flag = top bit
                    else { W32 $f $t.Rva }
                    $cur = $cur + $stride
                }
                $cur = $cur + $stride             # zero terminator
                $arrays += ($secRva + $arrOff)
            }
            Set-Variable -Name cur -Value $cur -Scope 1
            return @{ NameRva = ($secRva + $nameOff); IntRva = $arrays[0]; IatRva = $arrays[1] }
        }

        $i = 0
        foreach ($e in @($Imports)) {
            $t = Add-Table $e
            $d = $secRaw + $impOff + ($i * 20)
            if (-not $e.NoOft) { W32 $d $t.IntRva }
            W32 ($d + 12) $t.NameRva
            W32 ($d + 16) $t.IatRva
            $i++
        }
        if ($impCount) { W32 ($dd + 8) ($secRva + $impOff); W32 ($dd + 12) (($impCount + 1) * 20) }

        $i = 0
        foreach ($e in @($DelayImports)) {
            $t = Add-Table $e
            $d = $secRaw + $dlyOff + ($i * 32)
            W32 $d 1                              # grAttrs: fields are RVAs
            W32 ($d + 4) $t.NameRva
            W32 ($d + 12) $t.IatRva
            W32 ($d + 16) $t.IntRva
            $i++
        }
        if ($dlyCount) { W32 ($dd + 104) ($secRva + $dlyOff); W32 ($dd + 108) (($dlyCount + 1) * 32) }

        [IO.File]::WriteAllBytes($Path, $buf)
    }

    $script:FixDir = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-pe-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:FixDir -Force | Out-Null

    $script:InjectImports = @(
        @{ Dll = 'KERNEL32.dll'; Names = @('VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'); Ordinals = @(7) }
        @{ Dll = 'KERNEL32.dll'; Names = @('ResumeThread') }
        @{ Dll = 'USER32.dll';   Names = @('MessageBoxW'); NoOft = $true }
    )
    $script:Delay = @( @{ Dll = 'ADVAPI32.dll'; Names = @('RegOpenKeyExW') } )

    $script:Pe64 = Join-Path $script:FixDir 'fixture64.exe'
    $script:Pe32 = Join-Path $script:FixDir 'fixture32.exe'
    New-TestPe -Path $script:Pe64 -Is64 $true  -Imports $script:InjectImports -DelayImports $script:Delay
    New-TestPe -Path $script:Pe32 -Is64 $false -Imports $script:InjectImports -DelayImports $script:Delay
}

AfterAll {
    if ($script:FixDir -and (Test-Path -LiteralPath $script:FixDir)) {
        Remove-Item -LiteralPath $script:FixDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Read-TcpkPe import contract' {
    It 'returns imports of a real shipped PE as DLL name strings' {
        $dll = Join-Path $script:ModuleRoot 'lib/Cecil/Mono.Cecil.dll'
        $pe = InModuleScope TCPK -Parameters @{ p = $dll } { param($p) Read-TcpkPe -Path $p }
        $pe | Should -Not -BeNullOrEmpty
        @($pe.Imports).Count | Should -BeGreaterThan 0
        @($pe.Imports)[0] | Should -BeOfType [string]
        @($pe.Imports) | Should -Contain 'mscoree.dll'
    }

    It 'lists import and delay-import DLL names of the <name> fixture' -ForEach @(
        @{ name = 'PE32+'; key = 'Pe64' }
        @{ name = 'PE32';  key = 'Pe32' }
    ) {
        $path = (Get-Variable -Name $key -Scope Script).Value
        $pe = InModuleScope TCPK -Parameters @{ p = $path } { param($p) Read-TcpkPe -Path $p }
        $pe | Should -Not -BeNullOrEmpty
        @($pe.Imports) | Should -Contain 'kernel32.dll'
        @($pe.Imports) | Should -Contain 'user32.dll'
        @($pe.DelayImports) | Should -Contain 'advapi32.dll'
    }
}

Describe 'Get-TcpkPeFunctionImports' {
    It 'returns the imported function of a real shipped PE' {
        $dll = Join-Path $script:ModuleRoot 'lib/Cecil/Mono.Cecil.dll'
        $fi = InModuleScope TCPK -Parameters @{ p = $dll } { param($p) Get-TcpkPeFunctionImports -Path $p }
        $fi | Should -Not -BeNullOrEmpty
        @($fi.Imported['mscoree.dll']) | Should -Contain '_CorDllMain'
    }

    Context 'on the <name> fixture' -ForEach @(
        @{ name = 'PE32+'; key = 'Pe64' }
        @{ name = 'PE32';  key = 'Pe32' }
    ) {
        BeforeAll {
            $path = (Get-Variable -Name $key -Scope Script).Value
            $script:Fi = InModuleScope TCPK -Parameters @{ p = $path } { param($p) Get-TcpkPeFunctionImports -Path $p }
        }
        It 'does not return null' {
            $script:Fi | Should -Not -BeNullOrEmpty
        }
        It 'reads imports by name and skips the import by ordinal' {
            $k = @($script:Fi.Imported['kernel32.dll'])
            $k | Should -Contain 'VirtualAllocEx'
            $k | Should -Contain 'WriteProcessMemory'
            $k | Should -Contain 'CreateRemoteThread'
        }
        It 'keeps the names of every descriptor that names the same DLL' {
            $k = @($script:Fi.Imported['kernel32.dll'])
            $k | Should -Contain 'ResumeThread'
            $k.Count | Should -Be 4
        }
        It 'reads a table that only has FirstThunk' {
            @($script:Fi.Imported['user32.dll']) | Should -Contain 'MessageBoxW'
        }
        It 'returns string arrays, not lists' {
            , $script:Fi.Imported['kernel32.dll'] | Should -BeOfType [string[]]
        }
        It 'reads the delay-import table' {
            @($script:Fi.DelayImported['advapi32.dll']) | Should -Contain 'RegOpenKeyExW'
        }
    }
}

Describe 'Get-TcpkPeFunctionImports FirstThunk fallback' {
    It 'keeps symbol-shaped names and drops bytes that are not a symbol' {
        $p = Join-Path $script:FixDir 'ftjunk.exe'
        New-TestPe -Path $p -Is64 $true -Imports @(
            @{ Dll = 'USER32.dll'; Names = @('MessageBoxW', "`tjunk name"); NoOft = $true }
        )
        $fi = InModuleScope TCPK -Parameters @{ p = $p } { param($p) Get-TcpkPeFunctionImports -Path $p }
        $u = @($fi.Imported['user32.dll'])
        $u | Should -Contain 'MessageBoxW'
        $u.Count | Should -Be 1
    }
    It 'does not apply that filter to an ordinary name table' {
        $p = Join-Path $script:FixDir 'oftnames.exe'
        New-TestPe -Path $p -Is64 $true -Imports @(
            @{ Dll = 'USER32.dll'; Names = @('MessageBoxW', "`tjunk name") }
        )
        $fi = InModuleScope TCPK -Parameters @{ p = $p } { param($p) Get-TcpkPeFunctionImports -Path $p }
        @($fi.Imported['user32.dll']).Count | Should -Be 2
    }
}

Describe 'Checks that depend on the import shape' {
    It 'Test-TcpkHollowingApis rates an imported injection sequence, not a string reference' {
        $dir = Join-Path $script:FixDir 'hollow'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item -LiteralPath $script:Pe64 -Destination (Join-Path $dir 'fixture64.exe')
        $f = InModuleScope TCPK -Parameters @{ dir = $dir } {
            param($dir)
            Mock Assert-TcpkWindows { return $true }
            Mock Test-TcpkIsFrameworkFile { return $false }
            @(Test-TcpkHollowingApis -Path $dir)
        }
        $hit = @($f | Where-Object { $_.RuleId -eq 'injection.dll-inject-apis' })
        $hit.Count | Should -Be 1
        $hit[0].Severity | Should -Be 'HIGH'
        $hit[0].Evidence | Should -Match 'imported: '
        $hit[0].Evidence | Should -Match 'CreateRemoteThread'
    }

    It 'Test-TcpkHollowingApis rates the APC pair INFO in a Chromium runtime, like the other two rules' {
        $dir = Join-Path $script:FixDir 'apc-chromium'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $p = Join-Path $dir 'helper.exe'
        New-TestPe -Path $p -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('QueueUserAPC', 'VirtualAllocEx') }
        )
        $tail = [Text.Encoding]::ASCII.GetBytes((' sandbox' * 60) + (' crashpad' * 15))
        $fs = [IO.File]::Open($p, 'Append')
        try { $fs.Write($tail, 0, $tail.Length) } finally { $fs.Dispose() }
        $f = InModuleScope TCPK -Parameters @{ dir = $dir } {
            param($dir)
            Mock Assert-TcpkWindows { return $true }
            Mock Test-TcpkIsFrameworkFile { return $false }
            @(Test-TcpkHollowingApis -Path $dir)
        }
        $apc = @($f | Where-Object { $_.RuleId -eq 'injection.apc-inject-apis' })
        $apc.Count | Should -Be 1
        $apc[0].Severity | Should -Be 'INFO'
    }

    It 'Test-TcpkHollowingApis still rates the APC pair HIGH outside a Chromium runtime' {
        $dir = Join-Path $script:FixDir 'apc-plain'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        New-TestPe -Path (Join-Path $dir 'tool.exe') -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('QueueUserAPC', 'VirtualAllocEx') }
        )
        $f = InModuleScope TCPK -Parameters @{ dir = $dir } {
            param($dir)
            Mock Assert-TcpkWindows { return $true }
            Mock Test-TcpkIsFrameworkFile { return $false }
            @(Test-TcpkHollowingApis -Path $dir)
        }
        $apc = @($f | Where-Object { $_.RuleId -eq 'injection.apc-inject-apis' })
        $apc.Count | Should -Be 1
        $apc[0].Severity | Should -Be 'HIGH'
    }

    It 'Test-TcpkPacker reports a licensing wrapper runtime named in the import table' {
        $dir = Join-Path $script:FixDir 'drm'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        New-TestPe -Path (Join-Path $dir 'wrapped.exe') -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('ExitProcess') }
            @{ Dll = 'WibuCm64.dll'; Names = @('CmAccess2') }
        )
        $f = InModuleScope TCPK -Parameters @{ dir = $dir } {
            param($dir)
            Mock Assert-TcpkWindows { return $true }
            @(Test-TcpkPacker -Path $dir)
        }
        $hit = @($f | Where-Object { $_.RuleId -eq 'packer.licensing-drm' })
        $hit.Count | Should -Be 1
        $hit[0].Evidence | Should -Match 'wibucm64\.dll'
    }

    It 'Test-TcpkPacker also sees a licensing runtime that is delay-loaded' {
        $dir = Join-Path $script:FixDir 'drm-delay'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        New-TestPe -Path (Join-Path $dir 'wrapped.exe') -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('ExitProcess') }
        ) -DelayImports @( @{ Dll = 'hasp_windows_x64.dll'; Names = @('hasp_login') } )
        $f = InModuleScope TCPK -Parameters @{ dir = $dir } {
            param($dir)
            Mock Assert-TcpkWindows { return $true }
            @(Test-TcpkPacker -Path $dir)
        }
        @($f | Where-Object { $_.RuleId -eq 'packer.licensing-drm' }).Count | Should -Be 1
    }

    It 'Test-TcpkVendorDriverAcl confirms a kernel image by its kernel import' -Skip:($env:OS -ne 'Windows_NT') {
        $dir = Join-Path $script:FixDir 'drv'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        New-TestPe -Path (Join-Path $dir 'tcpkfixture.sys') -Is64 $true -Subsystem 1 -Imports @(
            @{ Dll = 'ntoskrnl.exe'; Names = @('IoCreateDevice', 'IofCompleteRequest') }
        )
        $f = @(Test-TcpkVendorDriverAcl -Path $dir)
        @($f | Where-Object { $_.RuleId -eq 'driver.kernel-pe-confirmed' }).Count | Should -Be 1
    }

    It 'Get-TcpkDependencyTree lists the imports and classifies them' -Skip:($env:OS -ne 'Windows_NT') {
        $dir = Join-Path $script:FixDir 'tree'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $exe = Join-Path $dir 'app.exe'
        New-TestPe -Path $exe -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('ExitProcess') }
            @{ Dll = 'api-ms-win-core-synch-l1-2-0.dll'; Names = @('Sleep') }
            @{ Dll = 'tcpk-no-such-module.dll'; Names = @('Nothing') }
        )
        $nodes = @(Get-TcpkDependencyTree -Path $exe -MaxDepth 1)
        $nodes.Count | Should -Be 3
        $k = $nodes | Where-Object { $_.DllName -eq 'kernel32.dll' }
        $k.Status | Should -Be 'FOUND-SYSTEM32'
        $k.HijackRisk | Should -Be 'NONE'
        $a = $nodes | Where-Object { $_.DllName -like 'api-ms-*' }
        $a.Status | Should -Be 'API-SET'
        $a.HijackRisk | Should -Be 'NONE'
        $m = $nodes | Where-Object { $_.DllName -eq 'tcpk-no-such-module.dll' }
        $m.Status | Should -Be 'MISSING'
        $m.HijackRisk | Should -Be 'HIGH'
    }

    It 'Get-TcpkDependencyTree survives an import name that cannot be a file name' -Skip:($env:OS -ne 'Windows_NT') {
        # On .NET Framework Path.Combine throws on such a name, which used to end the walk.
        $dir = Join-Path $script:FixDir 'tree-badname'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $exe = Join-Path $dir 'app.exe'
        New-TestPe -Path $exe -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('ExitProcess') }
            @{ Dll = 'bad|name.dll'; Names = @('Nothing') }
        )
        $nodes = @(Get-TcpkDependencyTree -Path $exe -MaxDepth 1)
        $nodes.Count | Should -Be 2
        ($nodes | Where-Object { $_.DllName -eq 'bad|name.dll' }).Status | Should -Be 'MISSING'
    }
}

# A PE image is not always called .exe or .dll. Every binary check walks Get-TcpkPeFiles, so a
# type missing from its list is invisible to all of them at once.
Describe 'Get-TcpkPeFiles enumeration' {
    BeforeAll {
        $script:EnumDir = Join-Path $script:FixDir 'enum'
        New-Item -ItemType Directory -Path $script:EnumDir -Force | Out-Null
        foreach ($n in 'app.exe', 'lib.dll', 'control.ocx', 'package.bpl', 'panel.cpl', 'saver.scr',
                       'filter.ax', 'addin.xll', 'UPPER.OCX', 'app.exe.deploy', 'lib.dll.deploy') {
            Copy-Item -LiteralPath $script:Pe64 -Destination (Join-Path $script:EnumDir $n)
        }
        foreach ($n in 'notes.txt', 'settings.xml.deploy', 'data.bin', 'x.deploy') {
            Set-Content -LiteralPath (Join-Path $script:EnumDir $n) -Value 'not a PE'
        }
        $script:EnumNames = InModuleScope TCPK -Parameters @{ d = $script:EnumDir } {
            param($d) @(Get-TcpkPeFiles -Path $d | ForEach-Object { $_.Name })
        }
    }

    It 'returns the PE image <name>' -ForEach @(
        @{ name = 'app.exe' }, @{ name = 'lib.dll' }, @{ name = 'control.ocx' }, @{ name = 'package.bpl' }
        @{ name = 'panel.cpl' }, @{ name = 'saver.scr' }, @{ name = 'filter.ax' }, @{ name = 'addin.xll' }
        @{ name = 'UPPER.OCX' }, @{ name = 'app.exe.deploy' }, @{ name = 'lib.dll.deploy' }
    ) {
        $script:EnumNames | Should -Contain $name
    }

    It 'does not return <name>' -ForEach @(
        @{ name = 'notes.txt' }, @{ name = 'settings.xml.deploy' }, @{ name = 'data.bin' }, @{ name = 'x.deploy' }
    ) {
        $script:EnumNames | Should -Not -Contain $name
    }

    It 'lets the side-load check read an ActiveX control' {
        $dir = Join-Path $script:FixDir 'ocx-sideload'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        New-TestPe -Path (Join-Path $dir 'control.ocx') -Is64 $true -Imports @(
            @{ Dll = 'KERNEL32.dll'; Names = @('ExitProcess') }
            @{ Dll = 'VERSION.dll';  Names = @('GetFileVersionInfoW') }
        )
        $f = @(Test-TcpkDllSideload -Path $dir)
        @($f | Where-Object { $_.RuleId -eq 'dllsearch.sideload-candidate' -and "$($_.Evidence)$($_.Title)" -match 'version\.dll' }).Count | Should -BeGreaterThan 0
    }

    It 'lets a binary check read an ActiveX control' {
        $dir = Join-Path $script:FixDir 'ocx-only'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item -LiteralPath $script:Pe64 -Destination (Join-Path $dir 'control.ocx')
        $f = @(Test-TcpkPeMitigations -Path $dir)
        @($f | Where-Object { "$($_.File)" -like '*control.ocx' }).Count | Should -BeGreaterThan 0
    }
}
