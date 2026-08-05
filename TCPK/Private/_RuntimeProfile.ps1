# CAP4 - Runtime/platform profile.
#
# An identical observation can be a defect on one runtime and structurally
# unavoidable on another.  RWX memory in a V8 JIT process is expected; in a
# native-win32 service it is unexplained.  Missing CFG on an Electron app is a
# platform limitation (V8 does not emit CFG guards); on a native C++ service it
# is a fixable build flag.
#
# Rules resolve a profile once per target and ask it questions rather than
# hard-coding runtime assumptions.

$script:TcpkPlatformData = [ordered]@{
    'electron' = @{
        # Behaviors that are structurally expected for this runtime.
        ExpectedBehaviors = @(
            'rwx-for-jit',             # V8 JIT generates code into RWX pages
            'dynamic-code-gen',        # V8 generates and patches native code at runtime
            'v8-snapshot-exec'         # v8_context_snapshot.bin is mapped and executed
        )
        CanEnable = @{
            'aslr'                      = $true    # the PE header can have ASLR bit set
            'dep'                       = $true    # NX bit on the PE; V8 still maps RWX pages
            'cfg'                       = $false   # V8 does not emit CFG guards -- platform limitation
            'authenticode'              = $true
            'seh'                       = $false   # Electron renderer uses a different exception model
            'write-protect-code-memory' = $true    # V8 flag --write-protect-code-memory
            'jitless'                   = $true    # V8 flag --jitless (breaks most apps)
        }
        PlatformLimitations = @(
            "cfg: V8 does not emit Control Flow Guard checks; not achievable for the renderer",
            "seh: structured exception handling is replaced by Chromium's crash handler in the renderer"
        )
    }
    'dotnet' = @{
        ExpectedBehaviors = @(
            'rwx-for-jit',        # CLR JIT maps hot methods into RWX pages
            'dynamic-code-gen'    # System.Reflection.Emit and expression trees compile at runtime
        )
        CanEnable = @{
            'aslr'         = $true
            'dep'          = $true
            'cfg'          = $true    # RyuJIT emits CFG checks when compiled with /guard:cf
            'authenticode' = $true
            'seh'          = $true
        }
        PlatformLimitations = @()
    }
    'java' = @{
        ExpectedBehaviors = @(
            'rwx-for-jit',        # HotSpot JIT code cache uses RWX or RX/RW pair
            'dynamic-code-gen'
        )
        CanEnable = @{
            'aslr'         = $true    # for the JVM launcher PE
            'dep'          = $true
            'cfg'          = $false   # HotSpot JIT does not emit CFG guards
            'authenticode' = $true    # for the JVM launcher PE
            'seh'          = $false
        }
        PlatformLimitations = @(
            "cfg: HotSpot JIT does not emit Control Flow Guard checks"
        )
    }
    'python' = @{
        ExpectedBehaviors = @('dynamic-code-gen')
        CanEnable = @{
            'aslr'         = $true
            'dep'          = $true
            'cfg'          = $false
            'authenticode' = $true
            'seh'          = $false
        }
        PlatformLimitations = @(
            "cfg: CPython does not emit Control Flow Guard checks"
        )
    }
    'native-win32' = @{
        ExpectedBehaviors = @()
        CanEnable = @{
            'aslr'         = $true
            'dep'          = $true
            'cfg'          = $true
            'authenticode' = $true
            'seh'          = $true
        }
        PlatformLimitations = @()
    }
    'unknown' = @{
        ExpectedBehaviors = @()
        CanEnable = @{
            'aslr'         = $true
            'dep'          = $true
            'cfg'          = $true
            'authenticode' = $true
        }
        PlatformLimitations = @()
    }
}

function Get-TcpkRuntimeProfile {
<#
.SYNOPSIS
    CAP4 - Resolve a runtime/platform profile for a scan target.

.DESCRIPTION
    When -RuntimeClass is given the registry entry is returned directly (useful
    in tests and when the caller has already detected the runtime).  When -Path
    is given the function probes the directory for Electron, .NET, Java, and
    Python markers and falls back to native-win32.

.OUTPUTS
    [PSCustomObject] with RuntimeClass, ExpectedBehaviors, CanEnable, PlatformLimitations
#>
    [CmdletBinding()]
    param(
        [string]$Path = '',
        [ValidateSet('electron','dotnet','java','python','native-win32','unknown')]
        [string]$RuntimeClass = ''
    )

    if (-not $RuntimeClass -and $Path) {
        $RuntimeClass = _Resolve-TcpkRuntimeClass -Path $Path
    }
    if (-not $RuntimeClass) { $RuntimeClass = 'unknown' }

    $data = $script:TcpkPlatformData[$RuntimeClass]
    return [pscustomobject]@{
        RuntimeClass        = $RuntimeClass
        ExpectedBehaviors   = $data.ExpectedBehaviors
        CanEnable           = $data.CanEnable
        PlatformLimitations = $data.PlatformLimitations
    }
}

function _Resolve-TcpkRuntimeClass {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        return 'unknown'
    }
    $files = try { Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue } catch { @() }

    # Electron: app.asar or v8_context_snapshot.bin or chrome_*.pak present
    if ($files | Where-Object { $_.Name -in @('app.asar','v8_context_snapshot.bin') -or $_.Name -like 'chrome_*.pak' } | Select-Object -First 1) {
        return 'electron'
    }
    # Java: jvm.dll or standard JRE structure
    if ($files | Where-Object { $_.Name -eq 'jvm.dll' -or $_.Extension -eq '.jar' } | Select-Object -First 1) {
        return 'java'
    }
    # Python: python3x.dll or pythonXX.dll
    if ($files | Where-Object { $_.Name -match '^python\d+\.dll$' } | Select-Object -First 1) {
        return 'python'
    }
    # .NET: .dll with .NET metadata (check for a .deps.json or .runtimeconfig.json as a proxy)
    if ($files | Where-Object { $_.Name -like '*.deps.json' -or $_.Name -like '*.runtimeconfig.json' } | Select-Object -First 1) {
        return 'dotnet'
    }
    return 'native-win32'
}

function Test-TcpkPlatformExpects {
<#
.SYNOPSIS
    CAP4 - Ask a platform profile whether a behavior is expected for this runtime.

    Returns $true when the behavior is structurally unavoidable or well-documented
    for the detected runtime, so rules can avoid escalating it to HIGH.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Profile,
        [Parameter(Mandatory)][string]$Behavior
    )
    return $Profile.ExpectedBehaviors -contains $Behavior
}

function Test-TcpkPlatformCanEnable {
<#
.SYNOPSIS
    CAP4 - Ask whether a hardening feature CAN be enabled on this platform.

    Returns $false when the feature is architecturally impossible for this runtime
    (e.g. CFG on Electron).  A missing feature that CANNOT be enabled is a platform
    limitation, not an application defect; report it at INFO.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Profile,
        [Parameter(Mandatory)][string]$Feature
    )
    $ce = $Profile.CanEnable
    if ($null -eq $ce) { return $true }   # unknown: conservative default
    if (-not $ce.ContainsKey($Feature)) { return $true }
    return [bool]$ce[$Feature]
}

function Get-TcpkPlatformLimitations {
<#
.SYNOPSIS
    CAP4 - Return the list of hardening features this platform cannot enable.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Profile)
    return @($Profile.PlatformLimitations)
}
