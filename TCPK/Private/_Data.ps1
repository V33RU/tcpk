# Loads + caches rule data from TCPK\Data\*.json.

$script:TcpkDataCache = $null

function Get-TcpkData {
    [CmdletBinding()] param([switch]$Force)
    if ($script:TcpkDataCache -and -not $Force) { return $script:TcpkDataCache }
    $path = Join-Path $script:TcpkRoot 'Data\secrets.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "TCPK data file not found: $path"
    }
    $script:TcpkDataCache = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    return $script:TcpkDataCache
}

# Common framework-noise prefixes - checks skip files starting with these
# unless told otherwise (cuts hundreds of false positives in .NET apps).
#
# MATCHING: StartsWith(prefix, OrdinalIgnoreCase) against the file NAME INCLUDING its
# extension, so a prefix ending in '.' matches both Foo.dll and Foo.Bar.dll (the extension
# supplies the dot for the bare case). A family that puts a token before the first dot
# therefore needs each name spelling out, which is why the UIAutomation entries below are
# listed individually rather than as a bare 'UIAutomation' prefix.
#
# THE COST OF A WRONG ENTRY IS ASYMMETRIC, so read this before adding one. A missing prefix
# produces noise: a third-party assembly's crypto, deserialization and P/Invoke surface gets
# attributed to the vendor, which is what put a CRITICAL on EntityFramework.dll. A prefix
# that is too broad produces SILENCE: a vendor assembly whose name happens to start with it
# is skipped at every one of the 84 call sites that consult this list, and a real finding is
# never emitted. Noise is visible and silence is not, so an entry must be a name no vendor
# would plausibly give their own assembly.
#
# Entries rejected on exactly that test, recorded so they are not proposed again:
#   'DocumentFormat.'  two generic English words; a vendor's DocumentFormat.Export.dll dies
#   'Prism.'           very common in enterprise WPF, but also a plausible product name
#   'Unity.'           collides with the DI container, the game engine and any vendor name
#   'Fluent.'          Fluent.Ribbon ships as Fluent.dll, but "Fluent" is a vendor word
#   'C1.'              ComponentOne; two characters is far too broad
#   'Squirrel.'        would delete the updater finding class that Test-TcpkUpdateFlow exists
#                      to produce; squirrel.exe is handled by TcpkRuntimeHelperExes instead
#   'Interop.'         tlbimp wrappers are generated FROM the vendor's own type library and
#                      are exactly where the COM surface lives; Test-TcpkComInterop needs them
# DO NOT MERGE THIS WITH $script:TcpkFxAsmSkip IN _ManagedCve.ps1.
# The overlap is real and the temptation to unify them is understandable, but they answer
# two different questions and merging would create a silent blind spot:
#
#   THIS list   - "did the vendor WRITE this code?"  Consulted by 84 checks that look for
#                 code patterns (crypto misuse, deserialization, TLS, reflection, P/Invoke).
#                 EntityFramework is here because its code is Microsoft's, not the vendor's.
#
#   TcpkFxAsmSkip - "does this component have its OWN CVE feed?"  Consulted by
#                 Get-TcpkManagedNugetComponents, which feeds OSV version matching.
#                 EntityFramework is deliberately NOT there, because EF6 is a real NuGet
#                 package with published CVEs and shipping a vulnerable version of it IS
#                 the vendor's problem.
#
# So a third-party library is simultaneously "not their code" (skip the pattern checks) and
# "their dependency" (keep the version check). Folding the lists together would take one of
# those two behaviours away from every entry, and losing the second one means a known-
# vulnerable bundled library stops being reported at all.
$script:TcpkFrameworkPrefixes = @(
    'Microsoft.','System.','WinRT.','Windows.','Azure.','BouncyCastle.',
    'CommunityToolkit.','DotNext.','ExCSS.','HarfBuzzSharp.','SkiaSharp.',
    'Json.More.','JsonPath.','Newtonsoft.','Aptabase.','Mono.','NuGet.',
    'McMaster.','Polly.','Serilog.','log4net.','NLog.','OpenTelemetry.',
    'Google.','Grpc.','MessagePack.','protobuf-net.','xunit.','Castle.',

    # Runtime and WPF/WinForms assemblies that are framework code but start with neither
    # System. nor Microsoft., so nothing above caught them. $script:TcpkFxAsmSkip in
    # _ManagedCve.ps1 already classified most of these as framework; this list did not,
    # and two lists in one module disagreeing about what the vendor wrote is the actual
    # defect being fixed here. All names are framework-reserved, so none can shadow a
    # vendor assembly.
    'mscorlib.','netstandard.','WindowsBase.',
    'PresentationCore.','PresentationFramework.','PresentationUI.',
    'ReachFramework.','Accessibility.','WindowsFormsIntegration.','stdole.',
    # Listed one by one on purpose: these put a token before the first dot, so the bare
    # prefix 'UIAutomation.' matches none of them and an undotted 'UIAutomation' would
    # swallow a vendor's UIAutomationHelper.dll.
    'UIAutomationClient.','UIAutomationTypes.','UIAutomationProvider.',
    'UIAutomationClientsideProviders.',

    # Third-party packages that genuinely ship inside .NET desktop applications. Each is a
    # distinctive vendor or project name, so the false-negative risk above is negligible.
    'EntityFramework.','SQLitePCLRaw.','Dapper.','AutoMapper.','Autofac.',
    'ICSharpCode.','NAudio.','RestSharp.','Npgsql.','Renci.','Hardcodet.',
    'Xceed.','MahApps.','MaterialDesignThemes.','MaterialDesignColors.',
    'DevExpress.','Telerik.','Syncfusion.'
)

function Test-TcpkIsFrameworkFile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    foreach ($p in $script:TcpkFrameworkPrefixes) {
        if ($Name.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Bundled NATIVE third-party libraries (lowercase 'lib*', C runtimes, browser/
# graphics/ML runtimes). These ship inside .NET apps but are not first-party
# code, so behavioral static checks (named objects, ETW, etc.) should skip them
# to avoid attributing a well-known library's behavior to the target app.
$script:TcpkNativeNoise = @(
    'libGLESv2','libEGL','libSkiaSharp','libHarfBuzzSharp','libusb','libcrypto','libssl','libsodium',
    'WebView2Loader','vcruntime','msvcp','msvcr','ucrtbase','concrt','vccorlib','mfc',
    'd3dcompiler','d3d12','d3d11','dxil','dxcompiler','vulkan-1','libcef','ffmpeg',
    'icudt','icuuc','icuin','icu','api-ms-win','clrjit','coreclr','clrgc','hostfxr','hostpolicy',
    'mscordaccore','mscordbi','clretwrc','createdump','sni','onnxruntime','tensorflow','opencv'
)
function Test-TcpkIsNativeNoise {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    foreach ($n in $script:TcpkNativeNoise) {
        if ($Name.StartsWith($n, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Runtime helper executables shipped BY the Electron/Squirrel/NSIS packaging, not authored
# by the vendor (the UAC elevate shim, the Squirrel updater, the crash handler, ...).
$script:TcpkRuntimeHelperExes = @(
    'elevate.exe', 'squirrel.exe', 'update.exe', 'crashpad_handler.exe',
    'chrome_crashpad_handler.exe', 'notification_helper.exe', 'stub.exe'
)

# Is this file the app's OWN (first-party) code, or bundled runtime / framework / installer /
# license text that ships INSIDE the app but the vendor did not write? Behavioural, string,
# secret and import scans MUST NOT attribute a bundled component's contents to the target app
# -- that is the #1 false-positive source on Electron apps (a match inside Chromium / Electron /
# NSIS / a license file reported as first-party). Pass $Text (the file's decoded string view)
# when you have it so the ELECTRON MAIN EXE -- named after the app but actually the Electron
# runtime -- is caught by its embedded Chromium+Electron signature, not merely by name.
# Returns $false for a bundled/runtime/installer/license file; $true for genuine app code.
function Test-TcpkIsFirstParty {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [long]$SizeBytes = 0, [string]$Text, [string]$Path)
    if (Test-TcpkIsFrameworkFile $Name)                     { return $false }   # .NET BCL / SDK
    if (Test-TcpkIsNativeNoise    $Name)                    { return $false }   # bundled native libs
    if (Test-TcpkIsChromiumRuntime -Name $Name -Text $Text) { return $false }   # Chromium/Electron runtime (by name / signature)
    $lower = $Name.ToLowerInvariant()
    if ($script:TcpkRuntimeHelperExes -contains $lower)     { return $false }   # elevate/squirrel/crash helpers
    # NSIS installer / uninstaller scaffolding (by name and by the Nullsoft content marker)
    if ($lower -match '^(uninstall|un[_-]?install|setup|install|nsis)' -and $lower.EndsWith('.exe')) { return $false }
    if ($Text -and $Text -match 'Nullsoft\.?\s*Install\s*System|NullsoftInst') { return $false }
    # third-party licence / notice / credits text (not first-party secrets or strings)
    if ($lower -match '^(licenses?|license|notice|third[-_ ]?party|credits|copyright)' -or $lower -match 'licenses?\.(chromium|electron)') { return $false }
    # A very large PE is a statically-linked runtime (the Electron / Chromium / CEF main
    # binary), NOT first-party code -- the app's own exe/dll is small, but the Electron main
    # exe (named after the app) is ~200 MB with its Chromium markers ~180 MB in, too far to
    # scan cheaply. Size is the reliable, O(1) signal that it is the runtime, not the app.
    if ($SizeBytes -gt 80MB -and ($lower.EndsWith('.exe') -or $lower.EndsWith('.dll'))) { return $false }
    # Electron packaging (STRUCTURAL, no content read): a loose PE at the app ROOT -- the folder
    # that also holds resources\app.asar -- is the Electron runtime / a bundled Chromium binary,
    # not first-party code (the app's own code is the JS INSIDE app.asar). Catches small bundled
    # DLLs the size + name checks miss, and confirms the main exe without reading 200 MB.
    if ($Path -and ($lower.EndsWith('.exe') -or $lower.EndsWith('.dll') -or $lower.EndsWith('.node'))) {
        try {
            $parent = Split-Path -Parent $Path
            if ($parent -and ((Test-Path -LiteralPath (Join-Path $parent 'resources\app.asar')) -or (Test-Path -LiteralPath (Join-Path $parent 'app.asar')))) { return $false }
        } catch { }
    }
    return $true
}
