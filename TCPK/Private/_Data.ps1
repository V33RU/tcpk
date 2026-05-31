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
$script:TcpkFrameworkPrefixes = @(
    'Microsoft.','System.','WinRT.','Windows.','Azure.','BouncyCastle.',
    'CommunityToolkit.','DotNext.','ExCSS.','HarfBuzzSharp.','SkiaSharp.',
    'Json.More.','JsonPath.','Newtonsoft.','Aptabase.','Mono.','NuGet.',
    'McMaster.','Polly.','Serilog.','log4net.','NLog.','OpenTelemetry.',
    'Google.','Grpc.','MessagePack.','protobuf-net.','xunit.','Castle.'
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
