# NVD (National Vulnerability Database) online CVE lookup for NATIVE libraries by CPE.
#
# WHY NVD, not OSV, for native C libs: OSV keys native results to DISTRO packages (Alpine /
# Debian / RHEL advisories) that are versioned per-distro, not by the upstream library version,
# so a bundled libcrypto returns a firehose of mis-versioned advisories. NVD is CPE-based
# (cpe:2.3:a:openssl:openssl:<version>) and version-accurate.
#
# ACCURACY RULE (critical): NVD's cpeName query over-returns -- old CVEs whose CPE has NO
# version bound (versionEnd*) match every version, so a current, patched lib looks vulnerable.
# We therefore flag a CVE ONLY when a matching vendor:product node has a real END bound and the
# shipped version falls inside [start, end). Unbounded / wildcard matches are dropped.
#
# PRIVACY: sends ONLY a public CPE (vendor + product + version) to NVD -- never findings,
# secrets, file contents, or the target name. Opt-in (fires only when -OnlineCve is set).

$script:TcpkNvdUri = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Native DLL/lib basename (lowercased, de-suffixed) -> NVD @(vendor, product). Only libraries
# with a stable, well-known CPE are mapped; an unmapped lib is skipped (no guess = no noise).
$script:TcpkNvdCpe = @{
    # crypto / TLS
    'openssl'    = @('openssl','openssl');      'libcrypto' = @('openssl','openssl'); 'libssl' = @('openssl','openssl')
    'libssh2'    = @('libssh2','libssh2');       'libssh'   = @('libssh','libssh')
    'nettle'     = @('nettle_project','nettle'); 'gnutls'   = @('gnu','gnutls')
    'mbedtls'    = @('arm','mbed_tls');          'wolfssl'  = @('wolfssl','wolfssl')
    # compression
    'zlib'       = @('zlib','zlib');            'zlib1'     = @('zlib','zlib')
    'bzip2'      = @('bzip','bzip2');            'libbz2'   = @('bzip','bzip2')
    'lzma'       = @('tukaani','xz');            'liblzma'  = @('tukaani','xz');        'xz' = @('tukaani','xz')
    'zstd'       = @('facebook','zstandard');    'libzstd'  = @('facebook','zstandard')
    'lz4'        = @('lz4_project','lz4');        'brotli'   = @('google','brotli')
    # database
    'sqlite'     = @('sqlite','sqlite');        'sqlite3'   = @('sqlite','sqlite'); 'e_sqlite3' = @('sqlite','sqlite'); 'winsqlite3' = @('sqlite','sqlite')
    # xml / parsing
    'libxml2'    = @('xmlsoft','libxml2');        'libxslt'  = @('xmlsoft','libxslt')
    'expat'      = @('libexpat_project','libexpat'); 'libexpat' = @('libexpat_project','libexpat')
    'pcre'       = @('pcre','pcre')
    # imaging / fonts / media
    'freetype'   = @('freetype','freetype');    'freetype6' = @('freetype','freetype')
    'libwebp'    = @('webmproject','libwebp');    'libvpx'  = @('webmproject','libvpx')
    'libpng'     = @('libpng','libpng');          'libpng16' = @('libpng','libpng'); 'libpng15' = @('libpng','libpng'); 'libpng12' = @('libpng','libpng')
    'libtiff'    = @('libtiff','libtiff');        'tiff'    = @('libtiff','libtiff')
    'libjpeg'    = @('libjpeg-turbo','libjpeg-turbo'); 'jpeg' = @('libjpeg-turbo','libjpeg-turbo'); 'turbojpeg' = @('libjpeg-turbo','libjpeg-turbo')
    'harfbuzz'   = @('harfbuzz_project','harfbuzz')
    'openjpeg'   = @('uclouvain','openjpeg')
    'ffmpeg'     = @('ffmpeg','ffmpeg');          'avcodec' = @('ffmpeg','ffmpeg'); 'avformat' = @('ffmpeg','ffmpeg')
    # networking / serialization
    'curl'       = @('haxx','curl');             'libcurl' = @('haxx','libcurl')
    'nghttp2'    = @('nghttp2','nghttp2');         'cares'  = @('c-ares_project','c-ares'); 'libcares' = @('c-ares_project','c-ares')
    'protobuf'   = @('google','protobuf');        'libprotobuf' = @('google','protobuf')
    'jansson'    = @('jansson_project','jansson')
}

# Native DLL basename -> NVD @(vendor, product). Tries the de-suffixed name, then progressively
# strips a trailing version tail (libpng16 -> libpng, libssl-3 -> libssl) so ABI-versioned names
# still map. An unmapped lib returns $null (no guess = no false positive).
function Get-TcpkNvdCpe {
    [CmdletBinding()] param([string]$Name)
    $base = "$Name".ToLowerInvariant() -replace '\.(dll|so|dylib)$','' -replace '_x64$|-x64$|_x86$|-x86$',''
    $cands = New-Object System.Collections.Generic.List[string]
    $cands.Add($base)
    $cands.Add(($base -replace '-\d.*$',''))     # libssl-3-x64 -> libssl
    $cands.Add(($base -replace '(32|64)$',''))
    # NB: no generic trailing-digit strip -- it would wrongly collapse distinct products whose
    # name ends in a digit (pcre2 -> pcre, nghttp2 -> nghttp, libxml2 -> libxml). ABI-versioned
    # names without a dash (libpng16) are handled by explicit keys instead.
    foreach ($c in $cands) { if ($c -and $script:TcpkNvdCpe.ContainsKey($c)) { return $script:TcpkNvdCpe[$c] } }
    return $null
}

# Embedded version-string patterns, keyed by NVD product. Used when a native DLL that maps to a
# CPE has NO usable FileVersion (common) -- the library stamps its version into a banner string
# (e.g. "OpenSSL 3.0.21 ..."), which is the authoritative version. The library NAME must be
# adjacent to the number, so this stays low-false-positive.
$script:TcpkNativeVerRx = @{
    'openssl'  = 'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)'
    'sqlite'   = 'SQLite\s+(?:version\s+)?(\d+\.\d+\.\d+)'
    'zlib'     = '(?:in|de)flate\s+(\d+\.\d+\.\d+(?:\.\d+)?)\s+Copyright'
    'libpng'   = 'libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)'
    'curl'     = 'libcurl/(\d+\.\d+\.\d+)'
    'libcurl'  = 'libcurl/(\d+\.\d+\.\d+)'
    'freetype' = 'FreeType\s+(\d+\.\d+\.\d+)'
}
function Get-TcpkNativeLibVersionString {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Product)
    $rx = $script:TcpkNativeVerRx["$Product"]; if (-not $rx) { return $null }
    $t = $null; try { $t = Read-TcpkAllText -Path $Path } catch { }
    if (-not $t) { return $null }
    $m = [regex]::Match($t, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

# Is $Shipped inside the vulnerable range described by a cpeMatch node? Requires a real END
# bound -- an open-ended / wildcard match is treated as NOT a reliable version hit (returns $false).
function Test-TcpkNvdInRange {
    [CmdletBinding()] param([string]$Shipped, $CpeMatch)
    $endEx = "$($CpeMatch.versionEndExcluding)"; $endIn = "$($CpeMatch.versionEndIncluding)"
    if (-not $endEx -and -not $endIn) { return $false }   # no upper bound -> unreliable, drop
    $stIn = "$($CpeMatch.versionStartIncluding)"; $stEx = "$($CpeMatch.versionStartExcluding)"
    if ($stIn -and (Test-TcpkSemVerLt -A $Shipped -B $stIn)) { return $false }                 # shipped < startIncluding
    if ($stEx -and (-not (Test-TcpkSemVerLt -A $stEx -B $Shipped))) { return $false }          # shipped <= startExcluding
    if ($endEx) { return (Test-TcpkSemVerLt -A $Shipped -B $endEx) }                           # shipped < endExcluding
    if ($endIn) { return (-not (Test-TcpkSemVerLt -A $endIn -B $Shipped)) }                    # shipped <= endIncluding
    return $false
}

# NETWORK (opt-in). Query NVD by CPE for each native component; return version-accurate matches.
# Rate limits: NVD allows ~5 requests / 30s anonymous, 50 / 30s with an API key (env NVD_API_KEY).
# We sleep between requests to stay under the anonymous limit; a small native inventory is a few
# requests. Failures are non-fatal (warn + return what we have) so the offline catalog still stands.
function Get-TcpkNvdMatches {
    [CmdletBinding()]
    param([object[]]$Components, [int]$TimeoutSec = 25, [string]$ApiKey = $env:NVD_API_KEY)
    $out = New-Object System.Collections.Generic.List[object]
    $seenReq = 0
    foreach ($comp in @($Components)) {
        $ver = "$($comp.Version)"; if ($ver -notmatch '^\d+\.\d+') { continue }
        $cpe = Get-TcpkNvdCpe $comp.Name; if (-not $cpe) { continue }
        $vendor = $cpe[0]; $product = $cpe[1]
        $cpeName = "cpe:2.3:a:${vendor}:${product}:${ver}:*:*:*:*:*:*:*"
        if ($seenReq -gt 0) { Start-Sleep -Seconds $(if ($ApiKey) { 1 } else { 6 }) }   # rate limit
        $seenReq++
        $headers = @{}; if ($ApiKey) { $headers['apiKey'] = $ApiKey }
        $uri = $script:TcpkNvdUri + '?cpeName=' + [uri]::EscapeDataString($cpeName)
        $resp = $null
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec $TimeoutSec -ErrorAction Stop
        } catch {
            Write-Warning "NVD online query for $product@$ver failed ($($_.Exception.Message)); keeping the offline catalog result only."
            continue
        }
        foreach ($v in @($resp.vulnerabilities)) {
            $id = "$($v.cve.id)"; if (-not $id) { continue }
            $bounded = $false; $fixed = ''
            foreach ($cfg in @($v.cve.configurations)) { foreach ($n in @($cfg.nodes)) { foreach ($cm in @($n.cpeMatch)) {
                if ("$($cm.criteria)" -notmatch ":a:${vendor}:${product}:") { continue }
                if (Test-TcpkNvdInRange -Shipped $ver -CpeMatch $cm) { $bounded = $true; if ("$($cm.versionEndExcluding)") { $fixed = "$($cm.versionEndExcluding)" } }
            }}}
            if (-not $bounded) { continue }   # only version-accurate, bounded matches
            $sev = ''
            try { $sev = "$((@($v.cve.metrics.cvssMetricV31)[0]).cvssData.baseSeverity)" } catch { }
            if (-not $sev) { try { $sev = "$((@($v.cve.metrics.cvssMetricV30)[0]).cvssData.baseSeverity)" } catch { } }
            $title = ''
            try { $title = "$((@($v.cve.descriptions | Where-Object { $_.lang -eq 'en' })[0]).value)" } catch { }
            if ($title.Length -gt 160) { $title = $title.Substring(0,160) + '...' }
            $out.Add([pscustomobject]@{
                Cve = $id; Package = $product; ShippedVersion = $ver; FixedVersion = $fixed
                Status = 'Vulnerable'; Confidence = 'Confirmed'; Severity = $(if ($sev) { $sev } else { 'UNKNOWN' })
                File = $comp.File; Title = $title; Source = 'NVD'
            })
        }
    }
    return @($out.ToArray())
}
