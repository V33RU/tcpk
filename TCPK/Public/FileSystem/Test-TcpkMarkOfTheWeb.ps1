function Test-TcpkMarkOfTheWeb {
<#
.SYNOPSIS
    FS02. Whether content the application brings in from outside carries the zone mark that
    Windows uses to treat it as untrusted.

.DESCRIPTION
    When a file arrives from the internet, Windows records where it came from in an NTFS
    alternate data stream named Zone.Identifier. Almost every downstream defence keys off
    that mark: SmartScreen reputation checks, Office Protected View, the script-host block
    on downloaded .js and .hta, and the warning on an executable launched from Explorer.
    The mark is not decoration, it is the input those controls read.

    An application that downloads or imports content and writes it to disk itself is
    responsible for applying that mark. Browsers and mail clients do it. Updaters, plugin
    installers, document importers and sync clients frequently do not, and when they do not
    the file lands on disk looking exactly like something the user authored locally. Every
    control listed above then treats it as trusted, and the user sees no warning when they
    open it.

    WHAT IS CHECKED. Does the application reference the API that applies the mark at all?
    On Windows that is IAttachmentExecute (urlmon / AttachmentServices), or a direct write
    of the Zone.Identifier stream. An application that fetches remote content and
    references neither cannot be applying it.

    Rules:
      motw.no-zone-api  MEDIUM  The app fetches remote content and references no API that
                                applies the zone mark.

    DELIBERATELY NOT CHECKED: whether files already on disk carry the mark. Almost nothing
    in an install tree legitimately has one, because the installer wrote those files
    locally, so scanning resting files would report the normal case on every target. The
    question worth asking is whether the code knows how to mark what it fetches, not
    whether already-present files happen to be marked.

.PARAMETER Path
    Install or data directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkMarkOfTheWeb')) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    # ---- static half: does anything here know how to apply the mark? ----------
    $zoneApis = @('IAttachmentExecute', 'AttachmentServices', 'urlmon.dll', 'Zone.Identifier',
                  'SaveWithUI', 'CLSID_AttachmentServices', 'ZoneId=3')
    $fetchApis = @('HttpClient', 'WebClient', 'DownloadFile', 'DownloadData', 'WinHttpRequest',
                   'InternetOpenUrl', 'URLDownloadToFile', 'HttpWebRequest')

    $sawFetch = $false; $sawZone = $false
    $fetchWhere = ''
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = ''
        try { $text = Read-TcpkAllText -Path $pe.FullName } catch { $text = '' }
        if (-not $text) { continue }
        foreach ($z in $zoneApis)  { if ($text.Contains($z)) { $sawZone = $true; break } }
        if (-not $sawFetch) {
            foreach ($d in $fetchApis) {
                if ($text.Contains($d)) { $sawFetch = $true; $fetchWhere = "$($pe.Name) references $d"; break }
            }
        }
        if ($sawZone -and $sawFetch) { break }
    }

    if ($sawFetch -and -not $sawZone) {
        New-TcpkFinding -Module 'filesystem' -RuleId 'motw.no-zone-api' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title 'Application fetches remote content and never applies the zone mark' `
            -File $Path -Evidence ($fetchWhere + '; no IAttachmentExecute / AttachmentServices / Zone.Identifier reference found') `
            -Cwe @('CWE-494', 'CWE-829') `
            -Description ('The application downloads content and writes it to disk, and nothing in the ' +
                'shipped binaries references the API that records where a file came from. Windows keeps ' +
                'that provenance in the Zone.Identifier alternate data stream, and it is the input for ' +
                'SmartScreen, Office Protected View, the script-host block on downloaded script files, and ' +
                'the Explorer warning on an unrecognised executable. A file written without it is ' +
                'indistinguishable from one the user created locally, so every one of those controls ' +
                'treats it as trusted and the user is never prompted. The application has effectively ' +
                'laundered the file''s origin on the way to disk.') `
            -Fix 'Apply the mark when writing any file whose bytes came from outside the machine: call IAttachmentExecute with the source URL and let it set the zone, or write the Zone.Identifier stream directly with ZoneId=3. Do this before the file becomes visible at its final path, not afterwards.'
    }
}
