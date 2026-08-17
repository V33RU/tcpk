function Get-TcpkFileStructure {
<#
.SYNOPSIS
    Apply a byte pattern to a file and return its header as named, decoded fields.

.DESCRIPTION
    Turns an opaque blob into a table instead of a hex dump. A pattern is a flat list of
    {name, offset, size, type, colour}, so a header renders as rows an operator can read.

    This is deliberately NOT a pattern LANGUAGE: no control flow, no structs, no loops.
    A flat field table describes a header, is cheap to write, and cannot misbehave. Anything
    needing conditionals belongs in a dedicated tool.

    WHY IT IS HERE. TCPK finds artifacts whose contents it then only shows as bytes: a DPAPI
    blob, a licence file, an embedded SQLite database, a config container. Combined with
    Test-TcpkEmbeddedBlobs, which reports the OFFSET of something embedded, -BaseOffset
    parses that structure where it actually sits.

    A field that does not fit the file comes back with Status='out-of-range' and an empty
    Value, never a number decoded from whatever bytes followed. A pattern quietly producing
    plausible values for the wrong file is worse than one that fails.

.PARAMETER Path
    File to parse.

.PARAMETER Pattern
    A shipped pattern name (see -ListPatterns), or a path to a pattern .json.

.PARAMETER BaseOffset
    Add this to every field offset, to parse a structure that is not at the start of the
    file. Feed it an offset reported by Test-TcpkEmbeddedBlobs.

.PARAMETER ListPatterns
    List the shipped patterns and return.

.EXAMPLE
    Get-TcpkFileStructure -ListPatterns

.EXAMPLE
    Get-TcpkFileStructure -Path .\app.exe -Pattern pe-dos-header

.EXAMPLE
    # parse a SQLite database found embedded inside an installer
    Get-TcpkFileStructure -Path .\setup.dat -Pattern sqlite-header -BaseOffset 0x2892de

.OUTPUTS
    [pscustomobject] Name, Offset, Size, Type, Value, Status
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Pattern,
        [int64]$BaseOffset = 0,
        [switch]$ListPatterns
    )

    $dir = Join-Path $script:TcpkRoot 'Data\patterns'

    if ($ListPatterns) {
        if (-not (Test-Path -LiteralPath $dir)) { return }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object Name)) {
            $p = Read-TcpkBytePattern -Path $f.FullName
            [pscustomobject]@{
                Name   = [IO.Path]::GetFileNameWithoutExtension($f.Name)
                Fields = $p.Fields.Count
                Errors = $p.Errors.Count
                File   = $f.FullName
            }
        }
        return
    }

    if (-not $Path)    { throw "Get-TcpkFileStructure needs -Path (or -ListPatterns)." }
    if (-not $Pattern) { throw "Get-TcpkFileStructure needs -Pattern. Run -ListPatterns to see the shipped set." }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }

    # A bare name resolves against the shipped set; anything else is treated as a path.
    $patFile = $Pattern
    if (-not (Test-Path -LiteralPath $patFile -PathType Leaf)) {
        $cand = Join-Path $dir ($Pattern + '.json')
        if (Test-Path -LiteralPath $cand -PathType Leaf) { $patFile = $cand }
        else {
            $known = @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue |
                       ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_.Name) })
            throw "Pattern '$Pattern' is neither a file nor a shipped pattern. Shipped: $($known -join ', ')"
        }
    }

    $p = Read-TcpkBytePattern -Path $patFile
    if ($p.Errors.Count) {
        # Refuse the whole pattern rather than render the fields that happened to parse: a
        # partial table looks complete and there is nothing on it saying otherwise.
        throw ("Pattern '$Pattern' is invalid:`n  " + ($p.Errors -join "`n  "))
    }
    if (-not $p.Fields.Count) { throw "Pattern '$Pattern' defines no fields." }

    # Assign, then emit. Resolve-TcpkBytePattern comma-returns so a one-field pattern stays an
    # array INTERNALLY, but forwarding that wrapper out of a public cmdlet is a trap: a
    # comma-protected array is not unrolled by the pipeline, so `Get-TcpkFileStructure ... |
    # ForEach-Object` handed every row to a SINGLE iteration. Emitting the variable unrolls
    # it, which is how every other TCPK cmdlet behaves -- one object per row. Callers wrap in
    # @() when they need an array (a one-field pattern otherwise arrives as a scalar).
    $rows = Resolve-TcpkBytePattern -Path $Path -Fields $p.Fields -BaseOffset $BaseOffset
    $rows
}
