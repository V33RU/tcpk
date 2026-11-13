# MCP host-config parsing and analysis helpers for Test-TcpkMcpHostConfig.
#
# Everything in this file is static analysis of one config file that was found inside the
# audited artifact tree: read the bytes, parse the JSON, normalise each server entry, and
# answer narrow questions about it (what is launched, what is fetched, what is a secret).
# Nothing here reads the operator's profile, the registry or the network.
#
# RUNTIME NOTES (Windows PowerShell 5.1 is the shipping runtime):
#   * ConvertFrom-Json on 5.1 rejects comments, throws on keys that differ only by case and
#     on empty keys, and has no -AsHashtable. The parse below therefore strips comments and
#     trailing commas itself and reads into case-sensitive dictionaries: JavaScriptSerializer
#     on 5.1, ConvertFrom-Json -AsHashtable on 6+. Both give IDictionary / IList trees, and
#     every consumer walks them through GetEnumerator() so one code path serves both.
#   * Helpers that return a collection return it wrapped (return ,$array). Callers assign the
#     result directly and never wrap it in @() again.
#
# COST. A config may hold a very long token (an encoded command, a blob in an argument).
# Every regex written in this file is built through Get-TcpkMcpRx, which gives it a short
# match timeout, no pattern starts with an unanchored greedy run, and the text handed to the
# pattern-based masker is cut to a bounded window first.

$script:TcpkMcpUrlFields = @('url', 'serverUrl', 'httpUrl', 'endpoint')
$script:TcpkMcpRxTimeout = [TimeSpan]::FromSeconds(2)
$script:TcpkMcpRxCache   = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
$script:TcpkMcpScanLimit = 65536      # characters of one value the secret patterns look at
$script:TcpkMcpWordLimit = 16384      # longest string that is split into words or statements
$script:TcpkMcpMaskWindow = 1024      # longest piece of text the pattern masker is run over
$script:TcpkMcpHitLimit = 100         # secrets reported for one value (256 for one word list)
$script:TcpkMcpWordStops = [char[]]@([char]32, [char]9, [char]10, [char]13, [char]34, [char]39)   # whitespace and quotes

# A Regex with the match timeout of this file, cached per pattern and option.
function Get-TcpkMcpRx {
    param([Parameter(Mandatory)][string]$Pattern, [switch]$IgnoreCase)
    $key = 'c|' + $Pattern
    if ($IgnoreCase) { $key = 'i|' + $Pattern }
    $rx = $null
    if ($script:TcpkMcpRxCache.TryGetValue($key, [ref]$rx)) { return $rx }
    $opt = [System.Text.RegularExpressions.RegexOptions]::None
    if ($IgnoreCase) { $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    $rx = New-Object System.Text.RegularExpressions.Regex -ArgumentList $Pattern, $opt, $script:TcpkMcpRxTimeout
    # a few patterns are built from the text of a config (a file name to look for again):
    # the cache is emptied rather than left to grow with them
    if ($script:TcpkMcpRxCache.Count -ge 400) { $script:TcpkMcpRxCache.Clear() }
    $script:TcpkMcpRxCache[$key] = $rx
    return $rx
}

# Replace character spans of a string. Each span is { Start; Length } with an optional Mask;
# spans are clamped to the string, sorted, and overlapping ones merged. Masking by position
# touches only the characters a rule pointed at, never other text that happens to be equal.
function Set-TcpkMcpSpans {
    param([AllowNull()][AllowEmptyString()][string]$Text, $Spans, [string]$Mask = '[redacted]')
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $Spans) {
        foreach ($s in $Spans) {
            if ($null -eq $s) { continue }
            $st = [int]$s.Start
            $ln = [int]$s.Length
            if ($st -lt 0 -or $ln -le 0 -or $st -ge $Text.Length) { continue }
            if (($st + $ln) -gt $Text.Length) { $ln = $Text.Length - $st }
            $mk = $Mask
            if ($s.PSObject.Properties['Mask'] -and $s.Mask) { $mk = "$($s.Mask)" }
            $list.Add([pscustomobject]@{ Start = $st; Length = $ln; Mask = $mk })
        }
    }
    if ($list.Count -eq 0) { return $Text }
    $sorted = @($list.ToArray() | Sort-Object -Property Start)
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($s in $sorted) {
        $end = $s.Start + $s.Length
        if ($end -le $pos) { continue }                       # inside the previous span
        if ($s.Start -ge $pos) {
            if ($s.Start -gt $pos) { [void]$sb.Append($Text, $pos, $s.Start - $pos) }
            [void]$sb.Append($s.Mask)
        }
        # a span that starts inside the previous one only extends it: no second mask
        $pos = $end
    }
    if ($pos -lt $Text.Length) { [void]$sb.Append($Text, $pos, $Text.Length - $pos) }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# reading and parsing
# ---------------------------------------------------------------------------

# Read a config file as text. Honours a UTF-8 or UTF-16 byte-order mark and recognises
# BOM-less UTF-16 by its zero bytes. Returns $null when the file cannot be read.
function Read-TcpkMcpConfigText {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $bytes = $null
    try { $bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return $null }
    if ($null -eq $bytes) { return $null }
    $n = $bytes.Length
    if ($n -eq 0) { return '' }
    $enc = [System.Text.Encoding]::UTF8
    $skip = 0
    if ($n -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $skip = 3 }
    elseif ($n -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $enc = [System.Text.Encoding]::Unicode; $skip = 2 }
    elseif ($n -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $enc = [System.Text.Encoding]::BigEndianUnicode; $skip = 2 }
    elseif ($n -ge 4 -and $bytes[0] -ne 0 -and $bytes[1] -eq 0 -and $bytes[3] -eq 0) { $enc = [System.Text.Encoding]::Unicode }
    elseif ($n -ge 4 -and $bytes[1] -ne 0 -and $bytes[0] -eq 0 -and $bytes[2] -eq 0) { $enc = [System.Text.Encoding]::BigEndianUnicode }
    try { return $enc.GetString($bytes, $skip, $n - $skip) } catch { return $null }
}

# Remove // line comments, /* */ block comments and trailing commas from JSON text.
# String-aware: a quoted string is copied through untouched, so "//server/share" or
# "a, }" inside a value survive. The scan jumps between the few characters that matter
# with IndexOfAny, so the cost is per string and per bracket, not per character.
# Malformed input (unterminated string or block comment) is passed through as-is for the
# parser to reject.
function Remove-TcpkMcpJsonComments {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $ord = [System.StringComparison]::Ordinal
    if ($Text.IndexOf('//', $ord) -lt 0 -and $Text.IndexOf('/*', $ord) -lt 0 -and
        -not [regex]::IsMatch($Text, ',\s*[}\]]')) { return $Text }

    $n = $Text.Length
    $sb = New-Object System.Text.StringBuilder ($n)
    $stops = [char[]]@([char]34, [char]47, [char]125, [char]93)    # " / } ]
    $eol   = [char[]]@([char]13, [char]10)
    $quote = [char]34
    $i = 0
    while ($i -lt $n) {
        $j = $Text.IndexOfAny($stops, $i)
        if ($j -lt 0) { [void]$sb.Append($Text, $i, $n - $i); break }
        if ($j -gt $i) { [void]$sb.Append($Text, $i, $j - $i) }
        $c = $Text[$j]

        if ($c -eq $quote) {
            $close = -1
            $k = $j + 1
            while ($k -lt $n) {
                $q = $Text.IndexOf($quote, $k)
                if ($q -lt 0) { break }
                $bs = 0
                $p = $q - 1
                while ($p -gt $j -and $Text[$p] -eq [char]92) { $bs++; $p-- }
                if (($bs % 2) -eq 0) { $close = $q; break }
                $k = $q + 1
            }
            if ($close -lt 0) { [void]$sb.Append($Text, $j, $n - $j); break }
            [void]$sb.Append($Text, $j, $close - $j + 1)
            $i = $close + 1
            continue
        }

        if ($c -eq [char]47) {
            $nx = [char]0
            if (($j + 1) -lt $n) { $nx = $Text[$j + 1] }
            if ($nx -eq [char]47) {
                $e = $Text.IndexOfAny($eol, $j)
                if ($e -lt 0) { break }
                $i = $e
                continue
            }
            if ($nx -eq [char]42) {
                $e = $Text.IndexOf('*/', $j + 2, $ord)
                if ($e -lt 0) { [void]$sb.Append($Text, $j, $n - $j); break }
                [void]$sb.Append(' ')
                $i = $e + 2
                continue
            }
            [void]$sb.Append($c)
            $i = $j + 1
            continue
        }

        # '}' or ']': drop a comma that directly precedes it, ignoring whitespace.
        $t = $sb.Length - 1
        while ($t -ge 0 -and [char]::IsWhiteSpace($sb.Chars($t))) { $t-- }
        if ($t -ge 0 -and $sb.Chars($t) -eq [char]44) { [void]$sb.Remove($t, 1) }
        [void]$sb.Append($c)
        $i = $j + 1
    }
    return $sb.ToString()
}

# Parse JSON (comments and trailing commas allowed) into case-sensitive dictionaries.
# Returns { Ok; Value; Error }. Never throws. Empty or whitespace-only text is Ok with a
# $null Value: an empty file declares nothing.
function ConvertFrom-TcpkMcpJson {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Text)
    $res = [pscustomobject]@{ Ok = $false; Value = $null; Error = '' }
    if ([string]::IsNullOrWhiteSpace($Text)) { $res.Ok = $true; return $res }
    $clean = $Text.TrimStart([char]0xFEFF)
    try { $clean = Remove-TcpkMcpJsonComments -Text $clean } catch { }
    if ([string]::IsNullOrWhiteSpace($clean)) { $res.Ok = $true; return $res }
    try {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            if ($null -eq $script:TcpkMcpJsonCmdParams) {
                $script:TcpkMcpJsonCmdParams = (Get-Command -Name ConvertFrom-Json -CommandType Cmdlet).Parameters
            }
            $splat = @{ InputObject = $clean; AsHashtable = $true; ErrorAction = 'Stop' }
            if ($script:TcpkMcpJsonCmdParams.ContainsKey('NoEnumerate')) { $splat['NoEnumerate'] = $true }
            if ($script:TcpkMcpJsonCmdParams.ContainsKey('DateKind'))    { $splat['DateKind'] = 'String' }
            $res.Value = ConvertFrom-Json @splat
        } else {
            if ($null -eq $script:TcpkMcpJsSerializer) {
                Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $ser.MaxJsonLength = [int]::MaxValue
                $ser.RecursionLimit = 256
                $script:TcpkMcpJsSerializer = $ser
            }
            $res.Value = $script:TcpkMcpJsSerializer.DeserializeObject($clean)
        }
        $res.Ok = $true
    } catch {
        $ex = $_.Exception
        if ($ex.InnerException) { $ex = $ex.InnerException }
        $res.Error = "$($ex.Message)"
    }
    return $res
}

# Case-sensitive lookup in a parsed JSON object. Returns $null when the node is not an
# object or has no such key. Arrays come back intact (not unrolled).
function Get-TcpkMcpProp {
    param($Map, [string]$Name)
    if ($Map -isnot [System.Collections.IDictionary]) { return $null }
    foreach ($e in $Map.GetEnumerator()) {
        if ("$($e.Key)" -ceq $Name) { return ,$e.Value }
    }
    return $null
}

function Test-TcpkMcpIsList {
    param($Node)
    if ($null -eq $Node) { return $false }
    if ($Node -is [string]) { return $false }
    if ($Node -is [System.Collections.IDictionary]) { return $false }
    return ($Node -is [System.Collections.IList])
}

# Scalars of a JSON array as strings. Objects, nested arrays and nulls are dropped. A bare
# string is taken as one token (it is not split: no host splits it either).
function ConvertTo-TcpkMcpStringList {
    param($Value)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Value) { return ,$out.ToArray() }
    if ($Value -is [string]) { $out.Add($Value); return ,$out.ToArray() }
    if (Test-TcpkMcpIsList $Value) {
        foreach ($x in $Value) {
            if ($null -eq $x) { continue }
            if ($x -is [string]) { $out.Add($x); continue }
            if ($x -is [System.Collections.IDictionary]) { continue }
            if (Test-TcpkMcpIsList $x) { continue }
            if ($x -is [bool]) { $out.Add(([string]$x).ToLowerInvariant()); continue }
            $out.Add([string]$x)
        }
    }
    return ,$out.ToArray()
}

function Get-TcpkMcpTail {
    param([string[]]$Items, [int]$Start)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $Items) {
        for ($i = [Math]::Max(0, $Start); $i -lt $Items.Count; $i++) { $out.Add("$($Items[$i])") }
    }
    return ,$out.ToArray()
}

# ---------------------------------------------------------------------------
# server maps and entries
# ---------------------------------------------------------------------------

# Does this entry look like an MCP server? A command (string, array or {path}) always counts.
# A url-type field counts according to $Level:
#   loose    any url
#   strict   a url with an sse / http style transport named next to it
#   mcponly  a url with a transport name only MCP uses (sse, streamable-http, http-stream);
#            "type": "http" next to a url is what any list of backends looks like
#   flat     a url with "type": "remote" (the flat "mcp" map form)
function Test-TcpkMcpEntryShape {
    param($Entry, [ValidateSet('loose', 'strict', 'mcponly', 'flat')][string]$Level = 'loose')
    if ($Entry -isnot [System.Collections.IDictionary]) { return $false }
    $src = $Entry
    $tr = Get-TcpkMcpProp $Entry 'transport'
    if ($tr -is [System.Collections.IDictionary]) { $src = $tr }

    $cmd = Get-TcpkMcpProp $src 'command'
    if ($cmd -is [string]) { if ($cmd.Trim()) { return $true } }
    elseif ($cmd -is [System.Collections.IDictionary]) {
        $p = Get-TcpkMcpProp $cmd 'path'
        if ($p -is [string] -and $p.Trim()) { return $true }
    }
    elseif (Test-TcpkMcpIsList $cmd) {
        $parts = ConvertTo-TcpkMcpStringList $cmd
        if ($parts.Count -gt 0 -and "$($parts[0])".Trim()) { return $true }
    }

    $hasUrl = $false
    foreach ($node in @($src, $Entry)) {
        foreach ($f in $script:TcpkMcpUrlFields) {
            $u = Get-TcpkMcpProp $node $f
            if ($u -is [string] -and $u -match '^\s*(https?|wss?)://') { $hasUrl = $true; break }
        }
        if ($hasUrl) { break }
    }
    if (-not $hasUrl) { return $false }
    if ($Level -ceq 'loose') { return $true }

    $kind = ''
    foreach ($node in @($src, $Entry)) {
        foreach ($f in @('type', 'transport', 'transportType')) {
            $v = Get-TcpkMcpProp $node $f
            if ($v -is [string] -and $v.Trim()) { $kind = $v.Trim(); break }
        }
        if ($kind) { break }
    }
    if ($Level -ceq 'flat')    { return ($kind -match '^remote$') }
    if ($Level -ceq 'mcponly') { return ($kind -match '^(sse|streamable[-_ ]?http|http[-_ ]?stream(ing|able)?)$') }
    return ($kind -match '^(sse|https?|streamable[-_ ]?http|http[-_ ]?stream(ing|able)?|wss?|websocket|remote)$')
}

# Find every server map in a parsed config. Each result is { Label; Node; Specific; Nested }.
#   Specific = the key only ever means MCP servers (mcpServers, mcp.servers, context_servers ...)
#   Nested   = the map sits under a per-project or similar key, so Label is needed to tell
#              two servers with the same name apart.
function Get-TcpkMcpServerMaps {
    param($Root)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $roots = New-Object 'System.Collections.Generic.List[object]'
    if ($Root -is [System.Collections.IDictionary]) { $roots.Add($Root) }
    elseif (Test-TcpkMcpIsList $Root) {
        foreach ($el in $Root) { if ($el -is [System.Collections.IDictionary]) { $roots.Add($el) } }
    }
    foreach ($r in $roots) {
        foreach ($e in $r.GetEnumerator()) {
            $k = "$($e.Key)"
            $v = $e.Value
            if ($k -cmatch '^(?:[A-Za-z0-9_-]+\.)?mcpServers$' -or $k -ceq 'context_servers' -or $k -ceq 'mcp.servers') {
                $out.Add([pscustomobject]@{ Label = $k; Node = $v; Specific = $true; Nested = $false })
                continue
            }
            if ($k -ceq 'servers') {
                $out.Add([pscustomobject]@{ Label = $k; Node = $v; Specific = $false; Nested = $false })
                continue
            }
            if ($k -ceq 'mcp' -and $v -is [System.Collections.IDictionary]) {
                $inner = Get-TcpkMcpProp $v 'servers'
                if ($null -ne $inner) {
                    $out.Add([pscustomobject]@{ Label = 'mcp.servers'; Node = $inner; Specific = $true; Nested = $false })
                } else {
                    # Flat form: every value under "mcp" is a server entry. The key is too
                    # generic to trust on its own, so it goes through its own shape gate.
                    $out.Add([pscustomobject]@{ Label = 'mcp'; Node = $v; Specific = $false; Nested = $false })
                }
                continue
            }
            if ($k -ceq 'projects' -and $v -is [System.Collections.IDictionary]) {
                foreach ($pe in $v.GetEnumerator()) {
                    $inner = Get-TcpkMcpProp $pe.Value 'mcpServers'
                    if ($null -ne $inner) {
                        $out.Add([pscustomobject]@{ Label = "projects/$($pe.Key)"; Node = $inner; Specific = $true; Nested = $true })
                    }
                }
                continue
            }
            if ($k -ceq 'experimental' -and $v -is [System.Collections.IDictionary]) {
                $inner = Get-TcpkMcpProp $v 'modelContextProtocolServers'
                if ($null -ne $inner) {
                    $out.Add([pscustomobject]@{ Label = 'experimental.modelContextProtocolServers'; Node = $inner; Specific = $true; Nested = $false })
                }
                continue
            }
        }
    }
    return ,$out.ToArray()
}

# Normalise one server entry. Returns $null for a non-object entry.
function ConvertTo-TcpkMcpServer {
    param([string]$Name, $Entry)
    if ($Entry -isnot [System.Collections.IDictionary]) { return $null }
    $src = $Entry
    $tr = Get-TcpkMcpProp $Entry 'transport'
    if ($tr -is [System.Collections.IDictionary]) { $src = $tr }

    $command = ''
    $argList = New-Object 'System.Collections.Generic.List[string]'
    $envNode = $null

    $cmdRaw = Get-TcpkMcpProp $src 'command'
    if ($cmdRaw -is [string]) {
        $command = $cmdRaw.Trim()
    } elseif ($cmdRaw -is [System.Collections.IDictionary]) {
        # { "command": { "path": ..., "args": [...], "env": {...} } }
        $p = Get-TcpkMcpProp $cmdRaw 'path'
        if ($p -is [string]) { $command = $p.Trim() }
        foreach ($a in (ConvertTo-TcpkMcpStringList (Get-TcpkMcpProp $cmdRaw 'args'))) { $argList.Add($a) }
        $e = Get-TcpkMcpProp $cmdRaw 'env'
        if ($e -is [System.Collections.IDictionary]) { $envNode = $e }
    } elseif (Test-TcpkMcpIsList $cmdRaw) {
        # { "command": ["npx", "-y", "pkg"] }
        $parts = ConvertTo-TcpkMcpStringList $cmdRaw
        if ($parts.Count -gt 0) {
            $command = "$($parts[0])".Trim()
            for ($i = 1; $i -lt $parts.Count; $i++) { $argList.Add($parts[$i]) }
        }
    }
    foreach ($a in (ConvertTo-TcpkMcpStringList (Get-TcpkMcpProp $src 'args'))) { $argList.Add($a) }

    if ($null -eq $envNode) {
        foreach ($node in @($src, $Entry)) {
            foreach ($f in @('env', 'environment')) {
                $e = Get-TcpkMcpProp $node $f
                if ($e -is [System.Collections.IDictionary]) { $envNode = $e; break }
            }
            if ($null -ne $envNode) { break }
        }
    }

    $urls = New-Object 'System.Collections.Generic.List[object]'
    $seenUrl = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($node in @($src, $Entry)) {
        foreach ($f in $script:TcpkMcpUrlFields) {
            $u = Get-TcpkMcpProp $node $f
            if ($u -is [string] -and $u.Trim()) {
                if ($seenUrl.Add("$f|$u")) { $urls.Add([pscustomobject]@{ Field = $f; Value = $u.Trim() }) }
            }
        }
    }

    $headers = $null
    foreach ($node in @($src, $Entry)) {
        $h = Get-TcpkMcpProp $node 'headers'
        if ($h -isnot [System.Collections.IDictionary]) {
            $ri = Get-TcpkMcpProp $node 'requestInit'
            if ($ri -is [System.Collections.IDictionary]) { $h = Get-TcpkMcpProp $ri 'headers' }
        }
        if ($h -is [System.Collections.IDictionary]) { $headers = $h; break }
    }

    $disabled = $false
    $d = Get-TcpkMcpProp $Entry 'disabled'
    if ($d -is [bool] -and $d) { $disabled = $true }
    $en = Get-TcpkMcpProp $Entry 'enabled'
    if ($en -is [bool] -and -not $en) { $disabled = $true }

    $cwd = ''
    foreach ($node in @($src, $Entry)) {
        $c = Get-TcpkMcpProp $node 'cwd'
        if ($c -is [string] -and $c.Trim()) { $cwd = $c.Trim(); break }
    }

    return [pscustomobject]@{
        Name     = $Name
        Command  = $command
        Args     = $argList.ToArray()
        Env      = $envNode
        Urls     = $urls.ToArray()
        Headers  = $headers
        Disabled = $disabled
        Cwd      = $cwd
        MapLabel = ''
        Nested   = $false
    }
}

# All servers a parsed config declares, after the shape gate.
#   NameKnown  the file name is one only MCP hosts use
#   SingleFile the caller pointed -Path at this file
# Gate per map (see Test-TcpkMcpEntryShape for the levels); a map counts only if at least
# one of its entries passes:
#   MCP-only key    known file name: no gate, every object entry is a server
#                   unknown file name in single-file mode: strict
#                   otherwise (generic file name that passed the content probe): loose
#   bare "servers"  known file name: strict
#                   any other file name: mcponly, and in directory mode the file must also
#                   carry an MCP-only key. A settings file with a list of backends under
#                   "servers" is not an MCP config, whatever else it mentions.
#   flat "mcp"      flat: an entry with a command, or a url with "type": "remote". An
#                   application's own "mcp" settings block has neither.
# Returns { Servers; BadMaps } where BadMaps names MCP-only keys whose value is neither an
# object nor an array.
function Get-TcpkMcpServers {
    param($Root, [bool]$NameKnown, [bool]$SingleFile)
    $servers = New-Object 'System.Collections.Generic.List[object]'
    $bad = New-Object 'System.Collections.Generic.List[string]'
    $maps = Get-TcpkMcpServerMaps -Root $Root
    $hasSpecific = $false
    foreach ($m in $maps) { if ($m.Specific) { $hasSpecific = $true; break } }
    foreach ($m in $maps) {
        $node = $m.Node
        $entries = New-Object 'System.Collections.Generic.List[object]'
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($e in $node.GetEnumerator()) {
                $entries.Add([pscustomobject]@{ Name = "$($e.Key)"; Entry = $e.Value })
            }
        } elseif (Test-TcpkMcpIsList $node) {
            $idx = 0
            foreach ($el in $node) {
                $idx++
                $nm = ''
                if ($el -is [System.Collections.IDictionary]) {
                    foreach ($nk in @('name', 'id', 'key')) {
                        $nv = Get-TcpkMcpProp $el $nk
                        if ($nv -is [string] -and $nv.Trim()) { $nm = $nv.Trim(); break }
                    }
                }
                if (-not $nm) { $nm = "#$idx" }
                $entries.Add([pscustomobject]@{ Name = $nm; Entry = $el })
            }
        } else {
            if ($m.Specific -and $null -ne $node) {
                $bad.Add("'$($m.Label)' is neither an object nor an array")
            }
            continue
        }

        $gate = 'loose'
        if ($m.Specific) {
            if ($NameKnown) { $gate = 'none' }
            elseif ($SingleFile) { $gate = 'strict' }
        } elseif ($m.Label -ceq 'mcp') {
            $gate = 'flat'
        } elseif ($NameKnown) {
            $gate = 'strict'
        } else {
            if ((-not $SingleFile) -and (-not $hasSpecific)) { continue }
            $gate = 'mcponly'
        }
        if ($gate -cne 'none') {
            $ok = $false
            foreach ($en in $entries) {
                if (Test-TcpkMcpEntryShape -Entry $en.Entry -Level $gate) { $ok = $true; break }
            }
            if (-not $ok) { continue }
        }

        foreach ($en in $entries) {
            $s = ConvertTo-TcpkMcpServer -Name $en.Name -Entry $en.Entry
            if ($null -eq $s) { continue }
            $s.MapLabel = $m.Label
            $s.Nested = [bool]$m.Nested
            $servers.Add($s)
        }
    }
    return [pscustomobject]@{ Servers = $servers.ToArray(); BadMaps = $bad.ToArray() }
}

# ---------------------------------------------------------------------------
# launcher analysis
# ---------------------------------------------------------------------------

# Launcher leaf name: last path segment, lower-case, without .exe / .cmd / .bat / .ps1.
# Split by hand: [IO.Path] throws on illegal characters on .NET Framework and does not
# split backslashes on a non-Windows host.
function Get-TcpkMcpLeaf {
    param([AllowNull()][string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $c = $Command.Trim().Trim([char]34).Trim([char]39)
    $parts = @($c -split '[\\/]')
    $leaf = "$($parts[$parts.Count - 1])".ToLowerInvariant()
    return ($leaf -replace '\.(exe|cmd|bat|ps1)$', '')
}

# Whitespace split that keeps a double-quoted run together.
function Split-TcpkMcpCommandLine {
    param([AllowNull()][string]$Line)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($Line)) {
        foreach ($m in [regex]::Matches($Line, '"([^"]*)"|(\S+)')) {
            if ($m.Groups[1].Success) { $out.Add($m.Groups[1].Value) } else { $out.Add($m.Groups[2].Value) }
        }
    }
    return ,$out.ToArray()
}

# Walk an argument list from $Start: skip options, consume the value of every option named
# in $ValueOpts, collect the values of $PkgOpts and $ExtraOpts, stop at the first
# positional token (or the one after "--"). Option names are case-sensitive.
# Returns { Index; Packages; Extras }. Index is -1 when there is no positional.
function Get-TcpkMcpPositional {
    param([string[]]$Argv, [int]$Start = 0, [string[]]$ValueOpts = @(), [string[]]$PkgOpts = @(), [string[]]$ExtraOpts = @())
    $pk = New-Object 'System.Collections.Generic.List[string]'
    $ex = New-Object 'System.Collections.Generic.List[string]'
    $pos = -1
    $n = 0
    if ($null -ne $Argv) { $n = $Argv.Count }
    $i = $Start
    while ($i -lt $n) {
        $a = "$($Argv[$i])"
        if ($a -ceq '--') { if (($i + 1) -lt $n) { $pos = $i + 1 }; break }
        if ($a.Length -gt 1 -and $a.StartsWith('-')) {
            $name = $a
            $val = $null
            $eq = $a.IndexOf('=')
            if ($eq -gt 0) { $name = $a.Substring(0, $eq); $val = $a.Substring($eq + 1) }
            $isPkg = ($PkgOpts -ccontains $name)
            $isExtra = ($ExtraOpts -ccontains $name)
            if ($isPkg -or $isExtra -or ($ValueOpts -ccontains $name)) {
                if ($null -eq $val) {
                    $i++
                    if ($i -lt $n) { $val = "$($Argv[$i])" }
                }
                if ($val) {
                    if ($isPkg) { $pk.Add($val) } elseif ($isExtra) { $ex.Add($val) }
                }
            }
            $i++
            continue
        }
        $pos = $i
        break
    }
    return [pscustomobject]@{ Index = $pos; Packages = $pk.ToArray(); Extras = $ex.ToArray() }
}

function New-TcpkMcpInline {
    param([string]$Kind, [string]$Shell, [string]$Option, [AllowNull()][string]$Script, [bool]$Encoded = $false)
    return [pscustomobject]@{ Kind = $Kind; Shell = $Shell; Option = $Option; Script = "$Script"; Encoded = $Encoded; Unwrapped = $false }
}

# What an interpreter-style launcher was asked to run: an inline script string (Inline),
# or a script file (ScriptPath at ScriptIndex). Option scanning stops at the first
# positional, so "-c" or "-e" after the script path is the script's own argument.
function Get-TcpkMcpInterpreter {
    param([string]$Leaf, [string[]]$Argv)
    $r = [pscustomobject]@{ Kind = ''; Inline = $null; ScriptPath = ''; ScriptIndex = -1 }
    $n = 0
    if ($null -ne $Argv) { $n = $Argv.Count }

    if ($Leaf -match '^(powershell|pwsh|pwsh-preview)$') {
        $r.Kind = 'powershell'
        $valOpts = '^[-/](ex|exec|executionpolicy|ep|w|win|windowstyle|v|version|if|inputformat|of|o|outputformat|config|configurationname|wd|wo|workingdirectory|custompipename|settings|settingsfile|psconsolefile)$'
        $encOpt  = '^[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -match '^[-/](c|co|com|comm|comma|comman|command|commandwithargs|cwa)$') {
                $r.Inline = New-TcpkMcpInline -Kind 'powershell' -Shell $Leaf -Option $a -Script ((Get-TcpkMcpTail $Argv ($i + 1)) -join ' ')
                return $r
            }
            if ($a -match $encOpt) {
                $dec = ''
                if (($i + 1) -lt $n) {
                    try { $dec = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("$($Argv[$i + 1])")) } catch { $dec = '' }
                }
                $r.Inline = New-TcpkMcpInline -Kind 'powershell' -Shell $Leaf -Option $a -Script $dec -Encoded $true
                return $r
            }
            if ($a -match '^[-/](f|fi|fil|file)$') {
                if (($i + 1) -lt $n) { $r.ScriptPath = "$($Argv[$i + 1])"; $r.ScriptIndex = $i + 1 }
                return $r
            }
            if ($a -match $valOpts) { $i++; continue }
            if ($a -match '^-[A-Za-z]' -or $a -match '^/[A-Za-z]+$') { continue }
            # First positional. Windows PowerShell treats it as -Command, pwsh as -File.
            $looksLikeFile = ($a -match '\.ps1$' -and $a -notmatch '[;|&]')
            if ($Leaf -ceq 'powershell' -and -not $looksLikeFile) {
                $r.Inline = New-TcpkMcpInline -Kind 'powershell' -Shell $Leaf -Option '(positional)' -Script ((Get-TcpkMcpTail $Argv $i) -join ' ')
            } else {
                $r.ScriptPath = $a; $r.ScriptIndex = $i
            }
            return $r
        }
        return $r
    }

    if ($Leaf -match '^(bash|sh|zsh|dash|ksh|ash|fish)$') {
        $r.Kind = 'posix-shell'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -cmatch '^-[A-Za-z]*c[A-Za-z]*$' -or $a -ceq '--command') {
                $s = ''
                if (($i + 1) -lt $n) { $s = "$($Argv[$i + 1])" }
                $r.Inline = New-TcpkMcpInline -Kind 'posix-shell' -Shell $Leaf -Option $a -Script $s
                return $r
            }
            if ($a -cmatch '^(-o|-O|--rcfile|--init-file)$') { $i++; continue }
            if ($a.StartsWith('-')) { continue }
            $r.ScriptPath = $a; $r.ScriptIndex = $i
            return $r
        }
        return $r
    }

    if ($Leaf -match '^(node|nodejs|bun|tsx|ts-node)$') {
        $r.Kind = 'node'
        $valOpts = @('-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions',
                     '--env-file', '--inspect-port', '--title', '--input-type', '--watch-path', '--cwd',
                     '--config', '--tsconfig', '-P', '--project')
        $first = $true
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -cmatch '^(-e|--eval|-p|--print|-pe)$') {
                $s = ''
                if (($i + 1) -lt $n) { $s = "$($Argv[$i + 1])" }
                $r.Inline = New-TcpkMcpInline -Kind 'node' -Shell $Leaf -Option $a -Script $s
                return $r
            }
            $m = [regex]::Match($a, '^(--eval|--print)=(.*)$', 'Singleline')
            if ($m.Success) {
                $r.Inline = New-TcpkMcpInline -Kind 'node' -Shell $Leaf -Option $m.Groups[1].Value -Script $m.Groups[2].Value
                return $r
            }
            if ($valOpts -ccontains $a) { $i++; continue }
            if ($a.Length -gt 1 -and $a.StartsWith('-')) { continue }
            if ($Leaf -ceq 'bun' -and $first) {
                $first = $false
                if ($a -ceq 'x') { return $r }          # package runner, handled as a launcher
                if ($a -ceq 'run') { continue }
            }
            $r.ScriptPath = $a; $r.ScriptIndex = $i
            return $r
        }
        return $r
    }

    if ($Leaf -ceq 'deno') {
        $r.Kind = 'deno'
        $w = Get-TcpkMcpPositional -Argv $Argv -Start 0
        if ($w.Index -lt 0) { return $r }
        $sub = "$($Argv[$w.Index])"
        if ($sub -ceq 'eval') {
            $w2 = Get-TcpkMcpPositional -Argv $Argv -Start ($w.Index + 1) -ValueOpts @('-c', '--config', '--import-map', '--ext', '-L', '--log-level')
            $s = ''
            if ($w2.Index -ge 0) { $s = "$($Argv[$w2.Index])" }
            $r.Inline = New-TcpkMcpInline -Kind 'node' -Shell $Leaf -Option 'eval' -Script $s
        }
        return $r
    }

    if ($Leaf -match '^(python[0-9.]*|pythonw|py|pypy[0-9.]*)$') {
        $r.Kind = 'python'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -ceq '-c') {
                $s = ''
                if (($i + 1) -lt $n) { $s = "$($Argv[$i + 1])" }
                $r.Inline = New-TcpkMcpInline -Kind 'python' -Shell $Leaf -Option $a -Script $s
                return $r
            }
            if ($a -ceq '-m') { if (($i + 1) -lt $n) { $r.ScriptIndex = $i + 1 }; return $r }
            if ($a -cmatch '^(-W|-X|--check-hash-based-pycs)$') { $i++; continue }
            if ($a.Length -gt 1 -and $a.StartsWith('-')) { continue }
            $r.ScriptPath = $a; $r.ScriptIndex = $i
            return $r
        }
        return $r
    }

    if ($Leaf -match '^(ruby|perl|php)$') {
        $r.Kind = 'script'
        $inlineOpt = '^-e$'
        if ($Leaf -ceq 'perl') { $inlineOpt = '^-[eE]$' }
        if ($Leaf -ceq 'php')  { $inlineOpt = '^-r$' }
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -cmatch $inlineOpt) {
                $s = ''
                if (($i + 1) -lt $n) { $s = "$($Argv[$i + 1])" }
                $r.Inline = New-TcpkMcpInline -Kind 'script' -Shell $Leaf -Option $a -Script $s
                return $r
            }
            if ($a -cmatch '^(-I|-r|-C|-c|-d|-f)$') {
                if ($a -ceq '-f' -and ($i + 1) -lt $n) { $r.ScriptPath = "$($Argv[$i + 1])"; $r.ScriptIndex = $i + 1; return $r }
                $i++; continue
            }
            if ($a.Length -gt 1 -and $a.StartsWith('-')) { continue }
            $r.ScriptPath = $a; $r.ScriptIndex = $i
            return $r
        }
        return $r
    }

    if ($Leaf -match '^(wscript|cscript)$') {
        $r.Kind = 'script-host'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -match '^//[A-Za-z][A-Za-z:]*$') { continue }      # //B //Nologo //E:jscript
            $r.ScriptPath = $a; $r.ScriptIndex = $i
            return $r
        }
        return $r
    }

    if ($Leaf -ceq 'mshta') {
        $r.Kind = 'script-host'
        if ($n -gt 0) {
            $a = "$($Argv[0])"
            if ($a -match '^"?(javascript|vbscript):') {
                $r.Inline = New-TcpkMcpInline -Kind 'mshta' -Shell $Leaf -Option '(script url)' -Script ((Get-TcpkMcpTail $Argv 0) -join ' ')
            } else {
                $r.ScriptPath = $a; $r.ScriptIndex = 0
            }
        }
        return $r
    }

    if ($Leaf -ceq 'rundll32') {
        $r.Kind = 'script-host'
        if ($n -gt 0) {
            $a = "$($Argv[0])"
            $comma = $a.LastIndexOf(',')
            if ($comma -gt 0) { $a = $a.Substring(0, $comma) }
            $r.ScriptPath = $a; $r.ScriptIndex = 0
        }
        return $r
    }

    if ($Leaf -ceq 'java') {
        $r.Kind = 'runtime'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -ceq '-jar') { if (($i + 1) -lt $n) { $r.ScriptPath = "$($Argv[$i + 1])"; $r.ScriptIndex = $i + 1 }; return $r }
            if ($a -cmatch '^(-cp|-classpath|--class-path|-p|--module-path|--add-modules)$') { $i++; continue }
            if ($a.StartsWith('-')) { continue }
            return $r
        }
        return $r
    }

    if ($Leaf -ceq 'dotnet') {
        $r.Kind = 'runtime'
        for ($i = 0; $i -lt $n; $i++) {
            $a = "$($Argv[$i])"
            if ($a -cmatch '^(--project|--fx-version|--roll-forward|--additionalprobingpath|--depsfile|--runtimeconfig)$') {
                if ($a -ceq '--project' -and ($i + 1) -lt $n) { $r.ScriptPath = "$($Argv[$i + 1])"; $r.ScriptIndex = $i + 1; return $r }
                $i++; continue
            }
            if ($a.StartsWith('-')) { continue }
            if ($a -ceq 'exec' -or $a -ceq 'run') { continue }
            if ($a -match '\.(dll|exe)$') { $r.ScriptPath = $a; $r.ScriptIndex = $i }
            return $r
        }
        return $r
    }

    return $r
}

# Split an inline script into simple commands. Quote-aware: an operator inside a quoted
# string does not split anything.
#   cmd          & && | || and newlines separate; "..." quotes; ^ escapes the next character
#   posix-shell  ; & && | || newlines ( ) { } separate; '...' and "..." quote; a backslash
#                escapes a following space, quote or operator
#   powershell   ; | && || newlines ( ) { } separate, and so does & (the call operator
#                starts a command); '...' and "..." quote; a backtick escapes
# Redirections (> file, 2>&1, < file) are not words. Returns records
#   { Words; Start; End; Sep }
# Words is the command as a string array without its quotes, Start / End its character range
# in $Script, and Sep the separator before it ('' for the first command, 'nl' for a newline).
# When several separators precede a command, a statement separator wins over | ( ) { }.
function Split-TcpkMcpScript {
    param([AllowNull()][string]$Script, [string]$Kind)
    $cmds = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Script)) { return ,$cmds.ToArray() }
    $s = $Script
    if ($s.Length -gt $script:TcpkMcpWordLimit) { $s = $s.Substring(0, $script:TcpkMcpWordLimit) }
    $n = $s.Length
    $isCmd = ($Kind -ceq 'cmd')
    $isPs = ($Kind -ceq 'powershell')
    $dq = [char]34
    $sq = [char]39
    $esc = [char]92
    if ($isCmd) { $esc = [char]94 } elseif ($isPs) { $esc = [char]96 }
    $escapable = '&|;(){}<>' + [char]92

    $words = New-Object 'System.Collections.Generic.List[string]'
    $sb = New-Object System.Text.StringBuilder
    $inWord = $false
    $q = [char]0
    $cmdStart = -1
    $pending = ''
    $i = 0
    while ($i -le $n) {
        $atEnd = ($i -ge $n)
        $c = [char]0
        if (-not $atEnd) { $c = $s[$i] }

        if ((-not $atEnd) -and $q -ne [char]0) {
            if ($c -eq $q) { $q = [char]0 }
            elseif ($c -eq $esc -and $q -eq $dq -and (-not $isCmd) -and ($i + 1) -lt $n -and ($s[$i + 1] -eq $dq -or $s[$i + 1] -eq $esc)) {
                $i++
                [void]$sb.Append($s[$i])
            }
            else { [void]$sb.Append($c) }
            $i++
            continue
        }

        $op = ''
        if ($atEnd) { $op = 'end' }
        elseif ($c -eq [char]10 -or $c -eq [char]13) { $op = 'nl' }
        elseif ($c -eq [char]38) {
            # 2>&1 and >&2 are redirections, not separators
            if ($i -gt 0 -and $s[$i - 1] -eq [char]62) { $op = '' }
            elseif (($i + 1) -lt $n -and $s[$i + 1] -eq [char]38) { $op = '&&' }
            else { $op = '&' }
        }
        elseif ($c -eq [char]124) {
            if (($i + 1) -lt $n -and $s[$i + 1] -eq [char]124) { $op = '||' } else { $op = '|' }
        }
        elseif ((-not $isCmd) -and $c -eq [char]59) { $op = ';' }
        elseif ((-not $isCmd) -and ($c -eq [char]40 -or $c -eq [char]41 -or $c -eq [char]123 -or $c -eq [char]125)) { $op = [string]$c }

        if ($op) {
            if ($inWord) { $words.Add($sb.ToString()); $sb.Length = 0; $inWord = $false }
            if ($words.Count -gt 0) {
                # redirections are not part of the command
                $clean = [System.Collections.Generic.List[string]]::new()
                $skipNext = $false
                foreach ($w in $words) {
                    if ($skipNext) { $skipNext = $false; continue }
                    if ($w -match '^\d*(>>?|<)$') { $skipNext = $true; continue }
                    if ($w -match '^\d*(>>?|<)') { continue }
                    $clean.Add($w)
                }
                if ($clean.Count -gt 0) {
                    $cmds.Add([pscustomobject]@{ Words = $clean.ToArray(); Start = $cmdStart; End = $i; Sep = $pending })
                    $pending = ''
                }
                $words.Clear()
            }
            if ($op -ceq 'end') { break }
            if ($pending -cne ';' -and $pending -cne '&' -and $pending -cne '&&' -and $pending -cne '||' -and $pending -cne 'nl') { $pending = $op }
            $cmdStart = -1
            if ($op -ceq '&&' -or $op -ceq '||') { $i += 2 } else { $i++ }
            continue
        }

        if ([char]::IsWhiteSpace($c)) {
            if ($inWord) { $words.Add($sb.ToString()); $sb.Length = 0; $inWord = $false }
            $i++
            continue
        }
        if ($cmdStart -lt 0) { $cmdStart = $i }
        if ($c -eq $dq -or ($c -eq $sq -and -not $isCmd)) { $q = $c; $inWord = $true; $i++; continue }
        if ($c -eq $esc -and ($i + 1) -lt $n) {
            $nx = $s[$i + 1]
            if ($isCmd -or $isPs -or [char]::IsWhiteSpace($nx) -or $nx -eq $dq -or $nx -eq $sq -or $escapable.IndexOf($nx) -ge 0) {
                [void]$sb.Append($nx)
                $inWord = $true
                $i += 2
                continue
            }
        }
        [void]$sb.Append($c)
        $inWord = $true
        $i++
    }
    return ,$cmds.ToArray()
}

# Group the simple commands of a shell script into statements: a pipeline, together with
# any ( ) { } group it opens, is one statement. Returns records { Text; Commands } where
# Text is the statement as written and Commands a list of word arrays.
function Get-TcpkMcpStatements {
    param([AllowNull()][string]$Script, [string]$Kind)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $s = "$Script"
    if ($s.Length -gt $script:TcpkMcpWordLimit) { $s = $s.Substring(0, $script:TcpkMcpWordLimit) }
    $cur = $null
    foreach ($c in (Split-TcpkMcpScript -Script $s -Kind $Kind)) {
        $isBreak = ($null -eq $cur) -or ($c.Sep -ceq ';') -or ($c.Sep -ceq '&') -or ($c.Sep -ceq '&&') -or ($c.Sep -ceq '||') -or ($c.Sep -ceq 'nl')
        if ($isBreak) {
            $cur = [pscustomobject]@{ Start = $c.Start; End = $c.End; Text = ''; Commands = [System.Collections.Generic.List[object]]::new() }
            $out.Add($cur)
        }
        $cur.End = $c.End
        $cur.Commands.Add($c.Words)
    }
    foreach ($st in $out) {
        $e = [Math]::Min($s.Length, [int]$st.End)
        if ($e -gt $st.Start) { $st.Text = $s.Substring($st.Start, $e - $st.Start) }
    }
    return ,$out.ToArray()
}

# The command a simple command of an inline script starts, without the words in front of it
# that only set things up (NAME=value, exec, call, start, sudo, env ...). Returns
# { Command; Args }, or $null when the words are a builtin that starts nothing
# (set, export, cd, source, echo ...).
function Get-TcpkMcpInnerCommand {
    param([string[]]$Words, [string]$Kind)
    $n = 0
    if ($null -ne $Words) { $n = $Words.Count }
    $k = 0
    while ($k -lt $n) {
        $w = "$($Words[$k])"
        if (-not $w) { $k++; continue }
        if ($Kind -cne 'cmd' -and $w -match '^[A-Za-z_][A-Za-z0-9_]*=') { $k++; continue }
        $lw = $w.ToLowerInvariant()
        if ($lw -match '^@?(exec|call|sudo|nohup|command|time|env|start|start-process|saps)$') {
            $k++
            while ($k -lt $n) {
                $o = "$($Words[$k])"
                if (-not $o) { $k++; continue }
                if ($o.StartsWith('-')) { $k++; continue }
                if ($lw -match 'start$' -and $o -match '^/[A-Za-z]+$') { $k++; continue }
                if ($lw -ceq 'env' -and $o -match '^[A-Za-z_][A-Za-z0-9_]*=') { $k++; continue }
                break
            }
            continue
        }
        break
    }
    if ($k -ge $n) { return $null }
    $first = "$($Words[$k])"
    if ($first.ToLowerInvariant() -match '^@?(\.|set|setlocal|export|unset|cd|chdir|pushd|popd|source|echo|rem|if|for|while|do|then|else|fi|done|exit|pause|title|alias|function|return|trap)$') { return $null }
    return [pscustomobject]@{ Command = $first; Args = (Get-TcpkMcpTail $Words ($k + 1)) }
}

# Write calls of the scripting languages an inline one-liner is written in; group 'p' is
# the file that is written.
$script:TcpkMcpCodeWriteRx = '(?:urlretrieve\s*\(\s*[^,()]+,\s*|getstore\s*\(\s*[^,()]+,\s*|copy\s*\(\s*["''][a-z]+://[^"'']*["'']\s*,\s*|createWriteStream\s*\(\s*|writeFile(?:Sync)?\s*\(\s*|file_put_contents\s*\(\s*|File\.(?:bin)?write\s*\(\s*)["''`](?<p>[^"''`]{1,260})["''`]|open\s*\(\s*["''](?<p>[^"'']{1,260})["'']\s*,\s*["''][wax]'
$script:TcpkMcpProgramExtRx = '\.(exe|msi|bat|cmd|com|scr|ps1|psm1|vbs|vbe|js|jse|wsf|hta|dll|sh|bash|py|pl|rb|jar)$'

# Files a shell statement saves from a remote location. Only output positions count: an
# output option of the download tool, a redirection, the second argument of DownloadFile,
# the argument after the URL for certutil / bitsadmin / Start-BitsTransfer, and the remote
# name for a tool that saves under it. A file name that merely appears in the statement
# (the tool itself, a message, a query string) is not a saved file.
# Returns records { Path; Leaf; FromUrl; Tool }.
function Get-TcpkMcpSavedFiles {
    param($Statement, [string]$Kind)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $add = {
        param([string]$Path, [bool]$FromUrl, [string]$Tool)
        $v = "$Path".Trim().Trim([char]34).Trim([char]39)
        if ($FromUrl) {
            $v = @($v -split '[?#]')[0]
            $v = $v -replace '^[A-Za-z][A-Za-z0-9+.-]*://[^/]*', ''
        }
        $v = $v.TrimEnd('\', '/')
        if (-not $v) { return }
        if ($v -match '^(nul|/dev/null|\$null|-|&\d)$') { return }
        $segs = @($v -split '[\\/]')
        $leaf = "$($segs[$segs.Count - 1])"
        if (-not $leaf) { return }
        $out.Add([pscustomobject]@{ Path = $v; Leaf = $leaf; FromUrl = $FromUrl; Tool = $Tool })
    }
    $rxUrl = Get-TcpkMcpRx '^(https?|ftp)://' -IgnoreCase

    foreach ($words in $Statement.Commands) {
        $n = $words.Count
        if ($n -eq 0) { continue }
        $tool = Get-TcpkMcpLeaf "$($words[0])"
        $hasExe = ("$($words[0])" -match '\.exe$')
        $isPsTool = ($tool -match '^(iwr|irm|invoke-webrequest|invoke-restmethod)$')
        $explicit = $false
        $remoteName = $false
        for ($k = 1; $k -lt $n; $k++) {
            $w = "$($words[$k])"
            $next = $null
            if (($k + 1) -lt $n) { $next = "$($words[$k + 1])" }
            $m = [regex]::Match($w, '^--(?:output|output-document|out)=(?<p>.+)$')
            if ($m.Success) { & $add $m.Groups['p'].Value $false $tool; $explicit = $true; continue }
            $m = [regex]::Match($w, '^-outfile:(?<p>.+)$', 'IgnoreCase')
            if ($m.Success) { & $add $m.Groups['p'].Value $false $tool; $explicit = $true; continue }
            if ($w -cmatch '^--(output|output-document|out)$') {
                if ($null -ne $next) { & $add $next $false $tool }
                $explicit = $true; $k++; continue
            }
            if ($w -match '^-(ou|out|outf|outfi|outfil|outfile)$' -or ($isPsTool -and $w -match '^-o$')) {
                if ($null -ne $next) { & $add $next $false $tool }
                $explicit = $true; $k++; continue
            }
            if ($tool -ceq 'start-bitstransfer' -and $w -match '^-d[a-z]*$') {
                if ($null -ne $next) { & $add $next $false $tool }
                $explicit = $true; $k++; continue
            }
            if ($w -cmatch '^-[A-Za-z]*O-$') { $explicit = $true; continue }          # wget -O- : standard output
            if ($w -cmatch '^-[A-Za-z]*O$') {
                $plainNext = ($null -ne $next -and (-not $next.StartsWith('-') -or $next -ceq '-') -and (-not $rxUrl.IsMatch($next)))
                if ($tool -ceq 'wget' -or ($Kind -ceq 'powershell' -and $tool -ceq 'curl' -and (-not $hasExe) -and $plainNext)) {
                    if ($null -ne $next) { & $add $next $false $tool }
                    $explicit = $true; $k++; continue
                }
                $remoteName = $true                                                   # curl -O
                continue
            }
            if ($w -cmatch '^-[A-Za-z]*o$' -and $tool -cne 'wget') {
                if ($null -ne $next) { & $add $next $false $tool }
                $explicit = $true; $k++; continue
            }
            if ($w -cmatch '^--remote-name(-all)?$') { $remoteName = $true; continue }
        }
        if ((-not $explicit) -and $tool -match '^(certutil|bitsadmin|start-bitstransfer)$') {
            for ($k = 1; $k -lt ($n - 1); $k++) {
                if (-not $rxUrl.IsMatch("$($words[$k])")) { continue }
                $next = "$($words[$k + 1])"
                if ($next.StartsWith('-') -or $rxUrl.IsMatch($next)) { continue }
                & $add $next $false $tool
                $explicit = $true
            }
        }
        if ($remoteName -or ((-not $explicit) -and $tool -match '^(wget|aria2c)$')) {
            for ($k = 1; $k -lt $n; $k++) {
                if ($rxUrl.IsMatch("$($words[$k])")) { & $add "$($words[$k])" $true $tool }
            }
        }
    }

    $text = "$($Statement.Text)"
    foreach ($m in (Get-TcpkMcpRx '(?<![0-9A-Za-z&>|=-])>{1,2}\s*(?:"(?<p>[^"]+)"|(?<p>[^\s"&|;<>()]+))').Matches($text)) {
        & $add $m.Groups['p'].Value $false 'a redirection'
    }
    foreach ($m in (Get-TcpkMcpRx 'DownloadFile(?:Async|TaskAsync)?\s*\(\s*(?:"[^"]*"|''[^'']*''|[^,()]+)\s*,\s*(?:"(?<p>[^"]*)"|''(?<p>[^'']*)''|(?<p>[^)\s]+))' -IgnoreCase).Matches($text)) {
        & $add $m.Groups['p'].Value $false 'DownloadFile'
    }
    return ,$out.ToArray()
}

# Does a later statement use a saved file? A program or script file counts when the
# statement names it again; any other file only when it is what a command of the statement
# runs. Returns 'names', 'runs' or ''.
function Test-TcpkMcpSavedFileUsed {
    param($Statement, $Saved)
    $leaf = "$($Saved.Leaf)"
    if (-not $leaf) { return '' }
    if ($leaf -match $script:TcpkMcpProgramExtRx) {
        $again = '(?<![A-Za-z0-9_.+-])' + [regex]::Escape($leaf) + '(?![A-Za-z0-9_.-])'
        if ((Get-TcpkMcpRx $again -IgnoreCase).IsMatch("$($Statement.Text)")) { return 'names' }
        return ''
    }
    $savedHasDir = ("$($Saved.Path)" -match '[\\/]')
    foreach ($words in $Statement.Commands) {
        $n = $words.Count
        $k = 0
        while ($k -lt $n) {
            $w = "$($words[$k])"
            if (-not $w -or $w -ceq '.') { $k++; continue }
            $lw = Get-TcpkMcpLeaf $w
            if ($lw -match '^(exec|sudo|call|start|nohup|command|env|source|sh|bash|zsh|dash|ksh|python[0-9.]*|py|node|perl|ruby|php|pwsh|powershell|start-process|saps|invoke-item|ii|chmod)$') {
                $k++
                while ($k -lt $n) {
                    $o = "$($words[$k])"
                    if (-not $o) { $k++; continue }
                    if ($o.StartsWith('-') -or $o.StartsWith('+')) { $k++; continue }
                    if ($lw -ceq 'chmod' -and $o -match '^([0-7]{3,4}|[ugoa]*[+=-][rwxXst]+)$') { $k++; continue }
                    if ($lw -ceq 'start' -and $o -match '^/[A-Za-z]+$') { $k++; continue }
                    break
                }
                continue
            }
            break
        }
        if ($k -ge $n) { continue }
        $cand = "$($words[$k])".Trim().Trim([char]34).Trim([char]39)
        $segs = @($cand -split '[\\/]')
        if (-not [string]::Equals("$($segs[$segs.Count - 1])", $leaf, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($savedHasDir -and $segs.Count -gt 1 -and $cand -notmatch '^\.[\\/]') {
            if ((ConvertTo-TcpkMcpNormPath $cand) -ne (ConvertTo-TcpkMcpNormPath "$($Saved.Path)")) { continue }
        }
        return 'runs'
    }
    return ''
}

# Download-and-execute test for an inline script. Two primitives merely being present in
# the same string is NOT enough (a health check followed by starting a fixed program has
# both). A hit needs them to be RELATED:
#   same statement  one statement holds a download primitive and an evaluation primitive
#                   (the fetched text is evaluated or piped into an interpreter)
#   file handed on  a shell statement saves a file from a literal remote location (see
#                   Get-TcpkMcpSavedFiles), and a later statement names that program or
#                   script file again, or runs the file; in a node / python / ruby / perl /
#                   php one-liner, the requesting statement writes a program or script file
#                   and the file is named again after the write
#   remote host arg a script-host style program is given a remote location directly
#   shell-out       a node / python / ruby / perl / php one-liner passes a command line to
#                   a shell, and that command line is itself a hit
# Returns { Hit; Why }. Why is the wording a finding prints.
function Test-TcpkMcpDownloadExec {
    param([string]$Kind, [AllowNull()][string]$Script)
    $res = [pscustomobject]@{ Hit = $false; Why = '' }
    if ([string]::IsNullOrWhiteSpace($Script)) { return $res }
    $text = $Script
    if ($text.Length -gt $script:TcpkMcpScanLimit) { $text = $text.Substring(0, $script:TcpkMcpScanLimit) }
    $fetch = ''
    $exec = ''
    $shellOut = ''
    $whole = $false          # mshta script URLs are one expression: no statement split
    $shell = ($Kind -ceq 'cmd' -or $Kind -ceq 'powershell' -or $Kind -ceq 'posix-shell')

    try {
        if ($Kind -ceq 'cmd' -or $Kind -ceq 'powershell') {
            $host1 = (Get-TcpkMcpRx '\b(mshta(\.exe)?\s+"?(https?:|\\\\)|regsvr32(\.exe)?\b[^&|]*/i:"?(https?:|\\\\)|msiexec(\.exe)?\b[^&|]*/(i|package)\s+"?(https?:|\\\\)|rundll32(\.exe)?\s+"?\\\\)' -IgnoreCase).Match($text)
            if ($host1.Success) {
                $res.Hit = $true
                $res.Why = "calls $(@($host1.Value -split '\s+')[0]) with a remote location"
                return $res
            }
        }

        switch ($Kind) {
            'powershell' {
                $fetch = '\b(iwr|irm|curl|wget|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadString|DownloadFile|DownloadData|OpenRead|WebClient|HttpClient|HttpWebRequest|bitsadmin|certutil)\b'
                $exec  = '\b(iex|Invoke-Expression)\b|\[scriptblock\]::Create|Assembly\]::Load|\|\s*(powershell|pwsh|cmd)(\.exe)?\b'
            }
            'posix-shell' {
                # An interpreter counts only when it reads the piped text as its program (no
                # further arguments): "| python3 -m json.tool" formats the data, it does not run it.
                $fetch = '\b(curl|wget|aria2c)\b'
                $exec  = '\|\s*(sudo\s+)?(ba|z|da|k|a)?sh\b|\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|node|php)(\s+-)?\s*($|[)"''])|\b(ba|z|da|k)?sh\s+<\(|\beval\s+["'']?(\$\(|`)|\b(source|\.)\s+<\(|(^|-c\s+)\s*["'']?(\$\(|`)\s*(curl|wget)\b'
            }
            'node' {
                $fetch = '\bhttps?\.(get|request)\b|\bfetch\s*\(|\baxios\b|XMLHttpRequest|require\(\s*[''"]https?[''"]\s*\)|import\s*\(\s*[''"]https?:'
                $exec  = '\beval\b|new\s+Function\b|vm\.run|runInThisContext|runInNewContext|import\s*\(\s*[''"]https?:'
                $shellOut = 'child_process|\bexecSync\b|\bexecFile(Sync)?\b|\bspawn(Sync)?\b|\bexec\s*\('
            }
            'python' {
                # A network CALL, not a module name: "import urllib.parse" downloads nothing.
                $fetch = '\burlopen\s*\(|\burlretrieve\s*\(|\brequests\.(get|post|request)\s*\(|\bhttpx\.(get|post|request|stream)\s*\(|\bHTTPS?Connection\s*\('
                $exec  = '(?<![.\w])exec\s*\(|(?<![.\w])eval\s*\(|(?<![.\w])compile\s*\('
                $shellOut = 'os\.system|\bsubprocess\b|os\.popen|pty\.spawn'
            }
            'script' {
                $fetch = 'open-uri|Net::HTTP|LWP::|HTTP::Tiny|file_get_contents\s*\(\s*[''"]https?:'
                $exec  = '\beval\b'
                $shellOut = '\bsystem\s*\(|\bexec\s*\(|`|\bpopen\b|passthru|shell_exec'
            }
            'mshta' {
                $fetch = 'https?://|\\\\[A-Za-z0-9]|XMLHTTP'
                $exec  = 'GetObject|\beval\b|\bExecute|\.Run\b|\.Exec\b|WScript\.Shell|ActiveXObject'
                $whole = $true
            }
            'cmd' {
                # A cmd script can carry a PowerShell command line.
                $ps = Test-TcpkMcpDownloadExec -Kind 'powershell' -Script $text
                if ($ps.Hit) { return $ps }
                $fetch = '\b(curl|wget|certutil|bitsadmin)(\.exe)?\b'
                $exec  = '\|\s*(cmd|powershell|pwsh)(\.exe)?\b'
            }
            default { return $res }
        }

        $stmts = New-Object 'System.Collections.Generic.List[object]'
        if ($whole) { $stmts.Add([pscustomobject]@{ Text = $text; Commands = @() }) }
        elseif ($shell) {
            foreach ($st in (Get-TcpkMcpStatements -Script $text -Kind $Kind)) { $stmts.Add($st) }
        } else {
            foreach ($p in (Get-TcpkMcpRx '[;\r\n]+|&&|\|\|').Split($text)) {
                if ("$p".Trim()) { $stmts.Add([pscustomobject]@{ Text = "$p"; Commands = @() }) }
            }
        }

        $rxFetch = Get-TcpkMcpRx $fetch -IgnoreCase
        $rxExec = Get-TcpkMcpRx $exec -IgnoreCase
        $rxRemote = Get-TcpkMcpRx '\b(https?|ftp)://|\\\\[A-Za-z0-9]' -IgnoreCase
        for ($i = 0; $i -lt $stmts.Count; $i++) {
            $st = $stmts[$i]
            $mf = $rxFetch.Match("$($st.Text)")
            if (-not $mf.Success) { continue }
            $me = $rxExec.Match("$($st.Text)")
            if ($me.Success) {
                # the matched text without a leading separator or the "(" of a call
                $got = ($mf.Value -replace '(?<=[A-Za-z0-9_])\s*\($', '').Trim()
                $ran = (($me.Value -replace '^[\s;|{(]+', '') -replace '(?<=[A-Za-z0-9_])\s*\($', '').Trim()
                $res.Hit = $true
                $res.Why = "holds a download primitive ($got) and an evaluation primitive ($ran) in one statement"
                return $res
            }
            if ($whole) { continue }
            if (-not $rxRemote.IsMatch("$($st.Text)")) { continue }

            if ($shell) {
                foreach ($sv in (Get-TcpkMcpSavedFiles -Statement $st -Kind $Kind)) {
                    for ($j = $i + 1; $j -lt $stmts.Count; $j++) {
                        $use = Test-TcpkMcpSavedFileUsed -Statement $stmts[$j] -Saved $sv
                        if (-not $use) { continue }
                        $got = "$($sv.Tool)"
                        if (-not $got -or $got -match '^(a redirection|DownloadFile)$') { $got = $mf.Value.Trim() }
                        $how = "names '$($sv.Leaf)' again"
                        if ($use -ceq 'runs') { $how = "runs '$($sv.Leaf)'" }
                        $res.Hit = $true
                        if ($sv.FromUrl) { $res.Why = "downloads '$($sv.Leaf)' from a remote location with $got under its remote name, and a later statement $how" }
                        else { $res.Why = "downloads from a remote location with $got to '$($sv.Leaf)', and a later statement $how" }
                        return $res
                    }
                }
                continue
            }

            # node / python / ruby / perl / php: the statement writes a program or script file
            # (an output position of a write call, not any name it happens to mention), and
            # that file is named again after the write
            foreach ($wm in (Get-TcpkMcpRx $script:TcpkMcpCodeWriteRx -IgnoreCase).Matches("$($st.Text)")) {
                $wp = $wm.Groups['p'].Value.TrimEnd('\', '/')
                $segs = @($wp -split '[\\/]')
                $leaf = "$($segs[$segs.Count - 1])"
                if (-not $leaf -or $leaf -notmatch $script:TcpkMcpProgramExtRx) { continue }
                $rxAgain = Get-TcpkMcpRx ('(?<![A-Za-z0-9_.+-])' + [regex]::Escape($leaf) + '(?![A-Za-z0-9_.-])') -IgnoreCase
                $where = ''
                $after = "$($st.Text)".Substring($wm.Index + $wm.Length)
                if ($rxAgain.IsMatch($after)) { $where = 'the same statement names it again' }
                for ($j = $i + 1; (-not $where) -and $j -lt $stmts.Count; $j++) {
                    if ($rxAgain.IsMatch("$($stmts[$j].Text)")) { $where = 'a later statement names it again' }
                }
                if ($where) {
                    $got = ($mf.Value -replace '(?<=[A-Za-z0-9_])\s*\($', '').Trim()
                    $res.Hit = $true
                    $res.Why = "requests a remote location with $got, writes '$leaf', and $where"
                    return $res
                }
            }
        }
        if ($shellOut -and (Get-TcpkMcpRx $shellOut -IgnoreCase).IsMatch($text)) {
            foreach ($k in @('posix-shell', 'powershell', 'cmd')) {
                $nested = Test-TcpkMcpDownloadExec -Kind $k -Script $text
                if ($nested.Hit) {
                    $nested.Why = "passes a command line to a shell, and that command line $($nested.Why)"
                    return $nested
                }
            }
        }
    } catch { }
    return $res
}

# Script-host style launchers given a remote location directly (no inline script).
# Returns { Hit; Why }.
function Test-TcpkMcpScriptHostRemote {
    param([string]$Leaf, [string[]]$Argv)
    $res = [pscustomobject]@{ Hit = $false; Why = '' }
    $n = 0
    if ($null -ne $Argv) { $n = $Argv.Count }
    $remote = '^"?(https?://|\\\\[^\\?.]|//[^/]+/)'
    if ($Leaf -ceq 'mshta') {
        foreach ($a in $Argv) {
            if ("$a" -match $remote) { $res.Hit = $true; $res.Why = 'mshta is given a remote location, which it downloads and runs as an HTML application'; break }
        }
    } elseif ($Leaf -ceq 'rundll32') {
        if ($n -gt 0 -and "$($Argv[0])" -match $remote) { $res.Hit = $true; $res.Why = 'rundll32 is given a DLL on a network path, which it loads and runs' }
    } elseif ($Leaf -ceq 'regsvr32') {
        foreach ($a in $Argv) {
            if ("$a" -match '^/i:"?(https?://|\\\\)' -or "$a" -match $remote) { $res.Hit = $true; $res.Why = 'regsvr32 is given a remote location, which it downloads and runs'; break }
        }
    } elseif ($Leaf -ceq 'msiexec') {
        for ($i = 0; $i -lt ($n - 1); $i++) {
            if ("$($Argv[$i])" -match '^[-/](i|package|a)$' -and "$($Argv[$i + 1])" -match $remote) {
                $res.Hit = $true; $res.Why = 'msiexec is given a package at a remote location, which it downloads and installs'; break
            }
        }
    } elseif ($Leaf -ceq 'wscript' -or $Leaf -ceq 'cscript') {
        foreach ($a in $Argv) {
            if ("$a" -match '^//[A-Za-z][A-Za-z:]*$') { continue }
            if ("$a" -match $remote) { $res.Hit = $true; $res.Why = "$Leaf is given a script on a network path, which it loads and runs" }
            break
        }
    }
    return $res
}

# Resolve what a server entry really starts.
#   * Unwraps "cmd /c <program> <args...>" given as separate tokens, and "wsl <program> ...".
#     The wrapper is not a finding: the inner program is what the other rules look at.
#   * Records an inline script: a single script string after cmd /c, a cmd command line that
#     carries an operator cmd will read (a standalone & && | || token, or & / | inside a
#     token the host passes unquoted), or an interpreter switch (-c, -Command,
#     -EncodedCommand, -e ...).
#   * Runs the download-and-execute test over every inline script and the script-host forms.
#   * Splits every shell inline script into its simple commands and resolves each one the
#     same way (Segments), so a package runner, a filesystem server or a remote bridge that
#     is started from inside a script string is still seen by the package, filesystem-scope
#     and endpoint rules.
# Metacharacters are never tested against the arguments of a directly executed program.
# Returns { Command; Leaf; Args; Inline; Inlines; DownloadExec; DownloadWhy; Interpreter;
# Segments }. Inline is the innermost inline script, Inlines every one found on the way.
# Each segment is { Launcher; Package; Inner; Cwd } with Launcher shaped like this result.
# Cwd is the directory an earlier "cd" / "pushd" / "Set-Location" of the same script
# changed to ('' when there was none), so a relative script path can be placed.
function Resolve-TcpkMcpLauncher {
    param([AllowNull()][string]$Command, [string[]]$Arguments, [int]$Depth = 0)
    $cmd = "$Command".Trim()
    $argv = @()
    if ($null -ne $Arguments) { $argv = $Arguments }
    $inlines  = New-Object 'System.Collections.Generic.List[object]'

    for ($hop = 0; $hop -lt 4; $hop++) {
        $leaf = Get-TcpkMcpLeaf $cmd
        if ($leaf -ceq 'cmd') {
            $n = $argv.Count
            $sw = -1
            $i = 0
            while ($i -lt $n) {
                $a = "$($argv[$i])"
                if ($a -match '^/[ck]$') { $sw = $i; break }
                if ($a -match '^/[a-z](:[a-z]+)?$') { $i++; continue }
                break
            }
            if ($sw -lt 0) { break }
            $rest = Get-TcpkMcpTail $argv ($sw + 1)
            if ($rest.Count -eq 0) { break }
            if ($rest.Count -eq 1) {
                $one = "$($rest[0])".Trim()
                $hasMeta = ($one -match '[&|<>^]')
                $isBare = ((-not $hasMeta) -and ($one -notmatch '\s'))
                $isPath = ((-not $hasMeta) -and
                           ($one -match '^"?(?:[A-Za-z]:[\\/]|\\\\|//|\.{1,2}[\\/]|%[A-Za-z_0-9()]+%)[^"]*\.(exe|cmd|bat|com|ps1)"?$') -and
                           ($one -notmatch '\.(exe|cmd|bat|com|ps1)"?\s'))
                if ($isBare -or $isPath) {
                    $cmd = $one.Trim([char]34)
                    $argv = @()
                    continue
                }
                $il = New-TcpkMcpInline -Kind 'cmd' -Shell 'cmd' -Option "$($argv[$sw])" -Script $one
                $inlines.Add($il)
                if (-not $hasMeta) {
                    $toks = Split-TcpkMcpCommandLine $one
                    if ($toks.Count -gt 0) {
                        # one command and its arguments in one string: analysed as the launcher
                        $il.Unwrapped = $true
                        $cmd = "$($toks[0])"
                        $argv = Get-TcpkMcpTail $toks 1
                        continue
                    }
                }
                break
            }
            # A token that IS an operator, or that carries & or | with no whitespace and no
            # quote in it: the host passes such a token to cmd unquoted, so cmd reads the
            # operator. (A token with whitespace is quoted by the host and stays literal.)
            $hasOp = $false
            foreach ($t in $rest) {
                if ("$t" -match '^(&|&&|\||\|\|)$') { $hasOp = $true; break }
                # not a redirection (2>&1) and not caret-escaped (^&)
                if ("$t" -match '(?<![>^])&|(?<!\^)\|' -and "$t" -notmatch '[\s"]') { $hasOp = $true; break }
            }
            if ($hasOp) {
                # the command line as cmd receives it: a token with whitespace arrives quoted
                $line = New-Object 'System.Collections.Generic.List[string]'
                foreach ($t in $rest) {
                    if ("$t" -match '\s' -and "$t" -notmatch '"') { $line.Add('"' + "$t" + '"') } else { $line.Add("$t") }
                }
                $inlines.Add((New-TcpkMcpInline -Kind 'cmd' -Shell 'cmd' -Option "$($argv[$sw])" -Script ($line.ToArray() -join ' ')))
                break
            }
            $cmd = "$($rest[0])"
            $argv = Get-TcpkMcpTail $rest 1
            continue
        }
        if ($leaf -ceq 'wsl') {
            $n = $argv.Count
            $start = -1
            $i = 0
            while ($i -lt $n) {
                $a = "$($argv[$i])"
                if ($a -ceq '--' -or $a -cmatch '^(-e|--exec)$') { $start = $i + 1; break }
                if ($a -cmatch '^(-d|--distribution|-u|--user|--cd|--shell-type)$') { $i += 2; continue }
                if ($a.StartsWith('-')) { $i++; continue }
                $start = $i
                break
            }
            if ($start -lt 0 -or $start -ge $n) { break }
            $cmd = "$($argv[$start])"
            $argv = Get-TcpkMcpTail $argv ($start + 1)
            continue
        }
        break
    }

    $leaf = Get-TcpkMcpLeaf $cmd
    $interp = Get-TcpkMcpInterpreter -Leaf $leaf -Argv $argv
    if ($null -ne $interp.Inline) { $inlines.Add($interp.Inline) }

    $dlHit = $false
    $dlWhy = ''
    foreach ($il in $inlines) {
        $t = Test-TcpkMcpDownloadExec -Kind $il.Kind -Script $il.Script
        if ($t.Hit) {
            $dlHit = $true
            $what = 'inline script'
            if ($il.Encoded) { $what = 'encoded command (decoded for this check)' }
            $dlWhy = "the $what passed to $($il.Shell) ($($il.Option)) $($t.Why)"
            break
        }
    }
    if (-not $dlHit) {
        $t = Test-TcpkMcpScriptHostRemote -Leaf $leaf -Argv $argv
        if ($t.Hit) { $dlHit = $true; $dlWhy = $t.Why }
    }

    # the simple commands inside the shell inline scripts
    $segments = New-Object 'System.Collections.Generic.List[object]'
    if ($Depth -lt 2) {
        foreach ($il in $inlines) {
            if ($il.Unwrapped -or (-not $il.Script)) { continue }
            if ($il.Kind -cne 'cmd' -and $il.Kind -cne 'posix-shell' -and $il.Kind -cne 'powershell') { continue }
            $made = 0
            $segCwd = ''
            foreach ($c in (Split-TcpkMcpScript -Script $il.Script -Kind $il.Kind)) {
                if ($made -ge 64) { break }
                if ($c.Words.Count -gt 1 -and "$($c.Words[0])" -match '^(cd|chdir|pushd|set-location|sl)$') {
                    for ($d = 1; $d -lt $c.Words.Count; $d++) {
                        $dw = "$($c.Words[$d])"
                        if ($dw -match '^(/d|-path|-literalpath)$') { continue }
                        $segCwd = Join-TcpkMcpPath -Base $segCwd -Child $dw
                        break
                    }
                    continue
                }
                $inner = Get-TcpkMcpInnerCommand -Words $c.Words -Kind $il.Kind
                if ($null -eq $inner) { continue }
                $made++
                $sub = Resolve-TcpkMcpLauncher -Command $inner.Command -Arguments $inner.Args -Depth ($Depth + 1)
                if ($sub.DownloadExec -and -not $dlHit) {
                    $dlHit = $true
                    $dlWhy = "a command inside the inline script passed to $($il.Shell) ($($il.Option)): $($sub.DownloadWhy)"
                }
                $pk = Get-TcpkMcpPackageInfo -Leaf $sub.Leaf -Argv $sub.Args
                $known = [bool]$pk.Launcher
                if ((-not $known) -and $sub.Interpreter.Kind -and ($sub.Interpreter.ScriptPath -or $sub.Interpreter.ScriptIndex -ge 0)) { $known = $true }
                if ((-not $known) -and ("$($sub.Leaf)" -match $script:TcpkMcpFsNameRx -or "$($sub.Leaf)" -match $script:TcpkMcpBridgeRx)) { $known = $true }
                # a program named by its path: the launch-target rule looks at where it is
                if ((-not $known) -and (Test-TcpkMcpPathLike $sub.Command)) { $known = $true }
                if ($known) { $segments.Add([pscustomobject]@{ Launcher = $sub; Package = $pk; Inner = $true; Cwd = $segCwd }) }
                foreach ($x in $sub.Segments) { $segments.Add($x) }
            }
        }
    }

    $inline = $null
    if ($inlines.Count -gt 0) { $inline = $inlines[$inlines.Count - 1] }
    return [pscustomobject]@{
        Command      = $cmd
        Leaf         = $leaf
        Args         = $argv
        Inline       = $inline
        Inlines      = $inlines.ToArray()
        DownloadExec = $dlHit
        DownloadWhy  = $dlWhy
        Interpreter  = $interp
        Segments     = $segments.ToArray()
    }
}

# ---------------------------------------------------------------------------
# package pinning
# ---------------------------------------------------------------------------

$script:TcpkMcpExactSemVer = '^[v=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$'
$script:TcpkMcpCommitRef   = '^[0-9a-fA-F]{7,40}$'

function Test-TcpkMcpPinnedRef {
    param([AllowNull()][string]$Ref)
    if ([string]::IsNullOrWhiteSpace($Ref)) { return $false }
    $r = $Ref.Trim()
    if ($r -match '^semver:') { $r = $r.Substring(7) }
    return (($r -match $script:TcpkMcpCommitRef) -or ($r -match $script:TcpkMcpExactSemVer))
}

# Classify one package / image specifier.
# Returns { Spec; Name; Kind; Pinned; Why } with Kind in
#   registry | git | image   evaluated: Pinned and Why are meaningful
#   local                    a path on disk, not a package
#   url | unknown            not evaluated (no claim is made either way)
function Get-TcpkMcpSpecInfo {
    param([AllowNull()][string]$Spec, [ValidateSet('npm', 'python', 'deno', 'image')][string]$Eco)
    $s = "$Spec".Trim().Trim([char]34).Trim([char]39)
    $r = [pscustomobject]@{ Spec = $s; Name = ''; Kind = 'unknown'; Pinned = $false; Why = '' }
    if (-not $s) { return $r }

    if ($Eco -ceq 'image') {
        if ($s -match '^[./~\\-]' -or $s -match '^[A-Za-z]:[\\/]' -or $s.IndexOf('=') -ge 0) { return $r }
        $m = [regex]::Match($s, '^(?<repo>[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]+)?(?:/[A-Za-z0-9._-]+)*)(?::(?<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?(?:@(?<dig>sha256:[A-Fa-f0-9]{64}))?$')
        if (-not $m.Success) { return $r }
        $r.Kind = 'image'
        $r.Name = $m.Groups['repo'].Value
        if ($m.Groups['dig'].Success) { $r.Pinned = $true; return $r }
        if ($m.Groups['tag'].Success) { $r.Why = "tag ':$($m.Groups['tag'].Value)' with no digest" }
        else { $r.Why = 'no tag and no digest' }
        return $r
    }

    $spec = $s
    if ($Eco -ceq 'deno') {
        $m = [regex]::Match($spec, '^(npm|jsr):/?(?<rest>.+)$')
        if (-not $m.Success) {
            if ($spec -match '^https?://') { $r.Kind = 'url' } else { $r.Kind = 'local' }
            return $r
        }
        $spec = $m.Groups['rest'].Value
        # name@version/subpath: the subpath is not part of the version
        $at = $spec.LastIndexOf('@')
        if ($at -gt 0) {
            $slash = $spec.IndexOf('/', $at)
            if ($slash -gt 0) { $spec = $spec.Substring(0, $slash) }
        } else {
            $segs = @($spec -split '/')
            if ($spec.StartsWith('@') -and $segs.Count -gt 2) { $spec = "$($segs[0])/$($segs[1])" }
            elseif ((-not $spec.StartsWith('@')) -and $segs.Count -gt 1) { $spec = "$($segs[0])" }
        }
    }

    # a path on disk
    if ($spec -match '^(\.{1,2}([\\/]|$)|[\\/]|~([\\/]|$)|[A-Za-z]:[\\/]|file:|%[A-Za-z_]+%|\$)') { $r.Kind = 'local'; return $r }
    if ($Eco -ceq 'python' -and $spec -match '\.(py|pyz|whl)$') { $r.Kind = 'local'; return $r }
    if ($Eco -cne 'python' -and $spec -match '\.(m?js|cjs|mts|ts|tgz)$' -and $spec -notmatch '^[a-z+]+:') { $r.Kind = 'local'; return $r }

    # git sources
    $gitRef = $null
    $isGit = $false
    if ($Eco -ceq 'python') {
        $direct = [regex]::Match($spec, '^(?:[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*@\s*)?(?<u>(?:git\+)?[a-z][a-z0-9+.-]*://.+)$')
        if ($direct.Success) {
            $u = $direct.Groups['u'].Value
            if ($u -notmatch '^git\+' -and $u -notmatch '\.git(@|#|$)') { $r.Kind = 'url'; return $r }
            $isGit = $true
            $u = ($u -split '#')[0]
            $afterScheme = $u.Substring($u.IndexOf('://') + 3)
            $firstSlash = $afterScheme.IndexOf('/')
            $pathPart = ''
            if ($firstSlash -ge 0) { $pathPart = $afterScheme.Substring($firstSlash) }
            $at = $pathPart.LastIndexOf('@')
            if ($at -ge 0) { $gitRef = $pathPart.Substring($at + 1) }
            $r.Name = $u
        }
    } else {
        if ($spec -match '^(git\+|git://|github:|gitlab:|bitbucket:|gist:)' -or $spec -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$') {
            $isGit = $true
            $hash = $spec.IndexOf('#')
            if ($hash -ge 0) { $gitRef = $spec.Substring($hash + 1); $r.Name = $spec.Substring(0, $hash) }
            else { $r.Name = $spec }
        } elseif ($spec -match '^https?://') { $r.Kind = 'url'; return $r }
    }
    if ($isGit) {
        $r.Kind = 'git'
        if (Test-TcpkMcpPinnedRef $gitRef) { $r.Pinned = $true }
        elseif ($gitRef) { $r.Why = "git ref '$gitRef' is a branch or tag name, not a commit or exact version" }
        else { $r.Why = 'git source with no commit or version ref' }
        return $r
    }

    if ($Eco -ceq 'python') {
        $m = [regex]::Match($spec, '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?<extras>\[[^\]]*\])?(?<rest>.*)$')
        if (-not $m.Success -or $m.Groups['name'].Value -notmatch '[A-Za-z]') { return $r }
        $r.Kind = 'registry'
        $r.Name = $m.Groups['name'].Value
        $rest = $m.Groups['rest'].Value.Trim()
        if (-not $rest) { $r.Why = 'no version'; return $r }
        # "==" is an exact match by definition; the "name@version" form needs at least X.Y
        $pin = [regex]::Match($rest, '^(?<op>===?|@)\s*(?<v>[0-9][0-9A-Za-z.!+_-]*)$')
        if ($pin.Success -and $pin.Groups['v'].Value -notmatch '\*') {
            if ($pin.Groups['op'].Value -cne '@' -or $pin.Groups['v'].Value -match '^\d+(\.\d+)+') {
                $r.Pinned = $true
                return $r
            }
        }
        if ($rest -notmatch '^(===?|@|[<>~!]=?|,|;|\s)') { $r.Kind = 'unknown'; $r.Why = ''; return $r }
        $r.Why = "'$rest' is a tag or range, not an exact version"
        return $r
    }

    # npm / deno registry spec: [@scope/]name[@version]. Only an '@' after index 0 separates
    # the version: index 0 is the scope marker.
    $name = $spec
    $ver = $null
    $at = $spec.LastIndexOf('@')
    if ($at -gt 0) { $name = $spec.Substring(0, $at); $ver = $spec.Substring($at + 1) }
    if ($name -notmatch '^(@[A-Za-z0-9~][A-Za-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$') { return $r }
    $r.Kind = 'registry'
    $r.Name = $name
    if ($null -eq $ver -or $ver -eq '') { $r.Why = 'no version'; return $r }
    if ($ver -match $script:TcpkMcpExactSemVer) { $r.Pinned = $true; return $r }
    $r.Why = "'@$ver' is a tag or range, not an exact version"
    return $r
}

# Fetch-and-run launchers. Returns
#   { Launcher; Refs; ArgStart; LocalTarget; Directory; Mounts }
# Launcher is '' when the command is not one of them. Refs are Get-TcpkMcpSpecInfo records
# for what the launcher resolves at start. ArgStart is the index of the first argument that
# belongs to the server itself. LocalTarget is a local script the launcher runs, Directory
# the project directory it runs from, Mounts the host side of container bind mounts.
function Get-TcpkMcpPackageInfo {
    param([string]$Leaf, [string[]]$Argv)
    $r = [pscustomobject]@{ Launcher = ''; Refs = @(); ArgStart = 0; LocalTarget = ''; Directory = ''; Mounts = @() }
    $refs = New-Object 'System.Collections.Generic.List[object]'
    $n = 0
    if ($null -ne $Argv) { $n = $Argv.Count }

    $npmVal = @('-c', '--call', '--registry', '--userconfig', '--globalconfig', '--cache', '--prefix', '-w', '--workspace',
                '--node-options', '--loglevel', '--script-shell', '-C', '--dir', '--filter', '--cwd')
    $uvVal  = @('--directory', '--project', '--config-file', '--cache-dir', '--color', '--python-preference', '--allow-insecure-host',
                '-p', '--python', '--index', '--default-index', '-i', '--index-url', '--extra-index-url', '-f', '--find-links',
                '--index-strategy', '--keyring-provider', '-c', '--constraint', '--constraints', '--overrides', '--override',
                '--resolution', '--prerelease', '--exclude-newer', '--refresh-package', '-P', '--upgrade-package',
                '--reinstall-package', '--link-mode', '--env-file', '-C', '--config-setting', '--no-binary-package',
                '--no-build-package', '--python-platform', '--with-editable', '--with-requirements', '--group', '--extra',
                '--package', '--only-group', '--no-group', '--fork-strategy', '--torch-backend', '--managed-python')

    $npmStyle = {
        param([int]$From, [string[]]$PkgOpts, [string]$Label)
        $w = Get-TcpkMcpPositional -Argv $Argv -Start $From -ValueOpts $npmVal -PkgOpts $PkgOpts
        $r.Launcher = $Label
        if ($w.Packages.Count -gt 0) {
            foreach ($p in $w.Packages) { $refs.Add((Get-TcpkMcpSpecInfo -Spec $p -Eco 'npm')) }
        } elseif ($w.Index -ge 0) {
            $refs.Add((Get-TcpkMcpSpecInfo -Spec "$($Argv[$w.Index])" -Eco 'npm'))
        }
        if ($w.Index -ge 0) { $r.ArgStart = $w.Index + 1 } else { $r.ArgStart = $n }
    }
    $uvxStyle = {
        param([int]$From, [string]$Label)
        $w = Get-TcpkMcpPositional -Argv $Argv -Start $From -ValueOpts $uvVal -PkgOpts @('--from') -ExtraOpts @('--with', '-w')
        $r.Launcher = $Label
        if ($w.Packages.Count -gt 0) {
            foreach ($p in $w.Packages) { $refs.Add((Get-TcpkMcpSpecInfo -Spec $p -Eco 'python')) }
        } elseif ($w.Index -ge 0) {
            $refs.Add((Get-TcpkMcpSpecInfo -Spec "$($Argv[$w.Index])" -Eco 'python'))
        }
        foreach ($x in $w.Extras) {
            foreach ($one in @("$x" -split ',')) { if ($one.Trim()) { $refs.Add((Get-TcpkMcpSpecInfo -Spec $one -Eco 'python')) } }
        }
        if ($w.Index -ge 0) { $r.ArgStart = $w.Index + 1 } else { $r.ArgStart = $n }
    }

    if ($Leaf -ceq 'npx' -or $Leaf -ceq 'pnpx' -or $Leaf -ceq 'bunx') {
        & $npmStyle 0 @('-p', '--package') $Leaf
    } elseif ($Leaf -ceq 'npm' -or $Leaf -ceq 'pnpm' -or $Leaf -ceq 'yarn' -or $Leaf -ceq 'bun') {
        $w0 = Get-TcpkMcpPositional -Argv $Argv -Start 0 -ValueOpts $npmVal
        if ($w0.Index -ge 0) {
            $sub = "$($Argv[$w0.Index])"
            $want = @('dlx')
            if ($Leaf -ceq 'npm') { $want = @('exec', 'x') }
            if ($Leaf -ceq 'bun') { $want = @('x') }
            if ($want -ccontains $sub) { & $npmStyle ($w0.Index + 1) @('-p', '--package') "$Leaf $sub" }
        }
    } elseif ($Leaf -ceq 'uvx') {
        & $uvxStyle 0 'uvx'
    } elseif ($Leaf -ceq 'uv') {
        $w0 = Get-TcpkMcpPositional -Argv $Argv -Start 0 -ValueOpts $uvVal -ExtraOpts @('--directory', '--project')
        if ($w0.Extras.Count -gt 0) { $r.Directory = "$($w0.Extras[0])" }
        if ($w0.Index -ge 0) {
            $sub = "$($Argv[$w0.Index])"
            if ($sub -ceq 'tool') {
                $w1 = Get-TcpkMcpPositional -Argv $Argv -Start ($w0.Index + 1) -ValueOpts $uvVal
                if ($w1.Index -ge 0 -and "$($Argv[$w1.Index])" -ceq 'run') { & $uvxStyle ($w1.Index + 1) 'uv tool run' }
            } elseif ($sub -ceq 'run') {
                # uv run executes a local script or a command from the project
                # environment. Only --with names something fetched from a registry.
                $w1 = Get-TcpkMcpPositional -Argv $Argv -Start ($w0.Index + 1) -ValueOpts ($uvVal + @('-m', '--module')) -ExtraOpts @('--with', '-w', '--directory', '--project')
                $r.Launcher = 'uv run'
                foreach ($x in $w1.Extras) {
                    if ("$x" -match '^(\.{1,2}([\\/]|$)|[\\/]|~|[A-Za-z]:[\\/]|%|\$)') {
                        if (-not $r.Directory) { $r.Directory = "$x" }
                        continue
                    }
                    foreach ($one in @("$x" -split ',')) { if ($one.Trim()) { $refs.Add((Get-TcpkMcpSpecInfo -Spec $one -Eco 'python')) } }
                }
                if ($w1.Index -ge 0) {
                    $r.ArgStart = $w1.Index + 1
                    $target = "$($Argv[$w1.Index])"
                    if ($target -match '^(mcp|fastmcp)$' -and ($w1.Index + 2) -lt $n -and "$($Argv[$w1.Index + 1])" -ceq 'run') {
                        # "mcp run <file>": the file is what runs
                        $target = "$($Argv[$w1.Index + 2])"
                        $r.ArgStart = $w1.Index + 3
                    }
                    if ($target -match '[\\/]' -or $target -match '\.(py|pyw)$') { $r.LocalTarget = $target }
                } else { $r.ArgStart = $n }
            }
        }
    } elseif ($Leaf -ceq 'pipx') {
        $w0 = Get-TcpkMcpPositional -Argv $Argv -Start 0
        if ($w0.Index -ge 0 -and "$($Argv[$w0.Index])" -ceq 'run') {
            $w1 = Get-TcpkMcpPositional -Argv $Argv -Start ($w0.Index + 1) -ValueOpts @('--python', '--pip-args', '--index-url', '-i', '--backend') -PkgOpts @('--spec')
            $r.Launcher = 'pipx run'
            if ($w1.Packages.Count -gt 0) {
                foreach ($p in $w1.Packages) { $refs.Add((Get-TcpkMcpSpecInfo -Spec $p -Eco 'python')) }
            } elseif ($w1.Index -ge 0) {
                $refs.Add((Get-TcpkMcpSpecInfo -Spec "$($Argv[$w1.Index])" -Eco 'python'))
            }
            if ($w1.Index -ge 0) { $r.ArgStart = $w1.Index + 1 } else { $r.ArgStart = $n }
        }
    } elseif ($Leaf -ceq 'deno') {
        $denoVal = @('-c', '--config', '--import-map', '--lock', '--cert', '--location', '--seed', '-L', '--log-level', '--ext', '--env-file')
        $w0 = Get-TcpkMcpPositional -Argv $Argv -Start 0 -ValueOpts $denoVal
        if ($w0.Index -ge 0) {
            $idx = $w0.Index
            if ("$($Argv[$idx])" -cmatch '^(run|serve)$') {
                $w1 = Get-TcpkMcpPositional -Argv $Argv -Start ($idx + 1) -ValueOpts $denoVal
                $idx = $w1.Index
            }
            if ($idx -ge 0 -and "$($Argv[$idx])" -match '^(npm|jsr):') {
                $r.Launcher = 'deno run'
                $refs.Add((Get-TcpkMcpSpecInfo -Spec "$($Argv[$idx])" -Eco 'deno'))
                $r.ArgStart = $idx + 1
            }
        }
    } elseif ($Leaf -ceq 'docker' -or $Leaf -ceq 'podman' -or $Leaf -ceq 'nerdctl') {
        $w0 = Get-TcpkMcpPositional -Argv $Argv -Start 0 -ValueOpts @('-H', '--host', '-c', '--context', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey')
        $idx = $w0.Index
        if ($idx -ge 0 -and "$($Argv[$idx])" -ceq 'container') {
            $idx = (Get-TcpkMcpPositional -Argv $Argv -Start ($idx + 1)).Index
        }
        if ($idx -ge 0 -and "$($Argv[$idx])" -ceq 'run') {
            $runVal = @('-e', '--env', '--env-file', '-p', '--publish', '--name', '--network', '--net', '-w', '--workdir',
                        '-u', '--user', '--entrypoint', '-l', '--label', '--label-file', '--platform', '--pull', '-m', '--memory',
                        '--memory-swap', '--memory-reservation', '--cpus', '-c', '--cpu-shares', '--cpuset-cpus', '-h', '--hostname',
                        '--add-host', '--dns', '--dns-search', '--cap-add', '--cap-drop', '--security-opt', '--restart', '--runtime',
                        '--gpus', '--ipc', '--pid', '--shm-size', '--tmpfs', '--ulimit', '--device', '--group-add', '--volumes-from',
                        '--log-driver', '--log-opt', '--cidfile', '--stop-signal', '--stop-timeout', '--expose', '--link',
                        '--mac-address', '--ip', '--ip6', '--cgroupns', '--userns', '--uts', '--isolation', '-a', '--attach',
                        '--annotation', '--storage-opt', '--sysctl', '--pids-limit', '--oom-score-adj', '--detach-keys',
                        '--domainname', '--health-cmd', '--health-interval', '--health-retries', '--health-timeout',
                        '--health-start-period', '--network-alias', '--volume-driver', '--cgroup-parent', '--init-path')
            $w1 = Get-TcpkMcpPositional -Argv $Argv -Start ($idx + 1) -ValueOpts $runVal -ExtraOpts @('-v', '--volume', '--mount')
            $r.Launcher = "$Leaf run"
            if ($w1.Index -ge 0) {
                $refs.Add((Get-TcpkMcpSpecInfo -Spec "$($Argv[$w1.Index])" -Eco 'image'))
                $r.ArgStart = $w1.Index + 1
            } else { $r.ArgStart = $n }
            $mounts = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in $w1.Extras) {
                $mv = "$x"
                if ($mv -match '(^|,)type=') {
                    if ($mv -match '(^|,)type=bind(,|$)') {
                        $ms = [regex]::Match($mv, '(?:^|,)(?:src|source)=(?<p>[^,]*)')
                        if ($ms.Success) { $mounts.Add($ms.Groups['p'].Value) }
                    }
                } else {
                    $mm = [regex]::Match($mv, '^(?<p>[A-Za-z]:[\\/]?[^:]*|[^:]+):')
                    if ($mm.Success) { $mounts.Add($mm.Groups['p'].Value) }
                }
            }
            $r.Mounts = $mounts.ToArray()
        }
    }
    $r.Refs = $refs.ToArray()
    return $r
}

# ---------------------------------------------------------------------------
# paths: user-writable launch targets and broad filesystem roots
# ---------------------------------------------------------------------------

# Lower-case, backslash-separated form of a path-like string, without quotes or the \\?\
# prefix. A drive mounted in the Linux subsystem (/mnt/c/...) is written as that drive.
# Pure string work: nothing is resolved against the local machine.
function ConvertTo-TcpkMcpNormPath {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $p = $Value.Trim().Trim([char]34).Trim([char]39)
    $p = $p.Replace('/', '\')
    if ($p.StartsWith('\\?\') -or $p.StartsWith('\\.\')) { $p = $p.Substring(4) }
    $unc = $p.StartsWith('\\')
    $p = [regex]::Replace($p, '\\{2,}', '\')
    if ($unc) { $p = '\' + $p }
    $p = $p.ToLowerInvariant()
    $mnt = [regex]::Match($p, '^\\mnt\\([a-z])(\\|$)')
    if ($mnt.Success) { $p = $mnt.Groups[1].Value + ':\' + $p.Substring($mnt.Length) }
    return $p
}

# Which per-user or temp location a launch target sits in ('' when none). Only locations
# that are user-writable by definition: a profile, AppData, a temp folder, the Public
# profile. A plain path on another drive, ProgramData or a relative path says nothing about
# who can write there, so those are not classified.
# The label says who can write there: %TEMP% and %TMP% are the user's own temp folder
# (under AppData), which other standard users cannot write; C:\Temp, the Windows temp
# folder, /tmp and the Public profile are shared.
function Get-TcpkMcpWritableClass {
    param([AllowNull()][string]$Target)
    if ("$Target" -match '^\s*["'']?[A-Za-z][A-Za-z0-9+.-]+://') { return '' }      # a URL is not a path
    $p = ConvertTo-TcpkMcpNormPath $Target
    if (-not $p) { return '' }
    # Not user-writable: the Windows directory (its Temp folder aside), which also holds the
    # service-account profiles, and the template and junction entries under \Users.
    if ($p -match '^([a-z]:)?\\windows\\' -and $p -notmatch '^([a-z]:)?\\windows\\temp(\\|$)') { return '' }
    if ($p -match '^([a-z]:)?\\users\\(default|default user|all users)(\\|$)') { return '' }
    if ($p -match '^([a-z]:)?\\users\\public(\\|$)' -or $p -match '^%public%') { return 'the shared Public profile' }
    if ($p -match '^([a-z]:)?\\users\\[^\\]+\\appdata(\\|$)' -or $p -match '\\appdata\\(roaming|local|locallow)(\\|$)') { return 'a per-user AppData folder' }
    if ($p -match '^%(appdata|localappdata)%' -or $p -match '^\$env:(appdata|localappdata)\b' -or $p -match '^\$\{env:(appdata|localappdata)\}') { return 'a per-user AppData folder' }
    if ($p -match '^%(temp|tmp)%' -or $p -match '^\$env:(temp|tmp)\b' -or $p -match '^\$\{env:(temp|tmp)\}') { return 'the per-user temp folder' }
    if ($p -match '^[a-z]:\\(temp|tmp)(\\|$)' -or $p -match '^([a-z]:)?\\windows\\temp(\\|$)' -or $p -match '^\\(tmp|var\\tmp)(\\|$)') { return 'a shared temp folder' }
    if ($p -match '^([a-z]:)?\\users\\[^\\]+(\\|$)' -or $p -match '^\\home\\[^\\]+(\\|$)') { return 'a user profile folder' }
    if ($p -match '^%userprofile%' -or $p -match '^%homedrive%%homepath%' -or $p -match '^%homepath%') { return 'a user profile folder' }
    if ($p -match '^\$env:(userprofile|home|homepath)\b' -or $p -match '^\$\{env:(userprofile|home|homepath)\}') { return 'a user profile folder' }
    if ($p -match '^~(\\|$)' -or $p -match '^\$home(\\|$)' -or $p -match '^\$\{home\}' -or $p -match '^\$\{userhome\}') { return 'a user profile folder' }
    return ''
}

# Is this argument a drive root, the Users root, a whole user home or a home shorthand?
# Returns a short label or ''.
function Get-TcpkMcpBroadRootLabel {
    param([AllowNull()][string]$Value)
    $p = ConvertTo-TcpkMcpNormPath $Value
    if (-not $p) { return '' }
    if ($p.Length -gt 1 -and $p -notmatch '^[a-z]:\\$') { $p = $p.TrimEnd('\') }
    if ($p -match '^[a-z]:\\?$') { return 'a drive root' }
    if ($p -eq '\' -or $p -eq '') { return 'the filesystem root' }
    if ($p -match '^(%systemdrive%|%homedrive%|\$env:systemdrive|\$\{env:systemdrive\})$') { return 'a drive root' }
    if ($p -match '^([a-z]:)?\\users$' -or $p -eq '\home') { return 'the Users root' }
    if ($p -match '^([a-z]:)?\\users\\[^\\]+$' -or $p -match '^\\home\\[^\\]+$') { return 'a whole user home' }
    if ($p -match '^(~|\$home|\$\{home\}|\$\{userhome\}|%userprofile%|%homepath%|%homedrive%%homepath%|\$env:userprofile|\$env:home|\$\{env:userprofile\}|\$\{env:home\})$') { return 'a whole user home' }
    return ''
}

function Test-TcpkMcpPathLike {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -match '^[a-z][a-z0-9+.-]*://') { return $false }
    return ($Value -match '[\\/]' -or $Value -match '^(~|%[A-Za-z_]+%|\$)')
}

function Join-TcpkMcpPath {
    param([AllowNull()][string]$Base, [AllowNull()][string]$Child)
    if (-not $Child) { return '' }
    if (-not $Base) { return $Child }
    if ($Child -match '^([A-Za-z]:|[\\/]|~|%|\$)') { return $Child }
    return ($Base.TrimEnd('\', '/') + '\' + ($Child -replace '^\.[\\/]', ''))
}

# What the entry executes from disk: the command itself and, for an interpreter or a
# local-script launcher, the script. Data arguments are never included.
function Get-TcpkMcpLaunchTargets {
    param($Launcher, $Package, [AllowNull()][string]$Cwd)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if (Test-TcpkMcpPathLike $Launcher.Command) { $out.Add("$($Launcher.Command)".Trim([char]34)) }
    $sp = "$($Launcher.Interpreter.ScriptPath)"
    if ($sp -and $sp -notmatch '^[a-z][a-z0-9+.-]*://') {
        $out.Add((Join-TcpkMcpPath -Base $Cwd -Child $sp))
    }
    if ($null -ne $Package) {
        if ($Package.LocalTarget) {
            $base = $Package.Directory
            if (-not $base) { $base = $Cwd }
            $out.Add((Join-TcpkMcpPath -Base $base -Child $Package.LocalTarget))
        } elseif ($Package.Directory -and $Package.Launcher -ceq 'uv run') {
            $out.Add($Package.Directory)
        }
        foreach ($ref in $Package.Refs) {
            if ($ref.Kind -ceq 'local') { $out.Add((Join-TcpkMcpPath -Base $Cwd -Child ($ref.Spec -replace '^file:', ''))) }
        }
    }
    return ,$out.ToArray()
}

$script:TcpkMcpFsNameRx = '(^|[\\/@:._-])(server-filesystem|filesystem|file-system|desktop-commander|fs)($|[\\/@:._-])'
$script:TcpkMcpAllowDirRx = '^--?(allowed?[-_]?(dir|dirs|directory|directories|path|paths|root|roots))$'

# Broad roots a filesystem-type server is granted. The server is recognised by its package,
# image, binary or script name, or by an allowed-directory option; never by the display
# name the user gave it. Only positional arguments, the values of allowed-directory options
# and (for a container) bind-mount sources are considered.
# Returns { IsFs; Roots } where Roots is a list of "<arg> (<label>)".
function Get-TcpkMcpBroadRoots {
    param($Launcher, $Package)
    $roots = New-Object 'System.Collections.Generic.List[string]'
    $argv = $Launcher.Args
    $n = 0
    if ($null -ne $argv) { $n = $argv.Count }

    $names = New-Object 'System.Collections.Generic.List[string]'
    $names.Add("$($Launcher.Leaf)")
    if ($Launcher.Interpreter.ScriptPath) { $names.Add("$($Launcher.Interpreter.ScriptPath)") }
    $start = 0
    $isContainer = $false
    if ($null -ne $Package -and $Package.Launcher) {
        foreach ($ref in $Package.Refs) { if ($ref.Name) { $names.Add("$($ref.Name)") } else { $names.Add("$($ref.Spec)") } }
        if ($Package.LocalTarget) { $names.Add("$($Package.LocalTarget)") }
        $start = $Package.ArgStart
        if ($Package.Launcher -match '^(docker|podman|nerdctl) ') { $isContainer = $true }
    } elseif ($Launcher.Interpreter.ScriptIndex -ge 0) {
        $start = $Launcher.Interpreter.ScriptIndex + 1
    }
    $isFs = $false
    foreach ($nm in $names) { if ($nm -match $script:TcpkMcpFsNameRx) { $isFs = $true; break } }

    $add = {
        param([string]$Value)
        $label = Get-TcpkMcpBroadRootLabel $Value
        if ($label) { $roots.Add("$Value ($label)") }
    }

    # values of allowed-directory options: count for any server
    for ($i = [Math]::Max(0, $start); $i -lt $n; $i++) {
        $a = "$($argv[$i])"
        $eq = $a.IndexOf('=')
        if ($eq -gt 0 -and $a.Substring(0, $eq) -match $script:TcpkMcpAllowDirRx) {
            $isFs = $true
            foreach ($one in @($a.Substring($eq + 1) -split '[,;]')) { & $add $one }
            continue
        }
        if ($a -match $script:TcpkMcpAllowDirRx) {
            $isFs = $true
            $k = $i + 1
            while ($k -lt $n -and -not "$($argv[$k])".StartsWith('-')) { & $add "$($argv[$k])"; $k++ }
            $i = $k - 1
        }
    }

    if ($isFs) {
        if ($isContainer) {
            foreach ($m in $Package.Mounts) { & $add "$m" }
        } else {
            # positional arguments only: an option and the token after it are skipped
            for ($i = [Math]::Max(0, $start); $i -lt $n; $i++) {
                $a = "$($argv[$i])"
                if ($a.Length -gt 1 -and $a.StartsWith('-')) {
                    if ($a.IndexOf('=') -lt 0) { $i++ }
                    continue
                }
                $text = "$a ("
                $dup = $false
                foreach ($x in $roots) { if ($x.StartsWith($text)) { $dup = $true; break } }
                if (-not $dup) { & $add $a }
            }
        }
    }
    return [pscustomobject]@{ IsFs = $isFs; Roots = $roots.ToArray() }
}

# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

# Loopback means: host is exactly "localhost", ::1, or an IPv4 address in 127.0.0.0/8.
# The unspecified address (0.0.0.0, ::) is also treated as local: it is not a remote host.
function Test-TcpkMcpLocalEndpoint {
    param([AllowNull()][string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $h = $HostName.Trim().Trim('[', ']')
    # the container runtime's names for the machine that hosts it
    if ($h -match '^(localhost|host\.docker\.internal|gateway\.docker\.internal|host\.containers\.internal)$') { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($h, [ref]$ip)) { return $false }
    try {
        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    } catch { }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $ip.GetAddressBytes()
        if ($b[0] -eq 127) { return $true }
        if ($b[0] -eq 0 -and $b[1] -eq 0 -and $b[2] -eq 0 -and $b[3] -eq 0) { return $true }
        return $false
    }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return $true }
    if ($ip.Equals([System.Net.IPAddress]::IPv6Any)) { return $true }
    return $false
}

$script:TcpkMcpBridgeRx = '(^|[\\/@:._-])(mcp-remote|supergateway|mcp-proxy|mcp-bridge|mcp-gateway)($|[\\/@:._-])'

# Cleartext (http / ws) endpoints with a non-local host: every url-type field, plus URLs
# passed as arguments to a remote-bridge package. $Units are the launcher records to look
# at: the entry's own launcher and the commands found inside its inline scripts, each
# { Launcher; Package }. Returns records { Field; Url }.
function Get-TcpkMcpCleartext {
    param($Server, $Units)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $cands = New-Object 'System.Collections.Generic.List[object]'
    foreach ($u in $Server.Urls) { $cands.Add([pscustomobject]@{ Field = $u.Field; Value = $u.Value }) }

    if ($null -ne $Units) {
        foreach ($unit in $Units) {
            $launcher = $unit.Launcher
            if ($null -eq $launcher) { continue }
            $names = New-Object 'System.Collections.Generic.List[string]'
            $names.Add("$($launcher.Leaf)")
            if ($launcher.Interpreter.ScriptPath) { $names.Add("$($launcher.Interpreter.ScriptPath)") }
            if ($null -ne $unit.Package) { foreach ($ref in $unit.Package.Refs) { if ($ref.Name) { $names.Add("$($ref.Name)") } } }
            $isBridge = $false
            foreach ($nm in $names) { if ($nm -match $script:TcpkMcpBridgeRx) { $isBridge = $true; break } }
            if (-not $isBridge) { continue }
            foreach ($a in $launcher.Args) {
                if ("$a" -match '^(http|ws)://') { $cands.Add([pscustomobject]@{ Field = 'args'; Value = "$a" }) }
            }
        }
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $cands) {
        $u = $null
        $ok = $false
        try { $ok = [System.Uri]::TryCreate($c.Value, [System.UriKind]::Absolute, [ref]$u) } catch { $ok = $false }
        if (-not $ok -or $null -eq $u) { continue }
        if ($u.Scheme -ne 'http' -and $u.Scheme -ne 'ws') { continue }
        if (Test-TcpkMcpLocalEndpoint $u.Host) { continue }
        if (-not $seen.Add("$($c.Field)|$($c.Value)")) { continue }
        $out.Add([pscustomobject]@{ Field = $c.Field; Url = $c.Value })
    }
    return ,$out.ToArray()
}

# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------

# Provider-shaped token rules: the self-contained token shapes from TCPK/Data/secrets.json
# plus a few shapes common in MCP configs that the shared rule file does not carry. Every
# shape has a body and a minimum length, so a bare prefix ("hf_cache", "sk-bratislava-1")
# cannot match.
function Get-TcpkMcpTokenRules {
    if ($null -ne $script:TcpkMcpTokenRules) { return ,$script:TcpkMcpTokenRules }
    $list = New-Object 'System.Collections.Generic.List[object]'
    $ids = @('openai-api-key', 'openai-project-key', 'anthropic-api-key', 'gitlab-pat', 'google-oauth-client-secret',
             'slack-webhook-url', 'slack-app-token', 'sendgrid-api-key', 'npm-access-token', 'pypi-api-token',
             'hashicorp-vault-token', 'digitalocean-pat', 'databricks-pat', 'postman-api-key', 'shopify-access-token',
             'azure-storage-account-key-bare', 'azure-sas-token', 'aws-access-key-id', 'jwt-token', 'github-classic-pat',
             'github-fine-grained-pat', 'slack-token', 'stripe-secret', 'google-api-key')
    try {
        foreach ($r in @(Get-TcpkSecretRegexRules)) {
            if ($ids -contains "$($r.id)") {
                $list.Add([pscustomobject]@{ Id = "$($r.id)"; Title = "$($r.title)"; Rx = $r._RX; Rule = $r })
            }
        }
    } catch { }
    $extra = @(
        @{ Id = 'mcp-openai-legacy-key';  Title = 'OpenAI-style API key';              P = '\bsk-[A-Za-z0-9]{32,}\b' }
        @{ Id = 'mcp-openrouter-key';     Title = 'OpenRouter API key';                P = '\bsk-or-v1-[a-f0-9]{64}\b' }
        @{ Id = 'mcp-huggingface-token';  Title = 'Hugging Face access token';         P = '\bhf_[A-Za-z0-9]{30,}\b' }
        @{ Id = 'mcp-groq-key';           Title = 'Groq API key';                      P = '\bgsk_[A-Za-z0-9]{40,}\b' }
        @{ Id = 'mcp-xai-key';            Title = 'xAI API key';                       P = '\bxai-[A-Za-z0-9]{40,}\b' }
        @{ Id = 'mcp-supabase-pat';       Title = 'Supabase access token';             P = '\bsbp_[a-f0-9]{40}\b' }
        @{ Id = 'mcp-notion-token';       Title = 'Notion integration token';          P = '\b(ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})\b' }
        @{ Id = 'mcp-figma-pat';          Title = 'Figma access token';                P = '\bfigd_[A-Za-z0-9_-]{40,}' }
        @{ Id = 'mcp-linear-key';         Title = 'Linear API key';                    P = '\blin_api_[A-Za-z0-9]{40}\b' }
        @{ Id = 'mcp-tavily-key';         Title = 'Tavily API key';                    P = '\btvly-[A-Za-z0-9_-]{28,}' }
        @{ Id = 'mcp-perplexity-key';     Title = 'Perplexity API key';                P = '\bpplx-[A-Za-z0-9]{40,}\b' }
        @{ Id = 'mcp-replicate-token';    Title = 'Replicate API token';               P = '\br8_[A-Za-z0-9]{36,}\b' }
        @{ Id = 'mcp-firecrawl-key';      Title = 'Firecrawl API key';                 P = '\bfc-[a-f0-9]{32}\b' }
        @{ Id = 'mcp-atlassian-token';    Title = 'Atlassian API token';               P = '\bATATT3[A-Za-z0-9_=-]{40,}' }
        @{ Id = 'mcp-sentry-token';       Title = 'Sentry auth token';                 P = '\bsntry[su]_[A-Za-z0-9_=+/-]{40,}' }
        @{ Id = 'mcp-grafana-token';      Title = 'Grafana service account token';     P = '\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b' }
    )
    foreach ($x in $extra) {
        try {
            $list.Add([pscustomobject]@{ Id = $x.Id; Title = $x.Title; Rx = (Get-TcpkMcpRx $x.P); Rule = $null })
        } catch { }
    }
    $script:TcpkMcpTokenRules = $list.ToArray()
    return ,$script:TcpkMcpTokenRules
}

# Is a token-rule match in a place where a token can be? The one shape with a short prefix
# and a plain hex body (fc- and 32 hex digits) also matches a cache or build folder name, so
# a match that is a path segment (a separator right before it) is not taken.
function Test-TcpkMcpTokenContext {
    param([string]$RuleId, [string]$Text, [int]$Index)
    if ($RuleId -cne 'mcp-firecrawl-key') { return $true }
    if ($Index -le 0 -or $Index -gt $Text.Length) { return $true }
    $prev = $Text[$Index - 1]
    return ($prev -ne [char]92 -and $prev -ne [char]47)
}

# A reference to a value held somewhere else: $NAME, ${...}, $env:NAME, %NAME%, {{...}},
# env:NAME, or a secret-store locator (vault:..., keyring:...). Not a secret.
function Test-TcpkMcpIndirection {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v.Length -gt 4096) { $v = $v.Substring(0, 4096) }          # bounded: the patterns below scan
    if ($v -match '\$\{[^}]+\}' -or $v -match '\{\{[^}]+\}\}' -or $v -match '%[A-Za-z_][A-Za-z0-9_()]*%') { return $true }
    if ($v -match '^\$(env:)?[A-Za-z_][A-Za-z0-9_]*$') { return $true }
    # a command substitution or an expansion, also when a word split cut its end off
    if ($v -match '^(\$\(|\$\{|`)') { return $true }
    if ($v -match '^(env[:.]|process\.env\.)[A-Za-z_][A-Za-z0-9_]*$') { return $true }
    if ($v -match '^(vault|keyring|keychain|ssm|awssm|akv|gcpsm|secretref):\S+$') { return $true }
    return $false
}

# README-style placeholder, not a real value.
function Test-TcpkMcpPlaceholder {
    param([AllowNull()][string]$Value, [switch]$Shaped)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim()
    if ($v.Length -gt 4096) { $v = $v.Substring(0, 4096) }
    if ($Shaped) {
        # The value already has the shape of a provider token, a JSON Web Token or a key
        # block, so its body is random text, where the short words xxx, todo, your and
        # here turn up by chance. They count only as whole words; a run of one repeated
        # character and the longer placeholder words count anywhere.
        if ($v -match '(example|sample|dummy|placeholder|changeme|change[_-]?me|change[_-]?this|replace|redacted|insert|fixme|foobar|<[^>]*>|\.\.\.|\*\*\*)') { return $true }
        if ($v -match '(?<![A-Za-z0-9])(your|todo|here|xxx+)(?![A-Za-z0-9])') { return $true }
        if ($v -match '(.)\1{5,}') { return $true }
        return $false
    }
    if ($v -match '(your|example|sample|dummy|placeholder|changeme|change[_-]?me|change[_-]?this|replace|redacted|insert|todo|fixme|xxx|<[^>]*>|\.\.\.|\*\*\*|[_-]here$|foobar)') { return $true }
    if ($v -match '\bmy[_-]?(api[_-]?)?(key|token|secret|password)\b') { return $true }
    if ($v -match '^(test|demo|fake|mock)[_-]?(api[_-]?)?(key|token|secret|password|pass)\b') { return $true }
    if ($v -match '^(none|null|nil|undefined|empty|secret|password|passwd|pass|pwd|token|key|apikey|api[_-]?key|value|string|tbd|n/?a)$') { return $true }
    if ($v -match '^(.)\1+$') { return $true }
    # an upper-case identifier such as API_KEY or GITHUB_TOKEN names a variable
    if ($v -cmatch '^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$') { return $true }
    return $false
}

# Class of a key / flag / header / query-parameter name: 'password', 'token', 'key' or ''.
# Anchored to the END of the name: the last word must be the credential noun, so a trailing
# qualifier (FILE, PATH, DIR, URL, ENDPOINT, HOST, NAME, MODE, TYPE, LIMIT, ID, HEADER ...)
# makes it a different thing, and TOKENS / AUTHOR / AUTHORITY are different words. The noun
# may be fused to a prefix in the last word (PGPASSWORD, DBPASSWORD, AUTHTOKEN, APITOKEN,
# CLIENTSECRET): PASSWORD-type nouns take any prefix, the shorter nouns only a known one,
# because BYPASS, COMPASS or OLDPWD are not credentials.
function Get-TcpkMcpNameClass {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    if ($Name.Length -gt 200) { return '' }
    $n = [regex]::Replace($Name.Trim(), '(?<=[a-z0-9])(?=[A-Z])', '_')
    $words = New-Object 'System.Collections.Generic.List[string]'
    foreach ($w in @($n -split '[^A-Za-z0-9]+')) { if ($w) { $words.Add($w.ToUpperInvariant()) } }
    while ($words.Count -gt 0 -and $words[$words.Count - 1] -match '^\d+$') { $words.RemoveAt($words.Count - 1) }
    if ($words.Count -eq 0) { return '' }
    $last = $words[$words.Count - 1]
    $prev = ''
    if ($words.Count -gt 1) { $prev = $words[$words.Count - 2] }
    if ($last.Length -gt 40) { return '' }
    if ($last -match '^[A-Z0-9]*(PASSWORD|PASSWD|PASSPHRASE)$') { return 'password' }
    if ($last -match '^(DB|PG|SQL|MYSQL|MSSQL|REDIS|SMTP|FTP|LDAP|ROOT|ADMIN|USER)?(PWD|PASS)$') { return 'password' }
    if ($last -match '^(AUTH|API|ACCESS|REFRESH|BEARER|BOT|APP|SESSION|OAUTH|JWT|SERVICE|DEPLOY|USER|SECRET)?TOKEN$') { return 'token' }
    if ($last -match '^(CLIENT|API|APP|SHARED|WEBHOOK|SIGNING|JWT|OAUTH|CONSUMER)?SECRET$') { return 'token' }
    if ($last -match '^(APIKEY|AUTHKEY|AUTHORIZATION|PAT|CREDENTIAL|CREDENTIALS|ACCESSKEY|SECRETKEY|PRIVATEKEY|SIG|SIGNATURE)$') { return 'token' }
    if ($last -ceq 'KEY') {
        if ($prev -match '^(API|ACCESS|SECRET|PRIVATE|AUTH|SIGNING|ENCRYPTION|MASTER|ACCOUNT|SUBSCRIPTION|SERVICE|LICENSE|SHARED|CLIENT|ADMIN|BOT)$') { return 'token' }
        if ($prev -match '^(PUBLIC|PUBLISHABLE|ANON|SITE|PRIMARY|PARTITION|SORT|CACHE|INDEX|FOREIGN|LOOKUP|GROUP|ROUTING|IDEMPOTENCY|HOT|REGISTRY|SSH|HOST)$') { return '' }
        return 'key'
    }
    return ''
}

# Class of an HTTP header name. A header is a credential carrier more often than an env key
# is, so a name that ends in AUTH (X-Auth, X-Custom-Auth) counts here, and so does a cookie.
function Get-TcpkMcpHeaderClass {
    param([AllowNull()][string]$Name)
    $c = Get-TcpkMcpNameClass $Name
    if ($c) { return $c }
    if ("$Name" -match '^(cookie|set-cookie)$') { return 'token' }
    if ("$Name" -match '(^|[-_])(auth|authentication)$') { return 'token' }
    return ''
}

# Does this value name a file? An absolute or relative path, a file name with an extension
# usual for key material or settings (credentials.json, certs/server.pem), or a conventional
# key file name (id_ed25519). A credential-named key often holds the PATH of the credential.
function Test-TcpkMcpFileValue {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v.Length -gt 1024) { return $false }
    if ($v -match '^([A-Za-z]:[\\/]|\\\\|~[\\/]|\.{1,2}[\\/])') { return $true }
    if ($v -match '^/[A-Za-z0-9._ -]+(/[A-Za-z0-9._ -]*)*$') { return $true }
    if ($v -match '^[A-Za-z0-9._ \\/~-]+\.(json|jsonc|pem|key|crt|cer|der|p12|pfx|jks|keystore|ya?ml|txt|env|ini|conf|cfg|toml|xml|pub|asc|gpg|properties)$') { return $true }
    if ($v -match '(^|[\\/])(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|\.netrc|\.pgpass|\.npmrc)$') { return $true }
    return $false
}

# Is this value a literal credential for a name of the given class? Excludes references,
# placeholders, URLs, filesystem paths and file names, numbers and booleans.
function Test-TcpkMcpLiteralCredential {
    param([AllowNull()][string]$Value, [string]$Class)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    $v = [regex]::Replace($v, '^(Bearer|Basic|Token|ApiKey)\s+', '', 'IgnoreCase')
    if (-not $v) { return $false }
    if (Test-TcpkMcpIndirection $v) { return $false }
    if (Test-TcpkMcpPlaceholder $v) { return $false }
    if ($v -match '^[a-z][a-z0-9+.-]*://') { return $false }
    if (Test-TcpkMcpFileValue $v) { return $false }
    if ($v -match '^-?\d+(\.\d+)?$' -and $Class -cne 'password') { return $false }
    if ($v -match '^(true|false|yes|no|on|off)$') { return $false }
    switch ($Class) {
        'password' { return ($v.Length -ge 4) }
        'token'    {
            if ($v.Length -lt 8 -or $v -match '\s') { return $false }
            # A plain word ("disabled", "development", "super-secret") is a setting, not a
            # token: want a digit, mixed case, or a character outside letters - and _.
            return ($v -match '\d' -or ($v -cmatch '[a-z]' -and $v -cmatch '[A-Z]') -or $v -match '[^A-Za-z0-9_-]')
        }
        'key'      { return ($v.Length -ge 16 -and $v -match '^[A-Za-z0-9+/_=.:~-]+$' -and $v -match '[A-Za-z]' -and $v -match '\d') }
    }
    return $false
}

function Format-TcpkMcpMask {
    param([AllowNull()][string]$Value, [string]$Label = '')
    $n = "$Value".Length
    if ($Label) { return "[redacted $Label, $n chars]" }
    return "[redacted, $n chars]"
}

# What the payload of a JSON Web Token says about it. Valid = the header and the payload
# decode and the header names an algorithm. Role = the "role" claim. Expired = the "exp"
# claim is in the past.
function Get-TcpkMcpJwtInfo {
    param([AllowNull()][string]$Token)
    $r = [pscustomobject]@{ Valid = $false; Role = ''; Expired = $false }
    if ([string]::IsNullOrWhiteSpace($Token)) { return $r }
    try {
        $j = ConvertFrom-TcpkJwt -Token $Token
        if (-not $j.Valid) { return $r }
        $r.Valid = $true
        $p = $j.Payload
        if ($null -eq $p) { return $r }
        if ($p.PSObject.Properties['role'] -and $p.role -is [string]) { $r.Role = "$($p.role)" }
        if ($p.PSObject.Properties['exp'] -and $null -ne $p.exp) {
            $exp = 0.0
            $okNum = [double]::TryParse("$($p.exp)", [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$exp)
            if ($okNum -and $exp -gt 0) {
                $epoch = New-Object System.DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc)
                $now = ([System.DateTime]::UtcNow - $epoch).TotalSeconds
                if ($exp -lt $now) { $r.Expired = $true }
            }
        }
    } catch { }
    return $r
}

# Secrets inside one string value. $KeyName is the env key / flag / parameter the value
# belongs to ('' when there is none); $Class overrides the class derived from it.
# Returns records { Kind; Severity; Label; Value; Start }. Value is the exact secret text,
# Start its offset inside $Value (so a caller can mask by position), Label a short tag for
# the mask.
#   provider-token  HIGH    a provider-shaped token
#   jwt             HIGH    a JSON Web Token (MEDIUM when its exp claim is in the past;
#                           not reported at all when its role claim is "anon": that is the
#                           publishable client key, which every front end ships)
#   private-key     HIGH    a private-key block
#   url-password    HIGH    scheme://user:password@host
#   url-token       MEDIUM  scheme://token@host with a token-shaped userinfo and no password
#   url-query       MEDIUM  a credential-named query parameter holding a literal
#   connstr         MEDIUM  Password=... inside a connection string
#   named           MEDIUM  a credential-named key holding a literal (also a credential-named
#                           key inside a JSON value)
#   bearer          MEDIUM  "Bearer <literal>" / "Basic <base64>" under any name
function Get-TcpkMcpValueSecrets {
    param([AllowNull()][string]$Value, [string]$KeyName = '', [string]$Class = '',
          [string]$NamedLabel = 'literal under a credential name', [switch]$NoNested)
    $hits = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Value)) { return ,$hits.ToArray() }
    $v = $Value
    if ($v.Length -gt $script:TcpkMcpScanLimit) { $v = $v.Substring(0, $script:TcpkMcpScanLimit) }
    if ((-not $Class) -and $KeyName) { $Class = Get-TcpkMcpNameClass $KeyName }
    $ord = [System.StringComparison]::Ordinal
    # Without a credential-style name, the shortest thing any rule below can match is longer
    # than this (a://u:p@h is 9 characters).
    if ((-not $Class) -and $v.Length -lt 9) { return ,$hits.ToArray() }
    $publicOnly = $false          # the value is a publishable token: no fallback hit either

    $isFree = {
        param([int]$At, [int]$Len)
        foreach ($h in $hits) {
            if ($At -lt ($h.Start + $h.Value.Length) -and $h.Start -lt ($At + $Len)) { return $false }
        }
        return $true
    }
    $add = {
        param([string]$Kind, [string]$Severity, [string]$Label, [string]$Text, [int]$At)
        if ($hits.Count -ge $script:TcpkMcpHitLimit) { return }
        $hits.Add([pscustomobject]@{ Kind = $Kind; Severity = $Severity; Label = $Label; Value = $Text; Start = $At })
    }

    # private-key block
    try {
        $pk = (Get-TcpkMcpRx '-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?<body>[\s\S]*)$').Match($v)
        if ($pk.Success) {
            $body = $pk.Groups['body'].Value
            $end = $body.IndexOf('-----END', $ord)
            if ($end -ge 0) { $body = $body.Substring(0, $end) }
            $body = $body.Replace('\n', '').Replace('\r', '')
            if ($body -match '[A-Za-z0-9+/]{4,}' -and -not (Test-TcpkMcpPlaceholder $body -Shaped)) {
                & $add 'private-key' 'HIGH' 'private key block' $pk.Value $pk.Index
            }
        }
    } catch { }

    # provider-shaped tokens (the shortest shape is 15 characters, so a shorter value
    # cannot hold one and the rule set is not run over it)
    $tokenRules = @()
    if ($v.Length -ge 15) { $tokenRules = Get-TcpkMcpTokenRules }
    foreach ($rule in $tokenRules) {
        try {
            if ($null -ne $rule.Rule) {
                if (-not (Test-TcpkSecretRuleApplies -Rule $rule.Rule -Text $v)) { continue }
            }
            foreach ($m in $rule.Rx.Matches($v)) {
                if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                $tok = $m.Value
                if (Test-TcpkMcpPlaceholder $tok -Shaped) { continue }
                if (Test-TcpkMcpIndirection $tok) { continue }
                if (-not (Test-TcpkMcpTokenContext -RuleId $rule.Id -Text $v -Index $m.Index)) { continue }
                if (-not (& $isFree $m.Index $m.Length)) { continue }
                if ($rule.Id -ceq 'jwt-token') {
                    $j = Get-TcpkMcpJwtInfo $tok
                    if (-not $j.Valid) { continue }
                    if ($j.Role -ceq 'anon') { $publicOnly = $true; continue }
                    if ($j.Expired) { & $add 'jwt' 'MEDIUM' 'JSON Web Token whose exp claim is in the past' $tok $m.Index }
                    else { & $add 'jwt' 'HIGH' 'JSON Web Token' $tok $m.Index }
                    continue
                }
                & $add 'provider-token' 'HIGH' "$($rule.Title)" $tok $m.Index
            }
        } catch { }
    }

    if ($v.IndexOf('://', $ord) -ge 0) {
        # scheme://user:password@host
        # The password runs to the LAST @ before the host, so one that contains @ is taken whole.
        try {
            foreach ($m in (Get-TcpkMcpRx '(?<![A-Za-z0-9+.-])(?<scheme>[A-Za-z][A-Za-z0-9+.-]{0,30})://(?<user>[^:@/\s''"]*):(?<pw>[^/?#\s''"]+)@(?<h>[A-Za-z0-9\[])').Matches($v)) {
                if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                $g = $m.Groups['pw']
                if (Test-TcpkMcpIndirection $g.Value) { continue }
                if (Test-TcpkMcpPlaceholder $g.Value) { continue }
                if (-not (& $isFree $g.Index $g.Length)) { continue }
                & $add 'url-password' 'HIGH' "password in a $($m.Groups['scheme'].Value):// URL" $g.Value $g.Index
            }
        } catch { }

        # The same with a password written without percent-encoding, so that it holds / ? or #.
        # What follows the colon is then not a port number, which is what tells it apart from
        # scheme://host:port/path@x. Schemes that take host:path (ssh, git, scp, rsync) are
        # left out. The word is scanned by hand: one pass, no backtracking.
        try {
            foreach ($m in (Get-TcpkMcpRx '(?<![A-Za-z0-9+.-])(?<scheme>[A-Za-z][A-Za-z0-9+.-]{0,30})://(?<user>[^:@/\s''"\[\]]*):').Matches($v)) {
                if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                if ($m.Groups['scheme'].Value -match '^(git|ssh|scp|sftp|rsync|git\+ssh|ssh\+git|file)$') { continue }
                $ps = $m.Index + $m.Length
                $lim = [Math]::Min($v.Length, $ps + 2048)          # a userinfo is not longer than this
                if ($lim -le $ps) { continue }
                $we = $v.IndexOfAny($script:TcpkMcpWordStops, $ps, $lim - $ps)
                if ($we -lt 0) { $we = $lim }
                if ($we -le $ps) { continue }
                $at = $v.LastIndexOf([char]64, $we - 1, $we - $ps)
                if ($at -le $ps -or ($at + 1) -ge $we) { continue }
                $hc = $v[$at + 1]
                if (-not ([char]::IsLetterOrDigit($hc) -or $hc -eq [char]91)) { continue }
                $pw = $v.Substring($ps, $at - $ps)
                if ($pw.IndexOfAny([char[]]@([char]47, [char]63, [char]35)) -lt 0) { continue }     # the pattern above saw it
                if ($pw -match '^\d{0,5}([/?#]|$)') { continue }                                    # host:port/path
                if (Test-TcpkMcpIndirection $pw) { continue }
                if (Test-TcpkMcpPlaceholder $pw) { continue }
                if (-not (& $isFree $ps $pw.Length)) { continue }
                & $add 'url-password' 'HIGH' "password in a $($m.Groups['scheme'].Value):// URL" $pw $ps
            }
        } catch { }

        # scheme://token@host: a userinfo with no password part counts only when it is
        # token-shaped (20+ characters, letters and digits), not for an ordinary user name.
        try {
            foreach ($m in (Get-TcpkMcpRx '(?<![A-Za-z0-9+.-])(?<scheme>[A-Za-z][A-Za-z0-9+.-]{0,30})://(?<ui>[A-Za-z0-9_.~%+=-]{20,})@(?<h>[A-Za-z0-9\[])').Matches($v)) {
                if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                $g = $m.Groups['ui']
                if ($g.Value -notmatch '[A-Za-z]' -or $g.Value -notmatch '\d') { continue }
                if (Test-TcpkMcpPlaceholder $g.Value) { continue }
                if (-not (& $isFree $g.Index $g.Length)) { continue }
                & $add 'url-token' 'MEDIUM' "userinfo of a $($m.Groups['scheme'].Value):// URL" $g.Value $g.Index
            }
        } catch { }

        # credential-named query parameters, and the same after # (a token handed over in
        # the fragment)
        try {
            if ((Get-TcpkMcpRx '^\s*[A-Za-z][A-Za-z0-9+.-]{0,30}://').IsMatch($v)) {
                foreach ($m in (Get-TcpkMcpRx '(?<d>[?&#])(?<k>[A-Za-z0-9_.-]{1,60})=(?<v>[^&#\s''"]*)').Matches($v)) {
                    if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                    $qk = $m.Groups['k'].Value
                    $g = $m.Groups['v']
                    $cls = Get-TcpkMcpNameClass $qk
                    if ((-not $cls) -and $qk -match '^(auth|code)$') { $cls = 'key' }
                    if (-not $cls) { continue }
                    if (-not (Test-TcpkMcpLiteralCredential -Value $g.Value -Class $cls)) { continue }
                    if (-not (& $isFree $g.Index $g.Length)) { continue }
                    $part = 'query'
                    if ($m.Groups['d'].Value -ceq '#') { $part = 'fragment' }
                    & $add 'url-query' 'MEDIUM' "$part parameter '$qk'" $g.Value $g.Index
                }
            }
        } catch { }
    }

    # Password=... inside a connection string: a ;-separated list with at least two
    # name=value pairs. The value runs to the next ; (it may hold spaces, commas or &).
    if ($v.IndexOf([char]59) -gt 0 -and $v.IndexOf([char]61) -gt 0) {
        try {
            $pairs = 0
            foreach ($part in $v.Split([char]59)) {
                if ($part -match '^\s*[A-Za-z][A-Za-z0-9 _.]{0,60}=') { $pairs++; if ($pairs -ge 2) { break } }
            }
            if ($pairs -ge 2) {
                foreach ($m in (Get-TcpkMcpRx '(?:^|;)\s*(?:password|pwd)\s*=(?:\s*"(?<v>[^"]*)"|\s*''(?<v>[^'']*)''|(?<v>[^;]+))' -IgnoreCase).Matches($v)) {
                    if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                    $g = $m.Groups['v']
                    $raw = $g.Value
                    $cv = $raw.Trim()
                    if (-not $cv) { continue }
                    $at = $g.Index + ($raw.Length - $raw.TrimStart().Length)
                    if (-not (Test-TcpkMcpLiteralCredential -Value $cv -Class 'password')) { continue }
                    if (-not (& $isFree $at $cv.Length)) { continue }
                    & $add 'connstr' 'MEDIUM' 'connection string password' $cv $at
                }
            }
        } catch { }
    }

    # Pairs with a credential-style name written inside the value: "name": "value" of a
    # JSON value, the same with single quotes in a script literal, and an index assignment
    # such as environ['NAME'] = 'value'.
    $hasQuote = ($v.IndexOf([char]34) -ge 0 -or $v.IndexOf([char]39) -ge 0)
    if ((-not $NoNested) -and $hasQuote -and ($v.IndexOf([char]58) -gt 0 -or $v.IndexOf([char]61) -gt 0)) {
        $pairRx = @(
            '(?<q>["''])(?<k>[A-Za-z0-9_.-]{1,60})\k<q>\s*:\s*(?<p>["''])(?<v>(?:\\.|(?!\k<p>)[^\\])*)\k<p>'
            '\[\s*(?<q>["''])(?<k>[A-Za-z0-9_.-]{1,60})\k<q>\s*\]\s*=\s*(?<p>["''])(?<v>(?:\\.|(?!\k<p>)[^\\])*)\k<p>'
        )
        foreach ($px in $pairRx) {
            try {
                foreach ($m in (Get-TcpkMcpRx $px).Matches($v)) {
                    if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
                    $jk = $m.Groups['k'].Value
                    $cls = Get-TcpkMcpNameClass $jk
                    if (-not $cls) { continue }
                    $g = $m.Groups['v']
                    foreach ($h in (Get-TcpkMcpValueSecrets -Value $g.Value -Class $cls -NamedLabel "literal under the key '$jk' inside the value" -NoNested)) {
                        $at = $g.Index + $h.Start
                        if (-not (& $isFree $at $h.Value.Length)) { continue }
                        & $add $h.Kind $h.Severity $h.Label $h.Value $at
                    }
                }
            } catch { }
        }
    }

    if ($hits.Count -eq 0 -and (-not $publicOnly)) {
        if ($Class) {
            # credential-named key holding a literal
            if (Test-TcpkMcpLiteralCredential -Value $v -Class $Class) {
                $lit = [regex]::Replace($v.Trim(), '^(Bearer|Basic|Token|ApiKey)\s+', '', 'IgnoreCase')
                $at = $v.IndexOf($lit, $ord)
                if ($at -lt 0) { $at = 0 }
                & $add 'named' 'MEDIUM' $NamedLabel $lit $at
            }
        } else {
            # "Bearer <literal>" or "Basic <base64>" is a credential whatever the key is called
            try {
                $bm = (Get-TcpkMcpRx '^\s*(?<s>Bearer|Basic)\s+(?<t>\S+)\s*$' -IgnoreCase).Match($v)
                if ($bm.Success) {
                    $g = $bm.Groups['t']
                    $word = $bm.Groups['s'].Value
                    $shapeOk = $true
                    if ($word -match '^basic$') { $shapeOk = ($g.Value -match '^[A-Za-z0-9+/]{8,}={0,2}$') }
                    if ($shapeOk -and (Test-TcpkMcpLiteralCredential -Value $g.Value -Class 'token')) {
                        & $add 'bearer' 'MEDIUM' "literal after the scheme word $word" $g.Value $g.Index
                    }
                }
            } catch { }
        }
    }
    return ,$hits.ToArray()
}

# An Authorization header written inside free text: a hash literal or an object in a
# script (@{Authorization='Bearer abc'}), a header line inside a longer string. The value
# after the scheme word counts when it is a literal. Same record shape as
# Get-TcpkMcpValueSecrets.
function Get-TcpkMcpAuthTextHits {
    param([AllowNull()][string]$Value)
    $hits = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Value)) { return ,$hits.ToArray() }
    $v = $Value
    if ($v.Length -gt $script:TcpkMcpScanLimit) { $v = $v.Substring(0, $script:TcpkMcpScanLimit) }
    if ($v.Length -lt 24 -or $v.IndexOf('uthorization', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return ,$hits.ToArray() }
    try {
        foreach ($m in (Get-TcpkMcpRx '(?<![A-Za-z0-9])(?:proxy-)?authorization["'']?\s*[:=]\s*["'']?(?:(?:Bearer|Basic|Token|ApiKey)\s+)?(?<t>[^\s''";,})]+)' -IgnoreCase).Matches($v)) {
            if ($hits.Count -ge $script:TcpkMcpHitLimit) { break }
            $g = $m.Groups['t']
            if ($g.Value -match '^(\$|%|\{\{|<|\[)') { continue }             # a reference or a placeholder
            if (-not (Test-TcpkMcpLiteralCredential -Value $g.Value -Class 'token')) { continue }
            $hits.Add([pscustomobject]@{ Kind = 'bearer'; Severity = 'MEDIUM'; Label = 'Authorization value inside the text'; Value = $g.Value; Start = $g.Index })
        }
    } catch { }
    return ,$hits.ToArray()
}

# Is this argument a credential-style flag (--api-key, --token, --password ...)?
function Test-TcpkMcpCredentialFlag {
    param([AllowNull()][string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    if ($Token.Length -gt 80) { return $false }
    if ($Token -notmatch '^--?[A-Za-z][A-Za-z0-9_.-]*$') { return $false }
    return [bool](Get-TcpkMcpNameClass ($Token -replace '^-+', ''))
}

# Split a command line held in one string into words. Whitespace separates; a run inside
# "..." or '...' stays in its word. Returns records { Raw; Start } (Raw keeps the quotes).
function Split-TcpkMcpWords {
    param([AllowNull()][string]$Text)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,$out.ToArray() }
    $n = $Text.Length
    $i = 0
    while ($i -lt $n) {
        while ($i -lt $n -and [char]::IsWhiteSpace($Text[$i])) { $i++ }
        if ($i -ge $n) { break }
        $start = $i
        $q = [char]0
        while ($i -lt $n) {
            $c = $Text[$i]
            if ($q -ne [char]0) { if ($c -eq $q) { $q = [char]0 } }
            elseif ($c -eq [char]34 -or $c -eq [char]39) { $q = $c }
            elseif ([char]::IsWhiteSpace($c)) { break }
            $i++
        }
        $out.Add([pscustomobject]@{ Raw = $Text.Substring($start, $i - $start); Start = $start })
    }
    return ,$out.ToArray()
}

# The content of a word or a value cut out of a command line: a trailing statement
# separator and one pair of surrounding quotes are not part of it.
# Returns { Value; Offset } where Offset is where Value starts inside $Raw.
function Get-TcpkMcpUnquoted {
    param([AllowNull()][string]$Raw)
    $r = "$Raw".TrimEnd([char]59)
    if ($r.Length -ge 2) {
        $f = $r[0]
        if (($f -eq [char]34 -or $f -eq [char]39) -and $r[$r.Length - 1] -eq $f) {
            return [pscustomobject]@{ Value = $r.Substring(1, $r.Length - 2); Offset = 1 }
        }
    }
    return [pscustomobject]@{ Value = $r; Offset = 0 }
}

# Secrets in a list of words: the argument tokens of an entry, or the words of a command
# line held in one string. One walk recognises
#   --flag value / --flag=value   a credential-style flag and its value
#   -H / --header "Name: value"   a header line
#   NAME=value                    a credential-style name (docker -e, a shell assignment,
#                                 cmd "set NAME=value", --env=NAME=value; inside a command
#                                 line also "NAME = value" written with spaces)
#   --auth user:password          the password of a user:password pair after an option that
#                                 takes one (inside a command line also curl -u / --user)
#   anything else                 tokens, URL credentials, connection strings, JSON values
#                                 and private keys found anywhere in the word
# With -Outer each word is one argument exactly as the host passes it. A word that holds
# whitespace is then also split into its own words and walked again, because a script
# string given to a shell, a whole command line in "command", or "args" written as one
# string carry their flags inside one token. A word marked Script (the script string of a
# shell or interpreter) is only ever read that way: its first characters are the start of a
# command line, not a flag or a NAME=value argument of its own.
# A word is { Value; Slot; Base; Pos }: Slot names the place the text came from, Base is the
# offset of Value inside that place, Pos the location name for a positional value. Words cut
# out of a line also carry { Line; At }.
# Returns records { Where; Severity; Kind; Label; Value; Slot; Start }.
function Get-TcpkMcpWordSecrets {
    param($Words, [string]$Prefix = 'arg', [switch]$Outer)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Words) { return ,$out.ToArray() }
    $list = $Words
    if ($Words -isnot [System.Collections.IList]) { $list = ,$Words }
    $n = $list.Count
    if ($n -eq 0) { return ,$out.ToArray() }

    $rxFlagEq = Get-TcpkMcpRx '^(?<f>--?[A-Za-z][A-Za-z0-9_.-]{0,60})=(?<v>[\s\S]*)$'
    $rxKv     = Get-TcpkMcpRx '^(?:\$env:|\$)?(?<k>[A-Za-z_][A-Za-z0-9_.-]{0,80})=(?<v>[\s\S]*)$'
    $rxHeader = Get-TcpkMcpRx '^\s*(?<n>[A-Za-z0-9_-]{1,80})\s*[:=]\s*(?<v>[\s\S]*)$'
    $rxUrl    = Get-TcpkMcpRx '^[A-Za-z][A-Za-z0-9+.-]{0,30}://'
    $rxName   = Get-TcpkMcpRx '^(?:\$env:|\$)?(?<k>[A-Za-z_][A-Za-z0-9_.-]{0,80})$'
    $rxPair   = Get-TcpkMcpRx '^(?<u>[^:\s''"/\\]{1,80}):(?<p>\S+)$'
    $pairOpts = '^(--auth|--basic-auth|--http-auth|--proxy-user|--userpwd)$'
    $rxOption = '^--?[A-Za-z][A-Za-z0-9_.-]*(=.*)?$'
    $sawCurl  = $false

    $cap = 256
    $push = {
        param($Rec)
        if ($out.Count -ge $cap) { return }
        foreach ($o in $out) {
            if ($o.Slot -ceq $Rec.Slot -and $Rec.Start -lt ($o.Start + $o.Value.Length) -and $o.Start -lt ($Rec.Start + $Rec.Value.Length)) { return }
        }
        $out.Add($Rec)
    }
    $emit = {
        param([string]$Where, $Hits, [string]$Slot, [int]$Base)
        foreach ($h in $Hits) {
            & $push ([pscustomobject]@{ Where = $Where; Severity = $h.Severity; Kind = $h.Kind; Label = $h.Label; Value = $h.Value; Slot = $Slot; Start = ($Base + $h.Start) })
        }
    }
    # user:password after an option that takes such a pair, written out or as the base64
    # form of a Basic credential. A uid:gid or host:port pair, a URL and a path are not one.
    # With $Plain a plain word after the colon counts too (curl -u is always user:password);
    # without it the part after the colon must look like a secret, because "--auth" also
    # takes values such as scheme:mode.
    $pair = {
        param([string]$Opt, [string]$Val, [string]$Slot, [int]$Base, [bool]$Plain = $false)
        if ($rxUrl.IsMatch($Val) -or (Test-TcpkMcpFileValue $Val)) { return }
        $pm = $rxPair.Match($Val)
        if (-not $pm.Success) {
            if ($Val.Length -le 4096 -and $Val -match '^[A-Za-z0-9+/]{12,}={0,2}$') {
                $dec = ''
                try { $dec = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Val)) } catch { $dec = '' }
                if ($dec -match '^[\x21-\x7E]{1,80}:[\x20-\x7E]{4,}$') {
                    & $push ([pscustomobject]@{ Where = "$Prefix $Opt"; Severity = 'MEDIUM'; Kind = 'named'; Label = "base64 user:password pair after $Opt"; Value = $Val; Slot = $Slot; Start = $Base })
                }
            }
            return
        }
        $g = $pm.Groups['p']
        if ($g.Value -match '^\d+$') { return }
        if (-not (Test-TcpkMcpLiteralCredential -Value $g.Value -Class 'password')) { return }
        if ((-not $Plain) -and (-not (Test-TcpkMcpLiteralCredential -Value $g.Value -Class 'token'))) { return }
        & $push ([pscustomobject]@{ Where = "$Prefix $Opt"; Severity = 'MEDIUM'; Kind = 'named'; Label = "password after $Opt"; Value = $g.Value; Slot = $Slot; Start = ($Base + $g.Index) })
    }

    for ($i = 0; $i -lt $n; $i++) {
        if ($out.Count -ge $cap) { break }
        $w = $list[$i]
        $a = "$($w.Value)"
        $wb = [int]$w.Base
        $lead = 0
        $isScript = $false
        if ($Outer) {
            if ($w.PSObject.Properties['Script'] -and $w.Script) { $isScript = $true }
        } else {
            $u = Get-TcpkMcpUnquoted $a
            $a = $u.Value
            $lead = $u.Offset
            $wb += $lead
        }
        if (-not $a) { continue }
        if ((-not $sawCurl) -and $a.Length -le 260 -and $a -match '(^|[\\/])curl(\.exe)?$') { $sawCurl = $true }

        if (-not $isScript) {
            # NAME = 'value': an assignment written with spaces, as in a PowerShell script or a
            # hash literal ($env:API_KEY = 'abc', @{ Authorization = 'Bearer abc' }). Only a
            # quoted string is a literal there; anything else is an expression or a command.
            if ((-not $Outer) -and ($i + 2) -lt $n -and "$($list[$i + 1].Value)" -ceq '=') {
                $nm = $rxName.Match($a)
                if ($nm.Success -and (Get-TcpkMcpNameClass $nm.Groups['k'].Value)) {
                    $k = $nm.Groups['k'].Value
                    $nw = $list[$i + 2]
                    $u = Get-TcpkMcpUnquoted "$($nw.Value)"
                    if ($u.Offset -gt 0) {
                        & $emit "$Prefix $k" (Get-TcpkMcpValueSecrets -Value $u.Value -KeyName $k) $nw.Slot ([int]$nw.Base + $u.Offset)
                    }
                    $i += 2
                    continue
                }
            }

            # A short word that is neither an option nor NAME=value cannot hold a secret. (The
            # value after a credential-style flag never gets here: the flag consumes it.)
            if ($a.Length -lt 9 -and $a[0] -ne [char]45 -and $a.IndexOf([char]61) -lt 0) { continue }

            # --flag=value
            $fm = $rxFlagEq.Match($a)
            if ($fm.Success) {
                $before = $out.Count
                $flag = $fm.Groups['f'].Value
                $val = $fm.Groups['v'].Value
                $off = $fm.Groups['v'].Index
                if (-not $Outer) { $u = Get-TcpkMcpUnquoted $val; $val = $u.Value; $off += $u.Offset }
                $key = ''
                if (Test-TcpkMcpCredentialFlag $flag) { $key = ($flag -replace '^-+', '') }
                & $emit "$Prefix $flag" (Get-TcpkMcpValueSecrets -Value $val -KeyName $key) $w.Slot ($wb + $off)
                $kv2 = $rxKv.Match($val)
                if ($kv2.Success -and (Get-TcpkMcpNameClass $kv2.Groups['k'].Value)) {
                    $k2 = $kv2.Groups['k'].Value
                    & $emit "$Prefix $k2" (Get-TcpkMcpValueSecrets -Value $kv2.Groups['v'].Value -KeyName $k2) $w.Slot ($wb + $off + $kv2.Groups['v'].Index)
                }
                if ($flag -cmatch $pairOpts) { & $pair $flag $val $w.Slot ($wb + $off) }
                elseif ($sawCurl -and $flag -ceq '--user') { & $pair $flag $val $w.Slot ($wb + $off) $true }
                # An argument that holds whitespace and gave nothing as one value may be a
                # whole command line ("args" written as one string): its words are walked below.
                if ($out.Count -gt $before -or (-not $Outer) -or $val -notmatch '\s') { continue }
            }

            # --flag value (not when the next word is itself an option: the flag is a switch then)
            elseif ((Test-TcpkMcpCredentialFlag $a) -and ($i + 1) -lt $n -and "$($list[$i + 1].Value)" -notmatch $rxOption) {
                $nw = $list[$i + 1]
                $val = "$($nw.Value)"
                $off = 0
                if (-not $Outer) { $u = Get-TcpkMcpUnquoted $val; $val = $u.Value; $off = $u.Offset }
                & $emit "$Prefix $a" (Get-TcpkMcpValueSecrets -Value $val -KeyName ($a -replace '^-+', '')) $nw.Slot ([int]$nw.Base + $off)
                $i++
                continue
            }

            # -H "Name: value"
            elseif ($a -cmatch '^(-H|--header|--headers)$' -and ($i + 1) -lt $n) {
                $nw = $list[$i + 1]
                $val = "$($nw.Value)"
                $off = 0
                if (-not $Outer) { $u = Get-TcpkMcpUnquoted $val; $val = $u.Value; $off = $u.Offset }
                $hm = $rxHeader.Match($val)
                if ($hm.Success) {
                    $hn = $hm.Groups['n'].Value
                    & $emit "$Prefix $a $hn" (Get-TcpkMcpValueSecrets -Value $hm.Groups['v'].Value -Class (Get-TcpkMcpHeaderClass $hn)) $nw.Slot ([int]$nw.Base + $off + $hm.Groups['v'].Index)
                } else {
                    & $emit "$Prefix $a" (Get-TcpkMcpValueSecrets -Value $val) $nw.Slot ([int]$nw.Base + $off)
                }
                $i++
                continue
            }

            # --auth user:password, and inside a command line curl -u user:password
            elseif (($i + 1) -lt $n -and ($a -cmatch $pairOpts -or ($sawCurl -and $a -cmatch '^(-u|--user)$'))) {
                $nw = $list[$i + 1]
                $val = "$($nw.Value)"
                $off = 0
                if (-not $Outer) { $u = Get-TcpkMcpUnquoted $val; $val = $u.Value; $off = $u.Offset }
                & $pair $a $val $nw.Slot ([int]$nw.Base + $off) ($a -cnotmatch $pairOpts)
                $i++
                continue
            }

            # NAME=value
            else {
                $kv = $rxKv.Match($a)
                if ($kv.Success -and (Get-TcpkMcpNameClass $kv.Groups['k'].Value)) {
                    $before = $out.Count
                    $k = $kv.Groups['k'].Value
                    $val = $kv.Groups['v'].Value
                    $off = $kv.Groups['v'].Index
                    if (-not $Outer) {
                        $prevWord = ''
                        if ($i -gt 0) { $prevWord = "$($list[$i - 1].Value)" }
                        if ($prevWord -match '^@?set$' -and $lead -eq 0 -and $w.PSObject.Properties['Line']) {
                            # cmd "set NAME=value with spaces & next": the value runs to the operator
                            $line = "$($w.Line)"
                            $vs = [int]$w.At + $off
                            $ve = $line.Length
                            $inQ = $false
                            for ($x = $vs; $x -lt $line.Length; $x++) {
                                $ch = $line[$x]
                                if ($ch -eq [char]34) { $inQ = -not $inQ; continue }
                                if ($inQ) { continue }
                                if (($ch -eq [char]38 -or $ch -eq [char]124) -and ($x -eq 0 -or $line[$x - 1] -ne [char]94)) { $ve = $x; break }
                            }
                            if ($ve -gt $vs) { $val = $line.Substring($vs, $ve - $vs).TrimEnd() }
                            while (($i + 1) -lt $n -and [int]$list[$i + 1].At -lt $ve) { $i++ }
                        } else {
                            $u = Get-TcpkMcpUnquoted $val
                            $val = $u.Value
                            $off += $u.Offset
                            # $name=... is a PowerShell assignment: only a quoted string is a literal
                            if ($a[0] -eq [char]36 -and $u.Offset -eq 0) { continue }
                        }
                    }
                    & $emit "$Prefix $k" (Get-TcpkMcpValueSecrets -Value $val -KeyName $k) $w.Slot ($wb + $off)
                    if ($out.Count -gt $before -or (-not $Outer) -or $val -notmatch '\s') { continue }
                }
            }
        }

        if ($Outer) {
            # a positional value is named after the option it follows, else by its position
            $pos = "$($w.Pos)"
            if ($Prefix -ceq 'arg' -and $i -gt 0 -and "$($list[$i - 1].Value)" -match '^--?[A-Za-z][A-Za-z0-9_.-]*$') { $pos = "arg $($list[$i - 1].Value)" }
            & $emit $pos (Get-TcpkMcpValueSecrets -Value $a) $w.Slot $wb
            if ($a.Length -le $script:TcpkMcpWordLimit -and $a -match '\s') {
                $sub = New-Object 'System.Collections.Generic.List[object]'
                foreach ($x in (Split-TcpkMcpWords $a)) {
                    $sub.Add([pscustomobject]@{ Value = $x.Raw; Slot = $w.Slot; Base = ($wb + $x.Start); Pos = $pos; Line = $a; At = $x.Start })
                }
                if ($sub.Count -gt 1) {
                    foreach ($rec in (Get-TcpkMcpWordSecrets -Words $sub.ToArray() -Prefix $Prefix)) { & $push $rec }
                }
            }
            & $emit $pos (Get-TcpkMcpAuthTextHits -Value $a) $w.Slot $wb
        } elseif ($rxUrl.IsMatch($a)) {
            # a URL inside a command line: its userinfo and its query parameters
            & $emit "$($w.Pos)" (Get-TcpkMcpValueSecrets -Value $a) $w.Slot $wb
        }
    }
    return ,$out.ToArray()
}

# Every secret a server entry holds: env values, the command and args (see
# Get-TcpkMcpWordSecrets), header values and url fields.
# Returns records { Where; Severity; Kind; Label; Value; Slot; Start }. Where names the
# location without the value: "env NAME", "arg --flag", "arg NAME", "arg 3", "command",
# "header NAME", "url userinfo", "url query parameter api_key". Slot and Start say where the
# value sits ("arg:2" + offset, "url:0" + offset, "command", "env:NAME", "header:NAME"), so
# the display string can mask exactly those characters.
# $Launcher is the result of Resolve-TcpkMcpLauncher for the entry when the caller has it
# (it is resolved here otherwise): an argument that is the script string of a shell or
# interpreter is read as a command line, not as one argument.
function Get-TcpkMcpSecretHits {
    param($Server, $Launcher = $null)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $wrap = {
        param([string]$Where, $Hits, [string]$Slot)
        foreach ($h in $Hits) {
            $out.Add([pscustomobject]@{ Where = $Where; Severity = $h.Severity; Kind = $h.Kind; Label = $h.Label; Value = $h.Value; Slot = $Slot; Start = $h.Start })
        }
    }

    if ($Server.Env -is [System.Collections.IDictionary]) {
        foreach ($e in $Server.Env.GetEnumerator()) {
            if ($e.Value -isnot [string]) { continue }      # numbers, booleans, null, nested values are not secrets
            $k = "$($e.Key)"
            & $wrap "env $k" (Get-TcpkMcpValueSecrets -Value $e.Value -KeyName $k) "env:$k"
        }
    }

    if ($Server.Command) {
        $cw = @([pscustomobject]@{ Value = "$($Server.Command)"; Slot = 'command'; Base = 0; Pos = 'command' })
        foreach ($rec in (Get-TcpkMcpWordSecrets -Words $cw -Prefix 'command' -Outer)) { $out.Add($rec) }
    }

    $argv = $Server.Args
    $n = 0
    if ($null -ne $argv) { $n = $argv.Count }
    if ($n -gt 0) {
        $scripts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        if ($Server.Command) {
            $lr = $Launcher
            if ($null -eq $lr) { try { $lr = Resolve-TcpkMcpLauncher -Command $Server.Command -Arguments $argv } catch { $lr = $null } }
            if ($null -ne $lr) {
                foreach ($il in $lr.Inlines) {
                    if ((-not $il.Encoded) -and "$($il.Script)".Trim()) { [void]$scripts.Add("$($il.Script)".Trim()) }
                }
            }
        }
        $aw = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $n; $i++) {
            $av = "$($argv[$i])"
            $aw.Add([pscustomobject]@{ Value = $av; Slot = "arg:$i"; Base = 0; Pos = "arg $($i + 1)"; Script = $scripts.Contains($av.Trim()) })
        }
        foreach ($rec in (Get-TcpkMcpWordSecrets -Words $aw.ToArray() -Prefix 'arg' -Outer)) { $out.Add($rec) }
    }

    if ($Server.Headers -is [System.Collections.IDictionary]) {
        foreach ($e in $Server.Headers.GetEnumerator()) {
            if ($e.Value -isnot [string]) { continue }
            $k = "$($e.Key)"
            & $wrap "header $k" (Get-TcpkMcpValueSecrets -Value $e.Value -Class (Get-TcpkMcpHeaderClass $k)) "header:$k"
        }
    }

    $j = 0
    foreach ($u in $Server.Urls) {
        foreach ($h in (Get-TcpkMcpValueSecrets -Value $u.Value)) {
            $w = "$($u.Field) value"
            if ($h.Kind -ceq 'url-password' -or $h.Kind -ceq 'url-token') { $w = "$($u.Field) userinfo" }
            elseif ($h.Kind -ceq 'url-query') { $w = "$($u.Field) $($h.Label -replace "'", '')" }
            $out.Add([pscustomobject]@{ Where = $w; Severity = $h.Severity; Kind = $h.Kind; Label = $h.Label; Value = $h.Value; Slot = "url:$j"; Start = $h.Start })
        }
        $j++
    }
    return ,$out.ToArray()
}

# Secrets in a piece of text that is not an argument slot of the entry, such as a decoded
# encoded command. Same record shape as Get-TcpkMcpSecretHits; Slot is 'text'.
function Get-TcpkMcpTextHits {
    param([AllowNull()][string]$Text, [string]$Where = 'text', [string]$Prefix = 'arg')
    $empty = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,$empty }
    $t = "$Text"
    if ($t.Length -gt $script:TcpkMcpScanLimit) { $t = $t.Substring(0, $script:TcpkMcpScanLimit) }
    $w = @([pscustomobject]@{ Value = $t; Slot = 'text'; Base = 0; Pos = $Where; Script = $true })
    $r = Get-TcpkMcpWordSecrets -Words $w -Prefix $Prefix -Outer
    return ,$r
}

# ---------------------------------------------------------------------------
# redaction and the per-server display string
# ---------------------------------------------------------------------------
#
# What a finding prints is masked in two layers.
#   1. By position. Every hit of the secret rule carries the place and the offset of its
#      value, and exactly those characters are replaced. This runs first and on the raw
#      text, so a value is masked whole whatever characters it holds (& , ; spaces,
#      quotes), and text elsewhere that merely equals a short password is left alone.
#   2. By pattern, as a backstop over what is left (Get-TcpkMcpRedactedText): credential
#      shapes the secret rule did not report. This layer over-masks on purpose, and it only
#      ever sees a bounded window of text.

function Test-TcpkMcpNonSecret {
    param([AllowNull()][string]$Value)
    $v = [regex]::Replace("$Value".Trim(), '^(Bearer|Basic|Token|ApiKey)\s+', '', 'IgnoreCase')
    return ((Test-TcpkMcpIndirection $v) -or ($v -match '^<[^>]*>$'))
}

$script:TcpkMcpMaskRules = $null
$script:TcpkMcpMaskTriggers = [char[]]@([char]58, [char]61, [char]32, [char]9, [char]10, [char]13)    # : = and whitespace

# The pattern rules of the backstop masker, compiled once. Each one masks its group 'v'.
function Get-TcpkMcpMaskRules {
    if ($null -ne $script:TcpkMcpMaskRules) { return ,$script:TcpkMcpMaskRules }
    $scheme = '(?:(?:Bearer|Basic|Token|ApiKey)\s+)?'
    $defs = @(
        # a credential header line: the value runs to the end of the line
        @{ P = '\b(?:authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie)\s*:\s*(?<v>[^\r\n]+)' }
        # scheme://user:password@host
        @{ P = '(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^:@/\s''"]*:(?<v>[^/?#\s''"]+)(?=@)' }
        # scheme://token@host
        @{ P = '(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://(?<v>(?=[A-Za-z0-9_.~%+=-]*[A-Za-z])(?=[A-Za-z0-9_.~%+=-]*\d)[A-Za-z0-9_.~%+=-]{20,})(?=@[A-Za-z0-9\[])' }
        # credential query or fragment parameters
        @{ P = '[?&#](?:api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|auth|authorization|secret|client[_-]?secret|password|passwd|pwd|sig|signature|code)=(?<v>[^&#\s''"]+)' }
        # connection-string password: to the next ;
        @{ P = '(?:^|;)\s*[A-Za-z0-9 _.-]{0,40}?(?:password|pwd)\s*=\s*(?<v>[^;\r\n]+)' }
        # name=value / "name": "value" with a credential name; an unquoted value may start
        # with a scheme word (Bearer abc), which belongs to it. An unquoted value that is
        # code (a call, an index, a variable, a cmdlet name) is left readable.
        # cmd "set NAME=value with spaces": to the next operator
        @{ P = '(?<![A-Za-z0-9_])set\s+(?<n>[A-Za-z_][A-Za-z0-9_]{0,80})=(?<v>[^&|"\r\n]+)'; Name = $true }
        @{ P = '(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|account[_-]?key|sharedaccesskey|private[_-]?key|authorization)["'']?\]?\s*[=:]\s*(?:"(?<v>[^"]*)"|''(?<v>[^'']*)''|(?<v>' + $scheme + '[^\s''"]+))'; Code = $true }
        # the value after a credential-style flag
        @{ P = '(?<![A-Za-z0-9_-])(?<f>--?[A-Za-z][A-Za-z0-9_.-]{0,60})\s+(?:"(?<v>[^"]*)"|''(?<v>[^'']*)''|(?<v>[^\s''"]+))'; Flag = $true }
    )
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in $defs) {
        $list.Add([pscustomobject]@{ Rx = (Get-TcpkMcpRx $d.P -IgnoreCase); Flag = [bool]$d.Flag; Name = [bool]$d.Name; Code = [bool]$d.Code })
    }
    $script:TcpkMcpMaskRules = $list.ToArray()
    return ,$script:TcpkMcpMaskRules
}

# Should the backstop leave this value visible? A reference, a mask that is already there,
# a URL, a path or a file name is not a secret.
function Test-TcpkMcpMaskSkip {
    param([AllowNull()][string]$Value)
    if (-not $Value) { return $true }
    $bare = [regex]::Replace($Value, '^(Bearer|Basic|Token|ApiKey)(\s+|$)', '', 'IgnoreCase')
    if (-not $bare.Trim()) { return $true }                                  # a scheme word alone
    if ($bare.StartsWith('[redacted') -or $bare.StartsWith('[encoded')) { return $true }
    if (Test-TcpkMcpNonSecret $Value) { return $true }
    if ($Value -match '^(\$\{|\$\(|\{\{|%[A-Za-z_]|\$[A-Za-z_])') { return $true }
    if ($Value -match '^[a-z][a-z0-9+.-]*://') { return $true }
    if (Test-TcpkMcpFileValue $Value) { return $true }
    return $false
}

# Backstop masker for a piece of free text: private-key bodies, provider tokens, credential
# header lines, URL passwords, credential query and fragment parameters, name=value /
# "name":"value" pairs with a credential name, the value after a credential-style flag, and
# an encoded command. A quoted value is masked up to its closing quote, an unquoted one up
# to the next whitespace, a connection-string password up to the next ; . References ($VAR,
# ${...}, %VAR%), paths and file names stay visible: they are not secrets and they help
# triage. Callers pass a bounded window; anything longer is cut here. On any failure the
# result is '[redacted]': nothing is shown rather than the raw text.
function Get-TcpkMcpRedactedText {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text
    if ($t.Length -gt 8192) { $t = $t.Substring(0, 8192) }
    # Every rule below needs a : an = or whitespace, or at least 15 characters (the shortest
    # token shape). A short plain word (npx, -y, run) is returned as it is.
    $plain = ($t.IndexOfAny($script:TcpkMcpMaskTriggers) -lt 0)
    if ($plain -and $t.Length -lt 15) { return $t }
    try {
        if ($t.IndexOf('-----BEGIN', [System.StringComparison]::Ordinal) -ge 0) {
            $t = (Get-TcpkMcpRx '(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----)[\s\S]*$').Replace($t, '$1 [redacted]')
        }

        if ($t.Length -ge 15) {
            $sp = $null
            foreach ($rule in (Get-TcpkMcpTokenRules)) {
                try {
                    foreach ($m in $rule.Rx.Matches($t)) {
                        if (Test-TcpkMcpIndirection $m.Value) { continue }
                        if (-not (Test-TcpkMcpTokenContext -RuleId $rule.Id -Text $t -Index $m.Index)) { continue }
                        if ($null -eq $sp) { $sp = New-Object 'System.Collections.Generic.List[object]' }
                        $sp.Add([pscustomobject]@{ Start = $m.Index; Length = $m.Length; Mask = (Format-TcpkMcpMask -Value $m.Value -Label $rule.Title) })
                    }
                } catch { }
            }
            if ($null -ne $sp) { $t = Set-TcpkMcpSpans -Text $t -Spans $sp.ToArray() }
        }

        if (-not $plain) {
            foreach ($r in (Get-TcpkMcpMaskRules)) {
                $sp = $null
                foreach ($m in $r.Rx.Matches($t)) {
                    $g = $m.Groups['v']
                    if (-not $g.Success) { continue }
                    $val = $g.Value
                    if ($r.Flag) {
                        if (-not (Test-TcpkMcpCredentialFlag $m.Groups['f'].Value)) { continue }
                        if ($val -match '^--?[A-Za-z]') { continue }
                    }
                    if ($r.Name -and -not (Get-TcpkMcpNameClass $m.Groups['n'].Value)) { continue }
                    if ($r.Code -and $g.Index -gt 0) {
                        $qc = $t[$g.Index - 1]
                        $quoted = ($qc -eq [char]34 -or $qc -eq [char]39)
                        if ((-not $quoted) -and ($val -match '[()\[\]]' -or $val -match '^[-<{]' -or $val -cmatch '^[A-Z][a-z]+-[A-Z][A-Za-z]+$')) { continue }
                    }
                    if (Test-TcpkMcpMaskSkip $val.Trim()) { continue }
                    if ($null -eq $sp) { $sp = New-Object 'System.Collections.Generic.List[object]' }
                    $sp.Add([pscustomobject]@{ Start = $g.Index; Length = $val.TrimEnd().Length })
                }
                if ($null -ne $sp) { $t = Set-TcpkMcpSpans -Text $t -Spans $sp.ToArray() }
            }

            # An encoded command is the script itself in another alphabet: never print it.
            $sp = $null
            foreach ($m in (Get-TcpkMcpRx '(?<![A-Za-z0-9])[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["'']?(?<v>[A-Za-z0-9+/]{24,}={0,2})' -IgnoreCase).Matches($t)) {
                $g = $m.Groups['v']
                if ($null -eq $sp) { $sp = New-Object 'System.Collections.Generic.List[object]' }
                $sp.Add([pscustomobject]@{ Start = $g.Index; Length = $g.Length; Mask = "[encoded command, $($g.Length) chars]" })
            }
            if ($null -ne $sp) { $t = Set-TcpkMcpSpans -Text $t -Spans $sp.ToArray() }
        }

        # Get-TcpkRedact masks a whole "Authorization: ..." line. Keep a line whose value is
        # only a reference (Bearer ${TOKEN}) or is already masked: it holds no secret.
        $keep = $false
        if (-not $plain) {
            $hl = (Get-TcpkMcpRx '^\s*(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*(?<v>[^\r\n]*)$' -IgnoreCase).Match($t)
            if ($hl.Success) {
                $hv = $hl.Groups['v'].Value
                $bare = [regex]::Replace($hv, '^(Bearer|Basic|Token|ApiKey)\s+', '', 'IgnoreCase')
                if ((Test-TcpkMcpNonSecret $hv) -or $bare.StartsWith('[redacted')) { $keep = $true }
            }
        }
        if (-not $keep) { $t = Get-TcpkRedact -Text $t }
    } catch {
        return '[redacted]'
    }
    return $t
}

# One token (an argument, a url) for display: the spans the secret rule pointed at are
# masked by position, then the backstop runs over the rest. A token longer than the mask
# window is shown as its head and its length; the backstop only ever sees the window.
function Get-TcpkMcpMaskedToken {
    param([AllowNull()][AllowEmptyString()][string]$Text, $Spans = $null)
    $t = "$Text"
    if (-not $t) { return '' }
    $m = $t
    try { $m = Set-TcpkMcpSpans -Text $t -Spans $Spans } catch { return '[redacted]' }
    if ($m.Length -gt $script:TcpkMcpMaskWindow) {
        $head = Get-TcpkMcpRedactedText $m.Substring(0, $script:TcpkMcpMaskWindow)
        if ($head.Length -gt 120) { $head = $head.Substring(0, 120) }
        return "$head...[$($t.Length) chars]"
    }
    return (Get-TcpkMcpRedactedText $m)
}

# Redacted argument list. $SpanSets holds, per token, the spans to mask by position ($null
# when there are none). On top of that: the value after a credential-style flag is masked
# whole unless it is a reference, a placeholder in angle brackets, a path or a file name;
# and the argument after a PowerShell -EncodedCommand switch is never printed.
function Get-TcpkMcpRedactedArgs {
    param([string[]]$Tokens, [object[]]$SpanSets = @(), [int]$MaxChars = 0)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Tokens) { return ,$out.ToArray() }
    $maskNext = $false
    $encNext = $false
    $sawPs = $false
    $shown = 0
    $encOpt = '^[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$'
    for ($i = 0; $i -lt $Tokens.Count; $i++) {
        # the caller cuts the joined text at $MaxChars: tokens past that are never shown
        if ($MaxChars -gt 0) {
            if ($out.Count -gt 0) { $shown += $out[$out.Count - 1].Length + 1 }
            if ($shown -gt $MaxChars) { break }
        }
        $t = "$($Tokens[$i])"
        $spans = $null
        if ($null -ne $SpanSets -and $i -lt $SpanSets.Count) { $spans = $SpanSets[$i] }
        $hasSpans = ($null -ne $spans -and @($spans).Count -gt 0)

        if ($encNext) {
            $encNext = $false
            if ($t -match '^[A-Za-z0-9+/=]{8,}$') { $out.Add("[encoded command, $($t.Length) chars]"); continue }
        }
        if ($maskNext) {
            $maskNext = $false
            # another option right after the flag: the flag was a switch and took no value
            $isOption = ((-not $hasSpans) -and $t -match '^--?[A-Za-z][A-Za-z0-9_.-]*(=.*)?$')
            if (-not $isOption) {
                if ($hasSpans) { $out.Add((Get-TcpkMcpMaskedToken -Text $t -Spans $spans)) }
                elseif ((Test-TcpkMcpNonSecret $t) -or (Test-TcpkMcpFileValue $t)) { $out.Add((Get-TcpkMcpMaskedToken -Text $t)) }
                else { $out.Add('[redacted]') }
                continue
            }
        }
        $fm = [regex]::Match($t, '^(?<f>--?[A-Za-z][A-Za-z0-9_.-]{0,60})=(?<v>[\s\S]*)$')
        if ($fm.Success -and (Test-TcpkMcpCredentialFlag $fm.Groups['f'].Value)) {
            $fv = $fm.Groups['v'].Value
            if ($hasSpans) { $out.Add((Get-TcpkMcpMaskedToken -Text $t -Spans $spans)) }
            elseif ((Test-TcpkMcpNonSecret $fv) -or (Test-TcpkMcpFileValue $fv)) { $out.Add((Get-TcpkMcpMaskedToken -Text $t)) }
            else { $out.Add($fm.Groups['f'].Value + '=[redacted]') }
            continue
        }
        if (Test-TcpkMcpCredentialFlag $t) { $maskNext = $true; $out.Add($t); continue }
        # slash-style credential switch (/password, /pwd, /token): its value is the next token
        if ($t -match '^/[A-Za-z][A-Za-z0-9_]{1,40}$' -and (Get-TcpkMcpNameClass ($t.Substring(1)))) { $maskNext = $true; $out.Add($t); continue }
        if ($sawPs -and $t -match $encOpt) { $encNext = $true; $out.Add($t); continue }
        if ((-not $sawPs) -and $t.Length -lt 260 -and (Get-TcpkMcpLeaf $t) -match '^(powershell|pwsh|pwsh-preview)$') { $sawPs = $true }
        $out.Add((Get-TcpkMcpMaskedToken -Text $t -Spans $spans))
    }
    # Default deny, last: whatever the rules above left readable is printed only when it
    # has a shape that cannot be a secret. The first token is the program.
    $final = New-Object 'System.Collections.Generic.List[string]'
    $prevIsFlag = $false
    $prevIsShort = $false
    for ($k = 0; $k -lt $out.Count; $k++) {
        $tok = $out[$k]
        if ($k -eq 0) { $final.Add((Get-TcpkMcpShownToken -Text $tok)); continue }
        $final.Add((Get-TcpkMcpShownToken -Text $tok -AfterFlag:$prevIsFlag -ShortFlag:$prevIsShort))
        $prevIsFlag = ($tok -match '^(--?[A-Za-z][A-Za-z0-9_.\-]{0,60}|/[A-Za-z?][A-Za-z0-9]{0,20})$')
        $prevIsShort = ($tok -cmatch '^-[A-Za-z]$' -and $tok -cnotmatch '^-[yYicm]$')
    }
    return ,$final.ToArray()
}

# ---------------------------------------------------------------------------------------
# DEFAULT-DENY DISPLAY
#
# The masking above is a deny list: it hides what it recognises as a credential. A deny
# list can always be beaten by a form nobody listed (a bridge option, a token in a URL
# path, a password inside a script string). So what finally goes into Evidence passes one
# more filter that works the other way round: an argument is printed only when it has a
# shape that cannot be a secret, and anything else is replaced by its length.
#
# Printed:  an option name; a reference (${VAR}, %VAR%, $VAR, <placeholder>); a number or a
#           boolean; a path or file name; a package, module or image reference; a URL reduced
#           to scheme, host, port and path.
# Replaced: anything with whitespace, quotes or shell / structure characters (a script, a
#           header pair, a JSON blob, a connection string); anything holding a key-like run;
#           every other value.
# ---------------------------------------------------------------------------------------

# A run that looks like key material: 20 or more letters and digits mixed, a long hex or
# base64 run, or a UUID. "sha256:<digest>" is an image digest, not a key.
function Test-TcpkMcpKeyLike {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text"
    if ($t.Length -lt 16) { return $false }
    if ($t.Length -gt 2048) { return $true }
    $t = [regex]::Replace($t, 'sha(256|512):[0-9a-fA-F]{64,128}', '')
    if ($t -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { return $true }
    foreach ($m in [regex]::Matches($t, '[A-Za-z0-9+_=]{16,}')) {
        $run = $m.Value
        $hasDigit = ($run -match '[0-9]')
        $hasAlpha = ($run -match '[A-Za-z]')
        if ($run.Length -ge 20 -and $hasDigit -and $hasAlpha) { return $true }
        if ($run.Length -ge 32 -and $run -match '^[0-9a-fA-F]+$') { return $true }
        if ($run.Length -ge 40) { return $true }
    }
    return $false
}

# A URL for display: scheme, host, port and path. User-info is dropped up to the LAST '@'
# of the authority (a user name or a password may hold '@'), the query and the fragment are
# dropped, and a path segment that could be a token is masked.
function Get-TcpkMcpShownUrl {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text"
    if (-not $t) { return '' }
    if ($t.Length -gt 2048) { $t = $t.Substring(0, 2048) }
    try {
        $m = [regex]::Match($t, '\A(?<s>[A-Za-z][A-Za-z0-9+.\-]{0,30}://)(?<a>[^/?#]*)(?<p>[^?#]*)(?<q>[?#][\s\S]*)?\z')
        if (-not $m.Success) { return "[value, $($t.Length) chars]" }
        $auth = $m.Groups['a'].Value
        $at = $auth.LastIndexOf([char]'@')
        $hadUser = ($at -ge 0)
        if ($hadUser) { $auth = $auth.Substring($at + 1) }
        if ($auth -notmatch '\A(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._\-]*|\$\{[^}]{1,80}\}|%[A-Za-z_][A-Za-z0-9_]*%)(:(\d{1,5}|\$\{[^}]{1,80}\}))?\z') { $auth = '[host masked]' }
        $segs = New-Object 'System.Collections.Generic.List[string]'
        foreach ($seg in ($m.Groups['p'].Value -split '/')) {
            if ($seg.Length -ge 12 -and $seg -notmatch '\.' -and $seg -match '[0-9]' -and $seg -match '[A-Za-z]') { $segs.Add('[masked]') }
            elseif (Test-TcpkMcpKeyLike $seg) { $segs.Add('[masked]') }
            elseif ($seg -match '^@[A-Za-z0-9._\-]{1,40}$') { $segs.Add($seg) }      # an npm scope
            elseif ($seg -match '^[A-Za-z0-9._\-]{1,80}@[A-Za-z0-9._\-]{1,60}$' -and -not (Test-TcpkMcpKeyLike $seg)) { $segs.Add($seg) }   # repo@ref
            elseif ($seg -match '[\s"''`;|&<>{}()=,@:]') { $segs.Add('[masked]') }
            else { $segs.Add($seg) }
        }
        $out = $m.Groups['s'].Value
        if ($hadUser) { $out += '[user-info masked]@' }
        $out += $auth + ($segs.ToArray() -join '/')
        if ($m.Groups['q'].Success) { $out += '?[query masked]' }
        if ($out.Length -gt 200) { $out = $out.Substring(0, 200) + '...' }
        return $out
    } catch { return '[redacted]' }
}

# One argument for display, default deny (see the block comment above). -AfterFlag: the
# token follows an option name, so it is that option's value.
function Get-TcpkMcpShownToken {
    param([AllowNull()][AllowEmptyString()][string]$Text, [switch]$AfterFlag, [switch]$ShortFlag)
    $t = "$Text"
    if (-not $t) { return '' }
    $hidden = "[value, $($t.Length) chars]"
    try {
        # a mask that is already there (possibly followed by the length note of a long token)
        if ($t -match '^\[(redacted|encoded|value|script)[^\]]*\](\.\.\.\[\d+ chars\])?$') { return $t }
        # a long token already cut to its head by the masker: report its real length
        $lm = [regex]::Match($t, '\.\.\.\[(\d+) chars\]$')
        if ($lm.Success) { return "[value, $($lm.Groups[1].Value) chars]" }
        if ($t.Length -gt 400) { return $hidden }
        # an option name, alone or as --name=value / NAME=value
        $om = [regex]::Match($t, '^(?<n>--?[A-Za-z][A-Za-z0-9_.\-]{0,60}|/[A-Za-z?][A-Za-z0-9]{0,20})(?<e>=(?<v>[\s\S]*))?$')
        if ($om.Success) {
            if (-not $om.Groups['e'].Success) { return $t }
            return $om.Groups['n'].Value + '=' + (Get-TcpkMcpShownToken -Text $om.Groups['v'].Value -AfterFlag)
        }
        $em = [regex]::Match($t, '^(?<n>[A-Za-z_][A-Za-z0-9_.\-]{0,60})=(?<v>[\s\S]*)$')
        if ($em.Success) {
            return $em.Groups['n'].Value + '=' + (Get-TcpkMcpShownToken -Text $em.Groups['v'].Value -AfterFlag)
        }
        # a reference to a value held elsewhere, or a placeholder in angle brackets
        if ($t.Length -le 200 -and $t -notmatch '\s' -and (Test-TcpkMcpNonSecret $t)) { return $t }
        if ($t -match '^[A-Za-z][A-Za-z0-9+.\-]{0,30}://') { return (Get-TcpkMcpShownUrl $t) }
        if ($t -match '^(\d{1,10}|true|false|yes|no|on|off|null|none)$') { return $t }
        # a file-system path or a file name (may hold spaces), with no token-like part
        if ($t -notmatch '["''`;|&<>{}=,]' -and -not (Test-TcpkMcpKeyLike $t)) {
            if (Test-TcpkMcpFileValue $t) { return $t }
            if ($t -notmatch '\s' -and $t -match '[\\/]' -and $t -match '^[A-Za-z0-9@._~%$\\/:+()\[\]\-]+$') { return $t }
        }
        # a header pair "Name: value": the name is shown, the value only when it is a reference
        $hm = [regex]::Match($t, '^(?<h>[A-Za-z][A-Za-z0-9\-]{0,40}):\s+(?<v>[\s\S]+)$')
        if ($hm.Success) {
            $hv = $hm.Groups['v'].Value.Trim()
            # a value the masker already replaced is shown as that mask
            if ($hv -match '^((Bearer|Basic|Token|ApiKey)\s+)?\[(redacted|encoded|value)[^\]]*\]$') { return $t }
            $bare = [regex]::Replace($hv, '^(Bearer|Basic|Token|ApiKey)\s+', '', 'IgnoreCase')
            if ($hv.Length -le 200 -and $bare -notmatch '\s' -and (Test-TcpkMcpNonSecret $hv)) { return $t }
            return $hm.Groups['h'].Value + ': ' + "[value, $($hv.Length) chars]"
        }
        if ($t -match '[\s"''`;|&<>{}()=,]') { return $hidden }
        if (Test-TcpkMcpKeyLike $t) { return $hidden }
        $max = 120
        if ($AfterFlag) { $max = 48 }
        if ($t.Length -gt $max) { return $hidden }
        # The value of a one-letter option (-p, -k, -t ...) is how a password, a key or a
        # token is passed on a command line. Only a word of letters is shown there.
        if ($ShortFlag -and $t -notmatch '^[A-Za-z][A-Za-z._\-]{0,19}$' -and $t -notmatch '(@|==)[0-9]') { return $hidden }
        # a plain word (a subcommand, a mode, a model name) or host:port
        if ($t -match '^[A-Za-z0-9][A-Za-z0-9._\-]*$') { return $t }
        if ($t -match '^[A-Za-z0-9][A-Za-z0-9._\-]*:\d{1,5}$') { return $t }
        # a package or module reference: [@scope/]name[extras][@version | ==version]
        if ($t -match '^(@[A-Za-z0-9][A-Za-z0-9._\-]*/)?[A-Za-z0-9][A-Za-z0-9._\-]*(\[[A-Za-z0-9,._\-]+\])?((@|==|~=|>=|<=)[A-Za-z0-9*^~][A-Za-z0-9._+*^~\-]*)?$') { return $t }
        # a container image reference, only as a positional argument: name:tag is also the
        # shape of user:password, and that is what the value of an option can be
        if (-not $AfterFlag -and $t -cmatch '^[a-z0-9][a-z0-9._\-]*(:\d{1,5})?(/[a-z0-9][a-z0-9._\-]*)*(:[A-Za-z0-9][A-Za-z0-9._\-]{0,60})?(@sha256:[0-9a-f]{64})?$') { return $t }
        return $hidden
    } catch { return '[redacted]' }
}

# A script string for display. The text of a script is never printed: it is where a
# password, a token or a connection string sits in a form no rule lists. What is shown is
# its length and the names of the programs it starts.
function Get-TcpkMcpShownScript {
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$MaxNames = 8)
    $t = "$Text"
    if (-not $t) { return '[script, 0 chars]' }
    $names = New-Object 'System.Collections.Generic.List[string]'
    try {
        $win = $t
        if ($win.Length -gt 8192) { $win = $win.Substring(0, 8192) }
        foreach ($stmt in ($win -split '(?:\r?\n|;|&&|\|\||\||&)')) {
            $w = [regex]::Match($stmt.Trim(), '^(?:@?(?:set|export|call|start|exec|sudo|env)\s+)?(?<c>[A-Za-z][A-Za-z0-9_.\-]{0,40})(?=\s|$)')
            if (-not $w.Success) { continue }
            $c = $w.Groups['c'].Value
            if ($c -match '=') { continue }
            if (-not $names.Contains($c)) { $names.Add($c) }
            if ($names.Count -ge $MaxNames) { break }
        }
    } catch { }
    $s = "[script, $($t.Length) chars"
    if ($names.Count -gt 0) { $s += '; starts: ' + ($names.ToArray() -join ', ') }
    return $s + ']'
}

# One line, bounded: what every piece of text gets before it goes into a finding.
function Get-TcpkMcpSafeText {
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$MaxLength = 300)
    $t = ("$Text" -replace '[\r\n\t]+', ' ').Trim()
    if ($MaxLength -gt 0 -and $t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength) + '...' }
    return $t
}

# A piece of text that is not an argument slot (a decoded command, a package spec, a launch
# target, an endpoint, the wording of a download finding), masked for display: the secret
# rule is run over the text itself and its hits are masked by position, then the backstop.
function Get-TcpkMcpMaskedFragment {
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$MaxLength = 300)
    $t = "$Text"
    if (-not $t) { return '' }
    $window = [Math]::Max($script:TcpkMcpMaskWindow, 4 * $MaxLength)
    if ($t.Length -gt $window) { $t = $t.Substring(0, $window) }
    $m = $t
    try {
        $spans = New-Object 'System.Collections.Generic.List[object]'
        foreach ($h in (Get-TcpkMcpTextHits -Text $t)) {
            $spans.Add([pscustomobject]@{ Start = $h.Start; Length = "$($h.Value)".Length })
        }
        $m = Set-TcpkMcpSpans -Text $t -Spans $spans.ToArray()
        $m = Get-TcpkMcpRedactedText $m
    } catch { $m = '[redacted]' }
    return (Get-TcpkMcpSafeText -Text $m -MaxLength $MaxLength)
}

# The ONE redacted display string for a server. Every Evidence field starts with it.
# $Hits are the records of Get-TcpkMcpSecretHits for the same server.
function Get-TcpkMcpDisplay {
    param($Server, $Hits = $null, [int]$MaxLength = 300)
    $bySlot = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    if ($null -ne $Hits) {
        foreach ($h in $Hits) {
            if ($null -eq $h -or -not $h.Slot) { continue }
            $slot = "$($h.Slot)"
            if (-not $bySlot.ContainsKey($slot)) { $bySlot[$slot] = New-Object 'System.Collections.Generic.List[object]' }
            $bySlot[$slot].Add([pscustomobject]@{ Start = [int]$h.Start; Length = "$($h.Value)".Length })
        }
    }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($Server.Command) {
        $toks = New-Object 'System.Collections.Generic.List[string]'
        $sets = New-Object 'System.Collections.Generic.List[object]'
        $toks.Add("$($Server.Command)")
        $s0 = $null
        if ($bySlot.ContainsKey('command')) { $s0 = $bySlot['command'].ToArray() }
        $sets.Add($s0)
        $i = 0
        foreach ($a in $Server.Args) {
            $toks.Add("$a")
            $si = $null
            if ($bySlot.ContainsKey("arg:$i")) { $si = $bySlot["arg:$i"].ToArray() }
            $sets.Add($si)
            $i++
        }
        $masked = Get-TcpkMcpRedactedArgs -Tokens $toks.ToArray() -SpanSets $sets.ToArray() -MaxChars $MaxLength
        $parts.Add('command: ' + ($masked -join ' '))
    }
    $j = 0
    foreach ($u in $Server.Urls) {
        $sj = $null
        if ($bySlot.ContainsKey("url:$j")) { $sj = $bySlot["url:$j"].ToArray() }
        $parts.Add("$($u.Field): " + (Get-TcpkMcpShownUrl (Get-TcpkMcpMaskedToken -Text $u.Value -Spans $sj)))
        $j++
    }
    if ($parts.Count -eq 0) { $parts.Add('(no command or url)') }
    return (Get-TcpkMcpSafeText -Text ($parts.ToArray() -join '; ') -MaxLength $MaxLength)
}
