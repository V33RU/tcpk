# Streaming string extractor.
#
# WHY THIS EXISTS
# ---------------
# The naive way to scan a binary for secrets is to decode the whole file into a
# string and run regex over it. That collapses on large targets: a 212 MB
# Electron binary decodes into ~445 M characters across the three views we need
# (UTF-8, UTF-16LE even-aligned, UTF-16LE odd-aligned), and Test-TcpkSecrets then
# runs 41 rules over every one of them. Even the cheap per-rule literal pre-filter
# is String.IndexOf with OrdinalIgnoreCase, which on .NET Framework goes through
# NLS collation rather than a byte compare -- so the pre-filter ALONE is ~18
# billion character comparisons for a single file. That is the shape of a scan
# that pegs one core for hours with no I/O and no network.
#
# Capping the read "fixes" it by not scanning the file, which is worse -- a
# credential at offset 800 MB is simply never seen.
#
# The established answer, unchanged since GNU strings(1), is to separate reading
# from matching:
#
#   stream every byte  ->  keep only printable runs  ->  regex over the runs
#
# Reading stays O(1) in memory per buffer and linear in time, so file size stops
# determining whether a scan is possible. Matching then operates on the extracted
# text, typically 2-5% of the input, so the expensive phase shrinks by more than
# an order of magnitude. Every byte is examined; only the non-text bytes are
# discarded, and they could never have matched an ASCII pattern anyway.
#
# References for the design:
#   binutils strings.c  -- character-at-a-time streaming, 4-char minimum run
#   Trivy secret scan   -- 64 KB buffer, overlap so keys spanning a boundary survive
#   YARA issue #1665    -- why whole-file mapping degrades past ~100 MB
#
# The hot loop is C# compiled on first use: a per-byte loop in PowerShell would
# take hours on a multi-GB file. Compilation failure is not fatal -- callers fall
# back to the bounded chunk reader in _Strings.ps1, which truncates nothing.
#
# MEMORY, STATED HONESTLY. Reading is bounded by the 64 KB buffer, but the OUTPUT
# is not: each view may grow to TcpkMaxViewChars (64 M chars = 128 MB), and
# Harvest() copies the StringBuilder into a string, so a view can momentarily cost
# ~256 MB and three views ~768 MB. Dedup adds a HashSet of the distinct runs on
# top. In practice extracted text is 2-5% of the file, so a 2 GB binary lands well
# under the caps; the ceilings exist for the pathological case, and reaching one
# sets OutputCapped so the shortfall is reported rather than hidden.

$script:TcpkExtractorReady = $false
$script:TcpkExtractorError = $null

# Minimum printable run to keep. 4 matches strings(1); shorter runs are almost
# entirely coincidental byte sequences inside machine code.
$script:TcpkMinRunLength = 4

# Ceiling on a single run. Guards against a pathological file that is one
# continuous printable region. On overflow the run is emitted and the last
# TcpkRunCarryChars are retained as the head of the next run, so a pattern
# straddling the split still matches.
$script:TcpkMaxRunChars   = 1MB
$script:TcpkRunCarryChars = 8KB   # exceeds the ~6 KB span of the PEM key regex

# Above this file size, identical runs are emitted once. Binaries repeat the same
# paths and API names thousands of times; deduping keeps the regex phase bounded.
# Below the threshold every occurrence is kept so occurrence-count findings
# (Test-TcpkNativeInterop, Test-TcpkReflectionLoading) stay exact.
$script:TcpkDedupAtBytes = 100MB

# Hard ceiling per view. Reaching it sets OutputCapped, which callers surface as
# a partial-scan finding rather than silently under-reporting.
$script:TcpkMaxViewChars = 64MB

$script:TcpkExtractorSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Tcpk
{
    /// <summary>Outcome of one streaming extraction pass over a file.</summary>
    public sealed class ExtractResult
    {
        public string Ascii;        // printable single-byte runs
        public string WideEven;     // UTF-16LE runs on even byte alignment
        public string WideOdd;      // UTF-16LE runs on odd byte alignment
        public long   FileLength;   // size on disk
        public long   BytesRead;    // bytes actually streamed; equals FileLength on a clean pass
        public bool   Deduped;      // identical runs collapsed
        public bool   OutputCapped; // a view hit its ceiling; coverage is incomplete
    }

    /// <summary>
    /// Accumulates one view. Characters arrive through Add; Break closes the
    /// current run. A run is emitted only once it reaches the minimum length.
    /// </summary>
    internal sealed class RunSink
    {
        private readonly StringBuilder   _out;
        private readonly char[]          _run;
        private readonly HashSet<string> _seen;
        private readonly int             _minLen;
        private readonly int             _carry;
        private readonly long            _maxOut;
        private int  _runLen;
        private bool _capped;

        internal RunSink(int minLen, int maxRun, int carry, bool dedup, long maxOut)
        {
            _out    = new StringBuilder(64 * 1024);
            _run    = new char[maxRun];
            _seen   = dedup ? new HashSet<string>(StringComparer.Ordinal) : null;
            _minLen = minLen;
            _carry  = carry;
            _maxOut = maxOut;
            _runLen = 0;
            _capped = false;
        }

        internal bool Capped { get { return _capped; } }

        internal void Add(char c)
        {
            _run[_runLen++] = c;
            if (_runLen == _run.Length) { Split(); }
        }

        internal void Break()
        {
            if (_runLen == 0) { return; }
            Emit();
            _runLen = 0;
        }

        // Run filled its buffer: emit it, then retain a tail as the head of the
        // continuation so a pattern crossing the split point can still match.
        private void Split()
        {
            Emit();
            int keep = _carry < _runLen ? _carry : _runLen;
            Array.Copy(_run, _runLen - keep, _run, 0, keep);
            _runLen = keep;
        }

        private void Emit()
        {
            if (_runLen < _minLen || _capped) { return; }
            string s = new string(_run, 0, _runLen);
            if (_seen != null && !_seen.Add(s)) { return; }
            if (_out.Length + s.Length + 1 > _maxOut) { _capped = true; return; }
            _out.Append(s);
            _out.Append('\n');
        }

        internal string Harvest()
        {
            Break();
            return _out.ToString();
        }
    }

    public static class StringExtractor
    {
        private const int BufferSize = 64 * 1024;

        // Graphic ASCII plus tab/CR/LF. Newlines are deliberately treated as part
        // of a run so multi-line blobs -- PEM private keys, embedded JSON,
        // certificate bodies -- survive intact instead of being shredded at every
        // line break.
        //
        // High bytes (0x80-0xFF) are excluded on purpose. Admitting them would
        // make ~88% of uniformly random bytes "printable", so compressed and
        // encrypted regions would emit as one enormous run and defeat the whole
        // point. Every TCPK detection pattern is ASCII, so nothing matchable is
        // lost by the restriction. The cost is that non-ASCII TEXT (a UTF-8 config
        // with CJK or accented characters) is broken at each high byte in a
        // streamed read; below the streaming threshold the verbatim decode keeps
        // it intact, and Read-TcpkStringViews reports which path was taken.
        private static readonly bool[] Graphic = BuildGraphicTable();

        private static bool[] BuildGraphicTable()
        {
            bool[] t = new bool[256];
            for (int i = 0x20; i <= 0x7E; i++) { t[i] = true; }
            t[0x09] = true;   // tab
            t[0x0A] = true;   // LF
            t[0x0D] = true;   // CR
            return t;
        }

        /// <summary>
        /// Streams the entire file once and returns the printable runs found in
        /// three views. Reading is bounded by the buffer; output is bounded by
        /// maxOutChars per view.
        /// </summary>
        public static ExtractResult Extract(string path, int minLen, int maxRun, int carry,
                                            long dedupAtBytes, long maxOutChars)
        {
            ExtractResult r = new ExtractResult();
            r.FileLength = new FileInfo(path).Length;

            bool dedup = r.FileLength >= dedupAtBytes;
            r.Deduped = dedup;

            RunSink sinkAscii = new RunSink(minLen, maxRun, carry, dedup, maxOutChars);
            RunSink sinkEven  = new RunSink(minLen, maxRun, carry, dedup, maxOutChars);
            RunSink sinkOdd   = new RunSink(minLen, maxRun, carry, dedup, maxOutChars);

            byte[] buf = new byte[BufferSize];
            long abs = 0;

            // Low byte of a UTF-16LE pair awaiting its high byte. Held across
            // buffer boundaries so a pair split by a read still resolves.
            int pendEven = -1;   // pairs at even offsets: (0,1), (2,3), ...
            int pendOdd  = -1;   // pairs at odd  offsets: (1,2), (3,4), ...

            // FileAccess.Read guarantees the target is never modified.
            // FileShare.ReadWrite|Delete declines an exclusive lock, so a running
            // application can still read, self-update, patch, or uninstall its own
            // files while the scan is in flight.
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                                  FileShare.ReadWrite | FileShare.Delete,
                                                  BufferSize, FileOptions.SequentialScan))
            {
                int n;
                while ((n = fs.Read(buf, 0, BufferSize)) > 0)
                {
                    for (int i = 0; i < n; i++)
                    {
                        byte b = buf[i];

                        if (Graphic[b]) { sinkAscii.Add((char)b); } else { sinkAscii.Break(); }

                        if ((abs & 1L) == 0L)
                        {
                            // Even offset: closes an odd-aligned pair, opens an even one.
                            if (pendOdd >= 0)
                            {
                                if (b == 0 && Graphic[pendOdd]) { sinkOdd.Add((char)pendOdd); }
                                else { sinkOdd.Break(); }
                                pendOdd = -1;
                            }
                            pendEven = b;
                        }
                        else
                        {
                            // Odd offset: closes an even-aligned pair, opens an odd one.
                            if (pendEven >= 0)
                            {
                                if (b == 0 && Graphic[pendEven]) { sinkEven.Add((char)pendEven); }
                                else { sinkEven.Break(); }
                                pendEven = -1;
                            }
                            pendOdd = b;
                        }

                        abs++;
                    }
                }
            }

            r.BytesRead    = abs;
            r.Ascii        = sinkAscii.Harvest();
            r.WideEven     = sinkEven.Harvest();
            r.WideOdd      = sinkOdd.Harvest();
            r.OutputCapped = sinkAscii.Capped || sinkEven.Capped || sinkOdd.Capped;
            return r;
        }
    }
}
'@

# Compiles the extractor on first use. Returns $true when the type is usable.
# Compilation is deliberately lazy: most audits never touch a file large enough
# to need it, and Add-Type costs a second or two per process.
function Initialize-TcpkExtractor {
    [CmdletBinding()] param()
    if ($script:TcpkExtractorReady) { return $true }
    if ('Tcpk.StringExtractor' -as [type]) {
        $script:TcpkExtractorReady = $true
        return $true
    }
    try {
        Add-Type -TypeDefinition $script:TcpkExtractorSource -Language CSharp -ErrorAction Stop
        $script:TcpkExtractorReady = $true
        return $true
    } catch {
        # Record and degrade: callers fall back to the overlapping-chunk reader,
        # which reports its own limits rather than hiding them.
        $script:TcpkExtractorError = $_.Exception.Message
        return $false
    }
}

# Emitted once per process, the first time the extractor is needed and cannot be
# built. Without this the host silently drops to the slower fallback and nobody
# knows why the scan is taking longer.
$script:TcpkExtractorWarned = $false

# Streams a file and returns a [Tcpk.ExtractResult], or $null if the read failed.
#
# Reports its own cost. A big file is the single most common reason a scan appears
# to hang, so every streamed read announces the size, how much text came out of it,
# and how long it took. That turns "the GUI is frozen" into "this 212 MB binary is
# being read, it is 3% text, and it took 40 seconds" -- which is a wait, not a bug.
function Invoke-TcpkStringExtract {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Initialize-TcpkExtractor)) {
        if (-not $script:TcpkExtractorWarned) {
            $script:TcpkExtractorWarned = $true
            $m = "streaming string extractor unavailable on this host, falling back to chunked reads (slower): $script:TcpkExtractorError"
            try { Write-Information -MessageData "  [strings] $m" -InformationAction Continue } catch { }
            try { Write-TcpkLog -Level WARN -Component 'strings' -Message $m | Out-Null } catch { }
        }
        return $null
    }

    $len = 0
    try { $len = [System.IO.FileInfo]::new($Path).Length } catch { }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = $null
    try {
        $r = [Tcpk.StringExtractor]::Extract(
            $Path,
            [int]$script:TcpkMinRunLength,
            [int]$script:TcpkMaxRunChars,
            [int]$script:TcpkRunCarryChars,
            [long]$script:TcpkDedupAtBytes,
            [long]$script:TcpkMaxViewChars)
    } catch {
        $sw.Stop()
        $m = "extract failed after $([int]$sw.Elapsed.TotalSeconds)s on $Path -- $($_.Exception.Message)"
        try { Write-Information -MessageData "  [strings] $m" -InformationAction Continue } catch { }
        try { Write-TcpkLog -Level ERROR -Component 'strings' -Message $m | Out-Null } catch { }
        return $null
    }
    $sw.Stop()
    if (-not $r) { return $null }

    # Announce anything genuinely large or genuinely slow. Small fast reads stay quiet:
    # a per-file line for every DLL in an install tree would bury the useful signal.
    $secs = $sw.Elapsed.TotalSeconds
    if ($len -ge 64MB -or $secs -ge 3.0) {
        $outChars = [int64]$r.Ascii.Length + $r.WideEven.Length + $r.WideOdd.Length
        $pct = if ($len -gt 0) { [math]::Round(($outChars * 100.0) / $len, 1) } else { 0 }
        $name = try { [System.IO.Path]::GetFileName($Path) } catch { $Path }
        $note = ''
        if ($r.Deduped)      { $note += '; repeated strings collapsed' }
        if ($r.OutputCapped) { $note += '; TEXT CAPPED -- coverage incomplete for this file' }
        $m = ("{0}: {1} MB read in {2}s -> {3} MB of text ({4}% is text){5}" -f `
              $name, [math]::Round($len / 1MB, 1), [math]::Round($secs, 1),
              [math]::Round($outChars * 2 / 1MB, 1), $pct, $note)
        try { Write-Information -MessageData "  [large file] $m" -InformationAction Continue } catch { }
        $lvl = if ($r.OutputCapped) { 'WARN' } else { 'INFO' }
        try { Write-TcpkLog -Level $lvl -Component 'strings' -Message $m -DurationMs ([int]$sw.Elapsed.TotalMilliseconds) | Out-Null } catch { }
    }
    return $r
}
