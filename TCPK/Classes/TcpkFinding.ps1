# [TCPK.Finding] - the universal output of every check.
# Every public cmdlet in this module returns instances of this class
# (via the New-TcpkFinding factory in Private\_Finding.ps1).
#
# Report generators are the only code that knows about formatting.
# Everything else passes [TCPK.Finding] objects down the pipeline.

class TcpkFinding {
    # --- identity ---
    [string] $Module       # bucket: 'static','manifest','os','creds','runtime','network','webview2','logging','memory','antidebug','exploit','meta'
    [string] $RuleId       # stable identifier, dotted (e.g. 'pe.missing-mitigations')

    # --- severity + confidence ---
    [string] $Severity     # INFO | LOW | MEDIUM | HIGH | CRITICAL
    [string] $Confidence   # Confirmed | Inferred | Unverified | Skipped

    # --- description ---
    [string] $Title        # one-line summary
    [string] $Description  # optional longer explanation

    # --- evidence ---
    [string] $File         # primary path/file/key the finding applies to
    [string] $Evidence     # raw observed value (redact secrets before storing here)

    # --- categorization + remediation ---
    [string[]] $Cwe        # CWE identifiers like 'CWE-798'
    [string] $Fix          # one-line remediation suggestion

    # --- provenance ---
    [string] $Timestamp    # ISO-8601 UTC

    [string] ToString() {
        return ("[{0,-8}] [{1,-10}] {2}" -f $this.Severity, $this.Confidence, $this.Title)
    }
}
