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
    [string[]] $Affected = @()   # when this finding aggregates multiple occurrences of the SAME rule: the affected files / URLs / params

    # --- categorization + remediation ---
    [string[]] $Cwe        # CWE identifiers like 'CWE-798'
    [string] $Impact       # optional business/technical impact sentence (else derived from Severity at report time)
    [string] $Cvss         # optional explicit CVSS v4.0 vector for THIS finding (e.g. a real NVD vector); else assigned by attack archetype at report time
    [string] $Fix          # one-line remediation suggestion

    # --- provenance ---
    [string] $Timestamp    # ISO-8601 UTC

    [string] ToString() {
        return ("[{0,-8}] [{1,-10}] {2}" -f $this.Severity, $this.Confidence, $this.Title)
    }
}
