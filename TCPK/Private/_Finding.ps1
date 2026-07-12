# New-TcpkFinding - factory for [TCPK.Finding].
# Private. Used by every check cmdlet.

$script:TcpkSeverityRank = @{
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4
}

# Base confidence labels (deterministic checks) + the LLM-verifier labels.
# Invoke-TcpkLlmCodeJudgment writes the '(LLM)' variants, and findings round-trip
# through New-TcpkFinding when the GUI/report layer rebuilds them, so the factory
# must accept these too.
$script:TcpkValidConfidence = @('Confirmed','Confirmed (IL)','Confirmed (dynamic)','Confirmed (exploit)','Confirmed (OSV)','Confirmed (NVD)','Inferred','Unverified','Skipped','Confirmed (LLM)','Likely-FP (IL)','Likely-FP (LLM)','Uncertain (LLM)')

function New-TcpkFinding {
    [CmdletBinding()]
    [OutputType([TcpkFinding])]
    param(
        [Parameter(Mandatory)][string] $Module,
        [Parameter(Mandatory)][string] $RuleId,
        [Parameter(Mandatory)]
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')]
        [string] $Severity,
        [Parameter(Mandatory)][string] $Title,

        [ValidateSet('Confirmed','Inferred','Unverified','Skipped','Confirmed (LLM)','Likely-FP (LLM)','Uncertain (LLM)','Confirmed (IL)','Likely-FP (IL)','Confirmed (dynamic)','Confirmed (exploit)','Confirmed (OSV)','Confirmed (NVD)')]
        [string] $Confidence = 'Confirmed',

        [string]   $Description,
        [string]   $File,
        [string]   $Evidence,
        [string[]] $Cwe = @(),
        [string]   $Impact,
        [string]   $Cvss,
        [string]   $Fix
    )

    $f = [TcpkFinding]::new()
    $f.Module      = $Module
    $f.RuleId      = $RuleId
    $f.Severity    = $Severity
    $f.Confidence  = $Confidence
    $f.Title       = $Title
    $f.Description = $Description
    $f.File        = $File
    $f.Evidence    = $Evidence
    $f.Cwe         = $Cwe
    $f.Impact      = $Impact
    $f.Cvss        = $Cvss
    $f.Fix         = $Fix
    $f.Timestamp   = (Get-Date).ToUniversalTime().ToString('o')
    return $f
}

function Get-TcpkSeverityRank {
    param([Parameter(Mandatory)][string]$Severity)
    if ($script:TcpkSeverityRank.ContainsKey($Severity)) {
        return $script:TcpkSeverityRank[$Severity]
    }
    return -1
}

# --- CVSS v4.0 (per-finding, attack-archetype based) ---------------------------
# IMPORTANT (honesty): we do NOT print a fabricated decimal base score. A CVSS v4.0
# base score is derived from an official macrovector lookup table (not a closed-form
# formula), so a hand-typed number would be a guess. Instead each finding carries an
# accurate v4.0 VECTOR chosen by its attack archetype; the analyst (or the FIRST.org
# calculator) derives the exact number from that vector. This fixes the old per-
# severity band, which mislabelled every CRITICAL as AV:N even when the issue is local
# (weak ACL, DLL hijack, on-disk secret, etc.). TCPK standardized on CVSS v4.0 only.
#
# Vectors per attack archetype (all 11 base metrics; SC/SI/SA kept N = no proven
# cross-system pivot, raise per finding if one exists).
$script:TcpkCvssArchetypes = [ordered]@{
    'net-mitm'        = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'  # transport interception / cert + hostname bypass
    'net-rce'         = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'  # remote code delivery / unsafe deserialization / poisoned update
    'untrusted-parse' = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N'  # XXE / zip-slip on attacker-supplied input
    'web-bridge'      = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'  # embedded web content -> native bridge (needs a navigation)
    'local-privesc'   = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'  # writable ACL / hijack / service -> elevation (LOCAL)
    'shipped-secret'  = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'  # secret baked into the distributed artifact (any holder reads it)
    'embedded-key'    = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'  # private key / unprotected keystore in the artifact: identity compromised (confidentiality + integrity) -> 8.5 High
    'live-credential' = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'  # network-service credential (cloud / API / source-control / SSH): full read+write reachable over the network -> 9.3 Critical
    'low-secret'      = 'CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'  # low-value secret (analytics / app id): minor confidentiality, effort to abuse -> 2.1 Low
    'local-at-rest'   = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'  # sensitive data on the victim host (needs local access)
    'client-bypass'   = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N'  # client-side licensing / auth decision flipped locally
    'weak-crypto'     = 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'  # cryptographic weakness (conditions / effort required)
    'hardening'       = 'CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'  # missing mitigation / posture gap (contributory)
    'cleartext-net'   = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'  # cleartext transport / DNS leak: on-path attacker can read/tamper (AT:P) -> 6.3 Medium
    'local-tempfile'  = 'CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N'  # predictable / world-readable temp file: a local user races/hijacks it (integrity-only, high effort) -> ~2.1 Low
}

# Rule-family -> archetype. First match wins; families are matched on the RuleId prefix.
# Families that are genuinely mixed (callsites, registry, raw endpoints) deliberately
# fall through to the 'per-finding' note rather than be assigned a misleading vector.
# EXCEPTION: a few callsites.* subrules ARE single-archetype (e.g. insecure-temp is
# always a local temp-file race), so they get a real, tier-matched vector here.
$script:TcpkCvssRuleArchetype = @(
    @{ Rx = '^exploit\.secret-recovered';                                                                                                                            A = 'live-credential' }
    @{ Rx = '^exploit\.credential-live';                                                                                                                             A = 'live-credential' }
    @{ Rx = '^exploit\.check-bypassed';                                                                                                                              A = 'client-bypass' }
    @{ Rx = '^exploit\.stored-credential';                                                                                                                           A = 'local-at-rest' }
    @{ Rx = '^intercept\.cleartext-credential';                                                                                                                      A = 'live-credential' }
    @{ Rx = '^intercept\.(weak-transport|session-token)';                                                                                                            A = 'cleartext-net' }
    @{ Rx = '^callsites\.insecure-temp';                                                                                                                            A = 'local-tempfile' }
    @{ Rx = '^(tls-bypass|tls-handshake|wcf|truststore)\.|^electron\.cert';                                                                                                         A = 'net-mitm' }
    @{ Rx = '^(scheme|dns|tls)\.';                                                                                                                                   A = 'cleartext-net' }
    @{ Rx = '^(deser|update)\.';                                                                                                                                    A = 'net-rce' }
    # electron.* renderer-config flaws are RCE-class -- EXCEPT electron.outdated-runtime, whose
    # exact CVSS depends on which Chromium/Node CVEs apply (the OSV electron@ver list carries
    # per-CVE scores), so it deliberately falls through to the 'assign per finding' note rather
    # than inheriting a misleading net-rce 9.x next to its version-age severity.
    @{ Rx = '^electron\.(?!outdated-runtime)';                                                                                                                      A = 'net-rce' }
    @{ Rx = '^electronjs\.(exec-sink|open-external|nav-injection|webview-tag|execute-js)';                                                                           A = 'net-rce' }
    @{ Rx = '^electronjs\.resource-path-traversal';                                                                                                                 A = 'untrusted-parse' }
    @{ Rx = '^electronjs\.';                                                                                                                                         A = 'web-bridge' }
    @{ Rx = '^fuses\.cookie';                                                                                                                                       A = 'local-at-rest' }
    @{ Rx = '^fuses\.';                                                                                                                                             A = 'local-privesc' }
    @{ Rx = '^(xxe|zipslip)\.';                                                                                                                                     A = 'untrusted-parse' }
    @{ Rx = '^(webview2)\.';                                                                                                                                        A = 'web-bridge' }
    @{ Rx = '^(install-dir|acl|service|driver|ifeo|scheduled-task|app-paths|autostart|com|named-object|pipe-dacl|dll-search|shim|avexclusion|firewall|wmi|uac)\.'; A = 'local-privesc' }
    @{ Rx = '^(entropy|jwt|config|app-config)\.';                                                                                                                   A = 'shipped-secret' }
    @{ Rx = '^(dpapi|token-cache|credman|localdb|env|memory|memsecret|pii|log)\.';                                                                                  A = 'local-at-rest' }
    @{ Rx = '^(authflags|guiunlock|flagflip)\.';                                                                                                                    A = 'client-bypass' }
    @{ Rx = '^(crypto)\.';                                                                                                                                          A = 'weak-crypto' }
    # debugflags.security-off / .backdoor disable a security control or hide a backdoor --
    # a locally-flipped integrity compromise, NOT a posture gap. Matched BEFORE 'hardening'
    # (which also lists debugflags) so the HIGH badge agrees with the computed CVSS instead
    # of showing HIGH next to a 2.0-Low 'hardening' score.
    @{ Rx = '^debugflags\.(security-off|backdoor)';                                                                                                                 A = 'client-bypass' }
    @{ Rx = '^(pe|pe-imports|pe-exports|strongname|authenticode|codeintegrity|packer|obfuscation|antidebug|antiinjection|timing|integrity|debugflags|devartifact|native|pinvoke|interop|reflection|sxs|mem|pagefile|wer)\.'; A = 'hardening' }
)

# Resolve the CVSS v4.0 vector for a finding. Returns @{ Vector; Display; Source }.
#   override     -> the finding's explicit .Cvss (e.g. a real NVD vector)
#   archetype:*  -> an accurate vector chosen by attack family
#   nvd          -> a CVE/dependency finding: use the linked advisory's official vector
#   per-finding  -> mixed/context-dependent class: analyst assigns the exact vector
#   info         -> INFO severity: not a vulnerability, N/A
function Get-TcpkCvssVector {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Finding)
    if ($null -eq $Finding) { return [pscustomobject]@{ Vector = ''; Score = $null; Rating = ''; Display = ''; Source = 'none' } }

    $sev = "$($Finding.Severity)".ToUpperInvariant()
    if ($sev -eq 'INFO') { return [pscustomobject]@{ Vector = ''; Score = $null; Rating = 'None'; Display = 'N/A (informational)'; Source = 'info' } }

    $ov = $null; try { $ov = $Finding.Cvss } catch { }
    if ($ov) { return (New-TcpkCvssResult -Vector $ov -Source 'override') }

    $rid = "$($Finding.RuleId)"

    # Credential / secret family (secrets.* , keymaterial.*): impact depends on what the
    # secret unlocks, which the rule's hand-assigned severity already encodes -- one
    # archetype can't span a low-value app id and a cloud root credential. Pick a REAL,
    # tier-matched vector so the displayed CVSS agrees with the badge (INFO returned
    # above). Scores: 9.3 / 8.5 / 6.9 / 2.1 for CRITICAL / HIGH / MEDIUM / LOW.
    if ($rid -match '^(secrets|keymaterial)\.') {
        $a = switch ($sev) {
            'CRITICAL' { 'live-credential' }
            'HIGH'     { 'embedded-key' }
            'MEDIUM'   { 'shipped-secret' }
            'LOW'      { 'low-secret' }
            default    { '' }
        }
        if ($a) { return (New-TcpkCvssResult -Vector $script:TcpkCvssArchetypes[$a] -Source ("archetype:" + $a)) }
    }

    foreach ($m in $script:TcpkCvssRuleArchetype) {
        if ($rid -match $m.Rx) {
            return (New-TcpkCvssResult -Vector $script:TcpkCvssArchetypes[$m.A] -Source ("archetype:" + $m.A))
        }
    }
    if ($rid -match '^(cve|deps|pkgmanifest)\.') {
        return [pscustomobject]@{ Vector = ''; Score = $null; Rating = ''; Display = 'See the linked NVD / GHSA advisory for the official CVSS v4.0 score'; Source = 'nvd' }
    }
    return [pscustomobject]@{ Vector = ''; Score = $null; Rating = ''; Display = 'Not auto-scored (mixed class) -- assign per finding'; Source = 'per-finding' }
}

# Build a CVSS result for a known vector: compute the REAL v4.0 base score from the
# vector (faithful FIRST.org engine in _Cvss40.ps1). Display is "score (Rating) vector".
# Degrades to the bare vector if the scoring table is unavailable / vector unparseable.
function New-TcpkCvssResult {
    param([Parameter(Mandatory)][string]$Vector, [Parameter(Mandatory)][string]$Source)
    $scored = $null
    try { $scored = Get-TcpkCvss40Score -Vector $Vector } catch { }
    if ($scored) {
        $num = '{0:0.0}' -f $scored.Score
        return [pscustomobject]@{ Vector = $Vector; Score = $scored.Score; Rating = $scored.Rating; Display = "$num ($($scored.Rating)) $Vector"; Source = $Source }
    }
    return [pscustomobject]@{ Vector = $Vector; Score = $null; Rating = ''; Display = $Vector; Source = $Source }
}

# Legacy: representative vector per severity band. Retained for callers that only have
# a severity (no RuleId). Prefer Get-TcpkCvssVector, which is attack-aware. Kept on
# CVSS v4.0 only (v3.1 dropped).
$script:TcpkCvssBand = @{
    CRITICAL = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (indicative; assign per finding)'
    HIGH     = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (indicative; assign per finding)'
    MEDIUM   = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N (indicative; assign per finding)'
    LOW      = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N (indicative; assign per finding)'
    INFO     = 'N/A (Info)'
}
function Get-TcpkCvssBand {
    param([Parameter(Mandatory)][string]$Severity)
    if ($script:TcpkCvssBand.ContainsKey($Severity)) { return $script:TcpkCvssBand[$Severity] }
    return ''
}

# Per-finding impact: use the finding's explicit Impact if set, else a concise
# severity-derived default so every reported finding carries an impact statement.
$script:TcpkImpactBand = @{
    CRITICAL = 'Direct compromise: code execution, privilege escalation, or exposure of live credentials with little/no precondition.'
    HIGH     = 'Serious exposure: an attacker meeting a modest precondition can steal secrets, escalate, or bypass a security control.'
    MEDIUM   = 'Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.'
    LOW      = 'Minor hardening gap / information useful to an attacker; low standalone risk.'
    INFO     = 'Informational - triage context, not a vulnerability on its own.'
}
function Get-TcpkImpactText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Finding)
    if ($Finding.Impact) { return $Finding.Impact }
    if ($Finding.Severity -and $script:TcpkImpactBand.ContainsKey($Finding.Severity)) { return $script:TcpkImpactBand[$Finding.Severity] }
    return ''
}
