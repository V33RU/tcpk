function Resolve-TcpkFindings {
<#
.SYNOPSIS
    Triage pipeline: dedupe + false-positive killers + confidence refinement.

.DESCRIPTION
    Takes a stream of [TcpkFinding] objects and returns a refined stream:
      - Deduplicates by RuleId + File + Title
      - Demotes well-known false-positive patterns (e.g. BinaryFormatter
        substring in *.runtimeconfig.json)
      - Promotes confidence based on cross-cmdlet correlation (e.g. if
        Test-TcpkSecrets found a credential AND Test-TcpkUpdateFlow flagged
        no signature verification, the supply-chain inference is reinforced)

    Use after Invoke-TcpkAudit to clean up the findings before report
    generation. The default audit calls this automatically; this cmdlet is
    also exposed so operators can re-triage existing JSON output.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings
    )

    begin { $all = New-Object 'System.Collections.Generic.List[TcpkFinding]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        # 1) Dedupe by (RuleId, File, Title)
        $seen = @{}
        $uniq = New-Object 'System.Collections.Generic.List[TcpkFinding]'
        foreach ($f in $all) {
            $key = "$($f.RuleId)::$($f.File)::$($f.Title)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $uniq.Add($f)
        }

        # 2) Known false-positive demoters
        foreach ($f in $uniq) {
            # BinaryFormatter substring inside a runtimeconfig.json is a switch name,
            # not a Deserialize() call site.
            if ($f.RuleId -like 'deser.binaryformatter' -and
                $f.File -match '\.runtimeconfig\.json$') {
                $f.Severity = 'INFO'
                $f.Confidence = 'Unverified'
                $f.Description = "$($f.Description) [TCPK auto-demoted: substring is the EnableUnsafeBinaryFormatterSerialization feature-switch name, not a call site.]"
            }
            # ServerCertificateValidationCallback in a managed framework lib is noise.
            if ($f.RuleId -like 'callsites.disabled-cert-validation' -and
                (Split-Path $f.File -Leaf) -match '^System\.' ) {
                $f.Severity = 'INFO'
                $f.Confidence = 'Unverified'
            }
            # tls-bypass.* rules can fire on the same callback the callsites.* rules
            # already catch -- demote tls-bypass.ServerCertificateCustomValidationCallback
            # to INFO when callsites.disabled-cert-validation fires on the same file.
            # (handled below in correlation pass, since we need to check across uniq)
        }

        # 2b) Cross-rule dedupe within the same file
        $callsiteByFile = @{}
        foreach ($f in $uniq) {
            if ($f.RuleId -eq 'callsites.disabled-cert-validation') {
                $callsiteByFile[$f.File] = $true
            }
        }
        $connstrByFile = @{}
        foreach ($f in $uniq) {
            if ($f.RuleId -eq 'secrets.azure-storage-connection-string') {
                $connstrByFile[$f.File] = $true
            }
        }
        # Files where the deterministic IL prover CONFIRMED an accept-all cert callback.
        # This verdict is the strongest evidence we have and must never be demoted.
        $provenTlsByFile = @{}
        foreach ($f in $uniq) {
            if ($f.RuleId -eq 'tls-bypass.cert-callback-accepts-all') { $provenTlsByFile[$f.File] = $true }
        }
        foreach ($f in $uniq) {
            # A WEAK (regex / Inferred) tls-bypass hit on a file the callsites.* rule
            # already CRITICAL'd is a duplicate -> demote. NEVER demote the IL-proven
            # verdict (tls-bypass.cert-callback-accepts-all, Confirmed): it is the
            # authoritative finding, not the noise.
            if ($f.RuleId -like 'tls-bypass.*' -and
                $f.RuleId -ne 'tls-bypass.cert-callback-accepts-all' -and
                "$($f.Confidence)" -notmatch 'Confirmed' -and
                $callsiteByFile.ContainsKey($f.File)) {
                $f.Severity = 'INFO'
                $f.Confidence = 'Unverified'
                $f.Description = "$($f.Description) [TCPK dedupe: same callback covered by callsites.disabled-cert-validation on this file.]"
            }
            # Conversely, the Inferred callsites.disabled-cert-validation is SUPERSEDED
            # when the IL prover confirmed the same file's callback accepts all certs.
            if ($f.RuleId -eq 'callsites.disabled-cert-validation' -and
                $provenTlsByFile.ContainsKey($f.File)) {
                $f.Severity = 'INFO'
                $f.Confidence = 'Unverified'
                $f.Description = "$($f.Description) [TCPK dedupe: superseded by IL-proven tls-bypass.cert-callback-accepts-all (Confirmed) on this file.]"
            }
            # azure-storage-account-key-bare is the key portion of the connection string
            # already CRITICAL'd via secrets.azure-storage-connection-string
            if ($f.RuleId -eq 'secrets.azure-storage-account-key-bare' -and
                $connstrByFile.ContainsKey($f.File)) {
                $f.Severity = 'INFO'
                $f.Confidence = 'Unverified'
                $f.Description = "$($f.Description) [TCPK dedupe: the same key bytes are covered by secrets.azure-storage-connection-string CRITICAL on this file.]"
            }
        }

        # 3) Cross-cmdlet correlation: secrets + no-sig-verify update flow = supply-chain
        $hasSecret = $uniq | Where-Object { $_.RuleId -like 'secrets.*' -and $_.Severity -in 'CRITICAL','HIGH' }
        $noSig    = $uniq | Where-Object { $_.RuleId -eq 'update.no-signature-verification' }
        if ($hasSecret -and $noSig) {
            foreach ($f in $noSig) {
                $f.Description = "$($f.Description) [TCPK correlation: a CRITICAL/HIGH secret was also found in this audit -- combining a leaked credential with an unverified update flow is a supply-chain primitive against all customers.]"
            }
        }

        # Emit
        foreach ($f in $uniq) { $f }
    }
}
