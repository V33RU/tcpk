function Export-TcpkReportSarif {
<#
.SYNOPSIS
    Export findings as SARIF 2.1.0 (report.sarif) for CI code-scanning ingest.

.DESCRIPTION
    SARIF (Static Analysis Results Interchange Format) is the standard consumed by
    GitHub Advanced Security code scanning and Azure DevOps. This makes a TCPK audit
    a first-class CI citizen: upload report.sarif and findings appear as code-scanning
    alerts, ranked by GitHub using the `security-severity` property (the computed
    CVSS v4.0 base score, so the ranking matches the report).

    Mapping:
      Severity -> SARIF level:  CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note
      CWE      -> rule + result tags
      CVSS v4.0 score -> properties.'security-severity' (GitHub severity bucketing)
      RuleId   -> a SARIF rule (deduplicated into tool.driver.rules)

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to the .sarif (JSON) file.

.PARAMETER Target
    Optional target string (recorded on the run).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Target = ''
    )
    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }
    end {
        # tool version, derived (no hardcoded 5th copy)
        $ver = try {
            $v = (Get-Module TCPK | Select-Object -First 1).Version
            if (-not $v -and $script:TcpkRoot) { $v = (Import-PowerShellDataFile -Path (Join-Path $script:TcpkRoot 'TCPK.psd1')).ModuleVersion }
            if ($v) { "$v" } else { '2.5.0-rc1' }
        } catch { '2.5.0-rc1' }

        $levelOf = @{ CRITICAL='error'; HIGH='error'; MEDIUM='warning'; LOW='note'; INFO='note' }
        $bandScore = @{ CRITICAL='9.5'; HIGH='8.0'; MEDIUM='5.5'; LOW='2.0'; INFO='0.0' }

        # ---- dedupe RuleIds into SARIF rules ----
        $ruleIndex = @{}
        $rules = New-Object 'System.Collections.Generic.List[object]'
        foreach ($f in $all) {
            $rid = "$($f.RuleId)"; if (-not $rid -or $ruleIndex.ContainsKey($rid)) { continue }
            $ruleIndex[$rid] = $rules.Count
            $tags = New-Object 'System.Collections.Generic.List[string]'
            $tags.Add('security')
            if ($f.Cwe) { foreach ($c in @($f.Cwe)) { if ($c) { $tags.Add("external/cwe/$($c.ToLowerInvariant())") } } }
            $atk = "$(Get-TcpkAttackText $rid)"; if ($atk) { $tags.Add('attack') }
            $oda = "$(Get-TcpkOwaspDa -RuleId $rid)"; if ($oda) { $tags.Add('owasp-desktop') }
            $rules.Add([ordered]@{
                id              = $rid
                name            = ($rid -replace '[^A-Za-z0-9]', '')
                shortDescription= [ordered]@{ text = "$($f.Title)" }
                fullDescription = [ordered]@{ text = "$(if ($f.Fix) { $f.Fix } else { $f.Title })" }
                properties      = [ordered]@{
                    tags             = $tags.ToArray()
                    'problem.severity'= $(if ("$($f.Severity)" -in 'CRITICAL','HIGH') { 'error' } elseif ("$($f.Severity)" -eq 'MEDIUM') { 'warning' } else { 'recommendation' })
                }
            })
        }

        # ---- results ----
        $results = foreach ($f in $all) {
            $rid = "$($f.RuleId)"; if (-not $rid) { continue }
            $sev = "$($f.Severity)".ToUpperInvariant()
            $cvss = Get-TcpkCvssVector $f
            $secSev = if ($cvss -and $null -ne $cvss.Score) { '{0:0.0}' -f $cvss.Score } elseif ($bandScore.ContainsKey($sev)) { $bandScore[$sev] } else { '0.0' }
            $uri = if ($f.File) { ($f.File -replace '\\', '/') } else { 'tcpk://finding' }
            $msg = "$($f.Title)"
            if ($f.Evidence)    { $msg += "  | evidence: $($f.Evidence)" }
            if ($f.Confidence)  { $msg += "  | confidence: $($f.Confidence)" }
            [ordered]@{
                ruleId    = $rid
                ruleIndex = $ruleIndex[$rid]
                level     = $(if ($levelOf.ContainsKey($sev)) { $levelOf[$sev] } else { 'note' })
                message   = [ordered]@{ text = $msg }
                locations = @(
                    [ordered]@{ physicalLocation = [ordered]@{ artifactLocation = [ordered]@{ uri = $uri } } }
                )
                properties= [ordered]@{
                    'security-severity' = $secSev
                    severity            = $sev
                    confidence          = "$($f.Confidence)"
                    cwe                 = @(if ($f.Cwe) { @($f.Cwe) } else { @() })
                    owaspDa             = "$(Get-TcpkOwaspDa -RuleId $rid)"
                }
            }
        }

        $sarif = [ordered]@{
            '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
            version   = '2.1.0'
            runs      = @(
                [ordered]@{
                    tool = [ordered]@{ driver = [ordered]@{
                        name           = 'TCPK'
                        fullName       = 'TCPK -- Thick Client Pentest Kit'
                        version        = $ver
                        informationUri = 'https://github.com/'
                        rules          = $rules.ToArray()
                    } }
                    results          = @($results)
                    automationDetails= [ordered]@{ id = "tcpk/$Target" }
                }
            )
        }

        $json = $sarif | ConvertTo-Json -Depth 20
        Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8
        Write-TcpkInfo "SARIF written: $OutFile ($($all.Count) results, $($rules.Count) rules)"
    }
}
