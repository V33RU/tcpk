# Shared "program intelligence" data model.
#
# Get-TcpkIntelModel turns a set of [TcpkFinding] objects (+ optional target profile)
# into the canonical { meta, summary, identity, recon, findings } object that BOTH the
# offline intel.html report (Export-TcpkReportIntel) and the live web control panel
# (Start-TcpkWebUi -> /api/run) serialize to JSON. One source of truth = the two views
# can never drift on WHAT data a finding carries.

function Get-TcpkIntelModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [string]$Target = '',
        [object]$Profile = $null
    )

    $all = @($Findings | Where-Object { $_ })
    # Force string args into the sort keys so the typed -Severity param can never receive a
    # non-string (some upstream findings surface .Severity oddly under Sort-Object's scope).
    $sorted = $all | Sort-Object `
        @{ Expression = { Get-TcpkSeverityRank "$($_.Severity)" }; Descending = $true }, `
        @{ Expression = { "$($_.RuleId)" } }

    # --- per-finding intelligence records (flattened, report-ready) ---
    $records = foreach ($f in $sorted) {
        $cvss = ''; try { $cvss = "$((Get-TcpkCvssVector $f).Display)" } catch { }
        $attack = ''; try { $attack = "$(Get-TcpkAttackText $f.RuleId)" } catch { }
        $tasvs  = ''; try { $tasvs  = "$(Get-TcpkTasvsText $f.RuleId)" } catch { }
        $impact = ''; try { $impact = "$(Get-TcpkImpactText $f)" } catch { }
        $verify = ''; try { $verify = "$(Get-TcpkVerifyHint -RuleId $f.RuleId -File $f.File -Evidence $f.Evidence)" } catch { }
        [pscustomobject]@{
            sev = "$($f.Severity)"; conf = "$($f.Confidence)"; rule = "$($f.RuleId)"
            title = "$($f.Title)"; desc = "$($f.Description)"; file = "$($f.File)"
            evidence = "$($f.Evidence)"; cwe = @($f.Cwe); cvss = $cvss; attack = $attack
            tasvs = $tasvs; impact = $impact; fix = "$($f.Fix)"; verify = $verify
            affected = @($f.Affected); module = "$($f.Module)"
        }
    }

    $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
    $sevCounts = [ordered]@{}; foreach ($s in $sevOrder) { $sevCounts[$s] = @($all | Where-Object { "$($_.Severity)" -eq $s }).Count }
    $confCounts = [ordered]@{}
    foreach ($g in ($all | Group-Object { "$($_.Confidence)" } | Sort-Object Count -Descending)) { $confCounts[$g.Name] = $g.Count }

    $identity = $null; $recon = $null
    if ($Profile) {
        $identity = [ordered]@{
            name = "$($Profile.Name)"; version = "$($Profile.Version)"; publisher = "$($Profile.Publisher)"
            type = "$($Profile.AppType)"; runtime = "$($Profile.Runtime)"; privilege = "$($Profile.PrivilegeModel)"
        }
        $recon = [ordered]@{
            endpoints = @($Profile.EndpointMap)
            ports     = @($Profile.ListeningPorts)
            handlers  = @($Profile.ProtocolHandlers).Count
            pipes     = @($Profile.NamedPipes).Count
            com       = @($Profile.ComServers).Count
        }
    }

    $ver = '1.5.0-dev'; try { $v = (Get-Module TCPK | Select-Object -First 1).Version; if ($v) { $ver = "$v" } } catch { }
    [ordered]@{
        meta     = [ordered]@{ target = "$Target"; version = $ver; generated = (Get-Date).ToUniversalTime().ToString('u'); total = $all.Count }
        summary  = [ordered]@{ severity = $sevCounts; confidence = $confCounts }
        identity = $identity
        recon    = $recon
        findings = @($records)
    }
}

# Escape every '<' in a JSON string to its < unicode form so an embedded
# <script type="application/json"> block can never be closed early by a literal
# '</script' inside finding evidence. '<' only appears inside JSON string values, so a
# blanket replace is safe; a JSON parser reads < back as '<'. The escape is built
# from [char]92 (backslash) so this source file carries no raw backslash-u sequence.
function Protect-TcpkJsonForScript {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $lt = [string][char]92 + 'u003c'
    return $Json.Replace('<', $lt)
}
