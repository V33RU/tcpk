#requires -Version 5.1
#
# A CRITICAL or HIGH finding has to say why it matters. -Description is the paragraph the
# report prints between the title and the fix, and -Impact is the one-line alternative some
# exploit rules use instead. A finding with neither shows the reader a title, a path and a
# CWE number, and never tells them what an attacker gets.
#
# WHY THIS EXISTS RATHER THAN JUST FIXING THEM. Nothing in the module requires either
# parameter: New-TcpkFinding declares a plain [string] $Description with no Mandatory and no
# validation (_Finding.ps1). So the gap grew silently to 21 CRITICAL/HIGH emitters, and
# without a gate it would grow back at exactly the same rate while the backlog is worked off.
#
# The repo already had this idea and it did not stick. Find-TcpkUnguardedEmitters
# (Private\Resolve-TcpkImpact.ps1) performs the same kind of audit for a different property
# and its own help says to "run this before releasing a version", but nothing calls it, so it
# only helps when someone remembers. This is the same audit wired to a test that cannot be
# forgotten.
#
# HOW TO USE IT. $KnownMissing is a worklist, not a permanent exemption. Writing the
# explanation for one of these means DELETING its line here. The test fails if a rule not on
# the list ships without one, and it also fails if a rule on the list has been fixed but left
# behind, so the list cannot rot into a lie about the state of the codebase.

Describe 'CRITICAL and HIGH findings explain themselves' {

    BeforeAll {
        $script:PublicDir = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public'

        # Walk every New-TcpkFinding invocation, following backtick continuations, and
        # report the CRITICAL/HIGH ones that carry neither -Description nor -Impact.
        # A single-line grep cannot do this: these calls routinely span eight lines.
        $script:Unexplained = @()
        foreach ($file in (Get-ChildItem -LiteralPath $script:PublicDir -Recurse -File -Filter '*.ps1' | Sort-Object FullName)) {
            $lines = [IO.File]::ReadAllLines($file.FullName)
            $i = 0
            while ($i -lt $lines.Count) {
                $line = $lines[$i]
                if ($line -notmatch 'New-TcpkFinding' -or $line.TrimStart().StartsWith('#')) { $i++; continue }

                $buf = New-Object 'System.Collections.Generic.List[string]'
                $j = $i
                while ($j -lt $lines.Count) {
                    $buf.Add($lines[$j])
                    if (-not $lines[$j].TrimEnd().EndsWith('`')) { break }
                    $j++
                }
                $call = ($buf.ToArray()) -join "`n"

                if ($call -match "-Severity\s+'(CRITICAL|HIGH)'" -and
                    $call -notmatch '-Description' -and $call -notmatch '-Impact') {
                    $rule = $file.BaseName + ':dynamic'
                    if ($call -match "-RuleId\s+'([^']+)'") { $rule = $Matches[1] }
                    $script:Unexplained += $rule
                }
                $i = $j + 1
            }
        }
        $script:Unexplained = @($script:Unexplained | Sort-Object -Unique)

        # The backlog, worst severity first when it was captured. Delete a line when you
        # write that rule's explanation. Do not add to it without a reason in the commit.
        $script:KnownMissing = @(
            'Test-TcpkPlaintextConfigs:dynamic'
            'app-config.connstring-password'
            'authenticode.msix-not-valid'
            'authenticode.tampered'
            'authmatrix.no-auth-accepted'
            'authmatrix.vertical-escalation'
            'dpapi.user-decryptable'
            'fuzz.crash-minimized'
            'install-dir.user-writable'
            'javasign.incomplete-coverage'
            'jni.library-path-writable'
            'jni.manifest-classpath-writable'
            'jwt.nbf-not-enforced-accepted'
            'jwt.privilege-escalation-accepted'
            'loadpoint.writable'
            'service.unquoted-path'
            'service.weak-dacl'
            'service.writable-binary'
            'wcf.basichttp-cleartext'
            'wcf.no-auth'
            'webview2.are-host-objects-allowed'
        )
    }

    It 'finds emitters to check at all' {
        # Guards the scanner itself. If the walk breaks, every other assertion in this file
        # passes vacuously and the gate silently stops gating.
        $all = @(Get-ChildItem -LiteralPath $script:PublicDir -Recurse -File -Filter '*.ps1' |
                 Select-String -Pattern 'New-TcpkFinding' -SimpleMatch)
        $all.Count | Should -BeGreaterThan 100
    }

    It 'has no NEW CRITICAL or HIGH finding without a Description or an Impact' {
        $new = @($script:Unexplained | Where-Object { $script:KnownMissing -notcontains $_ })
        $new -join ', ' | Should -BeNullOrEmpty -Because (
            'a CRITICAL or HIGH finding must tell the reader what an attacker gets. ' +
            'Add -Description (the report paragraph) or -Impact (the one-line form), ' +
            'or add the rule id to $KnownMissing in this file with a reason.')
    }

    It 'has no stale entry left in the backlog' {
        # Keeps the list honest in the other direction: once a rule is explained, its line
        # here has to go, so the list always reads as the real remaining work.
        $stale = @($script:KnownMissing | Where-Object { $script:Unexplained -notcontains $_ })
        $stale -join ', ' | Should -BeNullOrEmpty -Because (
            'these rules now carry an explanation, so remove them from $KnownMissing')
    }
}
