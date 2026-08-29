#requires -Version 5.1
# Pester 5: pin FunctionsToExport against the actual Public/ tree.
#
# WHY. The manifest is now an explicit list of 279 function names. It was previously
# @('*') and no test could tell whether a new Public cmdlet had been added but the
# manifest not updated. Under Install-Module (or any consumer that reads the psd1
# without loading), an unlisted cmdlet is invisible. This test catches the drift.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    $script:root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
    $script:data = Import-PowerShellDataFile -Path $psd1
    Import-Module $psd1 -Force
}

Describe 'FunctionsToExport is complete and honest' {
    It 'exports every function declared in TCPK/Public/**/*.ps1, no more, no fewer' {
        $onDisk = @()
        Get-ChildItem -Path (Join-Path $script:root 'Public') -Recurse -File -Filter *.ps1 |
            ForEach-Object {
                foreach ($line in [IO.File]::ReadAllLines($_.FullName)) {
                    if ($line -match '^function\s+([A-Za-z][A-Za-z0-9_\-]+)') {
                        $onDisk += $Matches[1]
                    }
                }
            }
        $onDisk = @($onDisk | Sort-Object -Unique)

        $exported = @($script:data.FunctionsToExport | Sort-Object -Unique)

        $missing = @($onDisk | Where-Object { $exported -notcontains $_ })
        $extra   = @($exported | Where-Object { $onDisk -notcontains $_ })

        # Fail loudly with the drift so the maintainer knows exactly what to add or remove.
        if ($missing.Count -or $extra.Count) {
            $msg = "FunctionsToExport drift.`n"
            if ($missing.Count) { $msg += "MISSING from psd1: $($missing -join ', ')`n" }
            if ($extra.Count)   { $msg += "EXTRA in psd1 (no matching Public file): $($extra -join ', ')`n" }
            $msg += "Regenerate with: grep -rhE '^function\s+([A-Za-z-]+)' TCPK/Public/**/*.ps1"
            throw $msg
        }

        $exported.Count | Should -Be $onDisk.Count
    }

    It 'never lists a wildcard' {
        $script:data.FunctionsToExport | Should -Not -Contain '*'
    }

    It 'ProjectUri is a real https URL, not empty and not a placeholder' {
        $uri = $script:data.PrivateData.PSData.ProjectUri
        $uri | Should -Not -BeNullOrEmpty
        $uri | Should -Match '^https://'
        $uri | Should -Not -Be 'https://github.com/'
    }
}
