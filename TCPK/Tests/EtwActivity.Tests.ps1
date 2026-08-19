#requires -Version 5.1
# Pester 5: the ETW activity analysers and the operator filter.
#
# These checks previously had no suite at all, and could not have had one: capture and analysis
# were the same function, so testing meant admin rights, a live ETW session and a 30-second
# sleep. Splitting them made the rule logic a pure function over records, which is what this
# pins. Synthetic records use the exact shape Read-TcpkEtwEvents emits.
#
# The behaviour that matters most here is the negative one: an analyser must not claim an event
# it does not own. The DLL-probe and file-write analysers read the same provider over the same
# capture, so a probe leaking into the write report would double-count every hijack candidate.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Test-TcpkEtwPathFilter: operator narrowing' {
    It 'keeps everything when neither Include nor Exclude is given' {
        InModuleScope TCPK {
            Test-TcpkEtwPathFilter -Path 'C:\anything\at\all.txt' | Should -BeTrue
        }
    }

    It 'requires a match against at least one Include pattern' {
        InModuleScope TCPK {
            Test-TcpkEtwPathFilter -Path 'C:\ProgramData\Acme\a.dat' -Include @('\\Acme\\') | Should -BeTrue
            Test-TcpkEtwPathFilter -Path 'C:\Users\bob\b.dat'        -Include @('\\Acme\\') | Should -BeFalse
        }
    }

    It 'drops a path matching any Exclude pattern' {
        InModuleScope TCPK {
            Test-TcpkEtwPathFilter -Path 'C:\app\trace.log' -Exclude @('\.log$') | Should -BeFalse
        }
    }

    It 'lets Exclude beat Include, because a silencer that Include can override is not one' {
        InModuleScope TCPK {
            Test-TcpkEtwPathFilter -Path 'C:\Acme\chatty.log' -Include @('\\Acme\\') -Exclude @('\.log$') |
                Should -BeFalse
        }
    }

    It 'keeps the event when a pattern is invalid, rather than manufacturing a clean result' {
        # A typo in a filter must never look like "nothing was found".
        InModuleScope TCPK {
            Test-TcpkEtwPathFilter -Path 'C:\a\b.txt' -Include @('[unclosed') | Should -BeTrue
        }
    }

    It 'drops an empty path' {
        InModuleScope TCPK { Test-TcpkEtwPathFilter -Path '' | Should -BeFalse }
    }
}

Describe 'ConvertTo-TcpkDllSearchFinding' {
    It 'reports only a .dll that returned STATUS_OBJECT_NAME_NOT_FOUND' {
        InModuleScope TCPK {
            $ev = @(
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\app\missing.dll'; Status='0xC0000034'; ValueName=$null }
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\app\present.dll'; Status='0x0';        ValueName=$null }
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\app\notes.txt';   Status='0xC0000034'; ValueName=$null }
            )
            $f = @(ConvertTo-TcpkDllSearchFinding -Events $ev -ProcName 'app')
            $f.Count | Should -Be 1
            $f[0].RuleId | Should -Be 'dll-search.name-not-found'
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].File | Should -Be 'C:\app\missing.dll'
        }
    }

    It 'names the PID that actually raised the event, which may be a child' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=4242; Path='C:\app\x.dll'; Status='0xC0000034'; ValueName=$null })
            (@(ConvertTo-TcpkDllSearchFinding -Events $ev -ProcName 'app')[0]).Evidence | Should -Match 'PID=4242'
        }
    }

    It 'deduplicates a probe repeated in a loop' {
        InModuleScope TCPK {
            $ev = 1..5 | ForEach-Object {
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\app\x.dll'; Status='0xC0000034'; ValueName=$null }
            }
            @(ConvertTo-TcpkDllSearchFinding -Events @($ev) -ProcName 'app').Count | Should -Be 1
        }
    }

    It 'honours Exclude' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\app\x.dll'; Status='0xC0000034'; ValueName=$null })
            @(ConvertTo-TcpkDllSearchFinding -Events $ev -ProcName 'app' -Exclude @('\\app\\')).Count | Should -Be 0
        }
    }
}

Describe 'ConvertTo-TcpkFileActivityFinding' {
    It 'grades a credential-named write HIGH and Confirmed' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Users\bob\AppData\Roaming\app\token.dat'; Status='0x0'; ValueName=$null })
            $f = @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app')
            $f.Count | Should -Be 1
            $f[0].RuleId | Should -Be 'file.write-credential-name'
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Confidence | Should -Be 'Confirmed'
        }
    }

    It 'grades a plain user-writable-path write INFO and Inferred, since most apps do it legitimately' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Users\bob\AppData\Local\app\cache.bin'; Status='0x0'; ValueName=$null })
            $f = @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app')
            $f[0].RuleId | Should -Be 'file.write-user-writable-path'
            $f[0].Severity | Should -Be 'INFO'
            $f[0].Confidence | Should -Be 'Inferred'
        }
    }

    It 'does NOT claim a DLL probe that belongs to the dll-search analyser' {
        # Both analysers read the same provider over the same capture now, so a probe leaking
        # in here would double-count every hijack candidate as a write as well.
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Temp\missing.dll'; Status='0xC0000034'; ValueName=$null })
            @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app').Count | Should -Be 0
        }
    }

    It 'skips OS and ETW noise paths' {
        InModuleScope TCPK {
            $ev = @(
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Windows\System32\kernel32.dll'; Status='0x0'; ValueName=$null }
                [pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Temp\TCPK-Activity-ab12cd34.etl'; Status='0x0'; ValueName=$null }
            )
            @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app').Count | Should -Be 0
        }
    }

    It 'flags a write outside the install tree when InstallDir is known' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='\Device\HarddiskVolume2\Data\out.bin'; Status='0x0'; ValueName=$null })
            $f = @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app' -InstallDir 'c:\program files\app')
            $f.Count | Should -Be 1
            $f[0].RuleId | Should -Be 'file.write-outside-install'
        }
    }

    It 'reports nothing at all when InstallDir is unknown and the path is unremarkable' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=12; ProcessId=100; Path='C:\Data\out.bin'; Status='0x0'; ValueName=$null })
            @(ConvertTo-TcpkFileActivityFinding -Events $ev -ProcName 'app').Count | Should -Be 0
        }
    }
}

Describe 'ConvertTo-TcpkRegistryFinding' {
    It 'reads only write-shaped event ids, not reads or opens' {
        InModuleScope TCPK {
            $ev = @(
                [pscustomobject]@{ EventId=5;  ProcessId=100; Path='\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName='App'; Status=$null }
                [pscustomobject]@{ EventId=10; ProcessId=100; Path='\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName='App'; Status=$null }
            )
            @(ConvertTo-TcpkRegistryFinding -Events $ev -ProcName 'app').Count | Should -Be 1
        }
    }

    It 'grades a credential-named value HIGH under reg.write.credential' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=5; ProcessId=100; Path='\REGISTRY\USER\S-1-5-21\Software\Acme'; ValueName='ApiToken'; Status=$null })
            $f = @(ConvertTo-TcpkRegistryFinding -Events $ev -ProcName 'app')
            $f[0].RuleId | Should -Be 'reg.write.credential'
            $f[0].Severity | Should -Be 'HIGH'
        }
    }

    It 'grades a persistence path INFO and Inferred, not a finding in its own right' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=13; ProcessId=100; Path='\REGISTRY\MACHINE\System\CurrentControlSet\Services\AcmeSvc'; ValueName=''; Status=$null })
            $f = @(ConvertTo-TcpkRegistryFinding -Events $ev -ProcName 'app')
            $f[0].RuleId | Should -Be 'reg.write.persistence-path'
            $f[0].Severity | Should -Be 'INFO'
            $f[0].Confidence | Should -Be 'Inferred'
        }
    }

    It 'ignores a write to an unremarkable key' {
        InModuleScope TCPK {
            $ev = @([pscustomobject]@{ EventId=5; ProcessId=100; Path='\REGISTRY\USER\S-1-5-21\Software\Acme\WindowPos'; ValueName='Left'; Status=$null })
            @(ConvertTo-TcpkRegistryFinding -Events $ev -ProcName 'app').Count | Should -Be 0
        }
    }

    It 'deduplicates the same op on the same key and value' {
        InModuleScope TCPK {
            $ev = 1..4 | ForEach-Object {
                [pscustomobject]@{ EventId=5; ProcessId=100; Path='\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName='App'; Status=$null }
            }
            @(ConvertTo-TcpkRegistryFinding -Events @($ev) -ProcName 'app').Count | Should -Be 1
        }
    }
}

Describe 'Get-TcpkProcessTreeId' {
    It 'always contains the process itself' {
        InModuleScope TCPK {
            $t = Get-TcpkProcessTreeId -ProcessId $PID
            $t.Contains($PID) | Should -BeTrue
        }
    }

    It 'returns a set, so a repeated call cannot double-count a PID' {
        InModuleScope TCPK {
            (Get-TcpkProcessTreeId -ProcessId $PID).GetType().Name | Should -Be 'HashSet`1'
        }
    }
}
