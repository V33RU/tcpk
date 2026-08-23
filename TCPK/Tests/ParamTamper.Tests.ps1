#requires -Version 5.1
# Pester 5: the parameter-tamper engine.
#
# Location discovery, the mutation table and the verdict are pure functions over data, so they
# are tested without a socket. The behaviour that matters most is the NEGATIVE one: an endpoint
# that answers a deliberately invalid value exactly as it answers a good one must come back
# not-conclusive, never accepted. Getting that wrong reports every permissive endpoint as
# vulnerable on every parameter it has, which is the same defect the vertical authorization
# matrix shipped with before it was fixed.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkTamperMutation' {
    It 'drops a price to a token amount' {
        InModuleScope TCPK { Get-TcpkTamperMutation -Class 'price' -Value '49.99' | Should -Be '0.01' }
    }

    It 'flips a boolean rather than always setting true' {
        InModuleScope TCPK {
            Get-TcpkTamperMutation -Class 'bool' -Value 'false' | Should -Be 'true'
            Get-TcpkTamperMutation -Class 'bool' -Value 'true'  | Should -Be 'false'
        }
    }

    It 'refuses a value that does not fit the class' {
        InModuleScope TCPK {
            Get-TcpkTamperMutation -Class 'price' -Value 'not-a-number' | Should -BeNullOrEmpty
            Get-TcpkTamperMutation -Class 'qty'   -Value '1.5'          | Should -BeNullOrEmpty
        }
    }

    It 'refuses a mutation that equals the original, which would test nothing' {
        # A price already at 0.01 would produce an identical request, and any accepted verdict
        # would be the baseline measured against itself.
        InModuleScope TCPK { Get-TcpkTamperMutation -Class 'price' -Value '0.01' | Should -BeNullOrEmpty }
    }

    It 'returns nothing for an unknown class' {
        InModuleScope TCPK { Get-TcpkTamperMutation -Class 'nope' -Value '1' | Should -BeNullOrEmpty }
    }
}

Describe 'Get-TcpkTamperLocations' {
    BeforeAll {
        function script:NewSpec($query, $body, $ctype) {
            $q = New-Object 'System.Collections.Specialized.OrderedDictionary'
            if ($query) { foreach ($k in $query.Keys) { $q[$k] = $query[$k] } }
            @{ Method='POST'; Path='/checkout'; Query=$q; Headers=@{}; Cookies=@{}
               Body = if ($body) { [Text.Encoding]::UTF8.GetBytes($body) } else { $null }
               ContentType = $ctype }
        }
    }

    It 'finds a price in the query string and classes it' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec @{ price = '49.99' } $null $null) } {
            param($s)
            $l = @(Get-TcpkTamperLocations -Spec $s)
            $l.Count | Should -Be 1
            $l[0].Kind | Should -Be 'query'
            $l[0].Class | Should -Be 'price'
            $l[0].Mutated | Should -Be '0.01'
        }
    }

    It 'ignores a parameter whose name matches no class' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec @{ colour = 'red' } $null $null) } {
            param($s)
            @(Get-TcpkTamperLocations -Spec $s).Count | Should -Be 0
        }
    }

    It 'ignores a class-shaped name whose value does not fit the class' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec @{ price = 'free' } $null $null) } {
            param($s)
            @(Get-TcpkTamperLocations -Spec $s).Count | Should -Be 0
        }
    }

    It 'finds a JSON body leaf by dotted path' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec $null '{"order":{"total":100,"sku":"AB1"}}' 'application/json') } {
            param($s)
            $l = @(Get-TcpkTamperLocations -Spec $s)
            $l.Count | Should -Be 1
            $l[0].Kind | Should -Be 'json'
            $l[0].Key | Should -Be '$.order.total'
        }
    }

    It 'finds a form field' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec $null 'quantity=2&sku=AB1' 'application/x-www-form-urlencoded') } {
            param($s)
            $l = @(Get-TcpkTamperLocations -Spec $s)
            $l.Count | Should -Be 1
            $l[0].Kind | Should -Be 'form'
            $l[0].Mutated | Should -Be '-1'
        }
    }

    It 'yields one test per parameter, not one per matching class' {
        InModuleScope TCPK -Parameters @{ s = (script:NewSpec @{ amount = '10' } $null $null) } {
            param($s)
            @(Get-TcpkTamperLocations -Spec $s).Count | Should -Be 1
        }
    }
}

Describe 'Get-TcpkTamperVerdict' {
    BeforeAll {
        function script:Snap($status, $hash, $len) { @{ Status=$status; Hash=$hash; Len=$len; BodyHead='' } }
    }

    It 'reports accepted when the tamper looks like success and the control was rejected' {
        InModuleScope TCPK {
            $v = Get-TcpkTamperVerdict -Baseline (script:Snap 200 'sha256:ok' 100) `
                                       -Tampered (script:Snap 200 'sha256:ok' 100) `
                                       -Bogus    (script:Snap 400 'sha256:err' 20)
            $v | Should -Be 'accepted'
        }
    }

    It 'reports rejected when the tamper looks like the control' {
        InModuleScope TCPK {
            $v = Get-TcpkTamperVerdict -Baseline (script:Snap 200 'sha256:ok' 100) `
                                       -Tampered (script:Snap 400 'sha256:err' 20) `
                                       -Bogus    (script:Snap 400 'sha256:err' 20)
            $v | Should -Be 'rejected'
        }
    }

    It 'reports not-conclusive when the control was ALSO accepted' {
        # The endpoint answers garbage exactly as it answers a good value, so nothing it returns
        # can separate accepted from rejected. Calling this "accepted" would flag every
        # permissive endpoint on every parameter.
        InModuleScope TCPK {
            $v = Get-TcpkTamperVerdict -Baseline (script:Snap 200 'sha256:ok' 100) `
                                       -Tampered (script:Snap 200 'sha256:ok' 100) `
                                       -Bogus    (script:Snap 200 'sha256:ok' 100)
            $v | Should -Be 'not-conclusive'
        }
    }

    It 'reports not-conclusive on a transport failure rather than guessing' {
        InModuleScope TCPK {
            $v = Get-TcpkTamperVerdict -Baseline (script:Snap 200 'sha256:ok' 100) `
                                       -Tampered (script:Snap 0 'sha256:error' 0) `
                                       -Bogus    (script:Snap 400 'sha256:err' 20)
            $v | Should -Be 'not-conclusive'
        }
    }

    It 'reports not-conclusive when the tamper matches neither reference' {
        InModuleScope TCPK {
            $v = Get-TcpkTamperVerdict -Baseline (script:Snap 200 'sha256:ok' 100) `
                                       -Tampered (script:Snap 200 'sha256:other' 55) `
                                       -Bogus    (script:Snap 400 'sha256:err' 20)
            $v | Should -Be 'not-conclusive'
        }
    }
}

Describe 'Invoke-TcpkParamTamper: gates' {
    It 'refuses without -ConfirmActive' {
        { Invoke-TcpkParamTamper -Url 'http://127.0.0.1:1/x?price=9.99' -Target '127.0.0.1' } |
            Should -Throw -ExpectedMessage '*ConfirmActive*'
    }
}
