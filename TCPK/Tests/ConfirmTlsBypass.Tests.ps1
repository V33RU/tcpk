#requires -Version 5.1
# Pester 5 tests for Confirm-TcpkTlsBypass and its deterministic IL prover.
#
# The prover (Test-TcpkIlReturnsTrueUnconditionally) is pure logic over the IL text
# that Get-TcpkMethodIl emits, so these tests need no compiled assembly and no
# Mono.Cecil - they prove the verdict logic directly. The IL strings below are in
# the exact format Get-TcpkMethodIl produces (header lines prefixed //, one
# instruction per line as "  <opcode>  <operand>").

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # Invoke the module-internal prover with a given IL string.
    function script:Verdict([string]$il) {
        & (Get-Module TCPK) { param($x) Test-TcpkIlReturnsTrueUnconditionally -Il $x } $il
    }
}

Describe 'Confirm-TcpkTlsBypass is exported' {
    It 'is available as a command' {
        Get-Command Confirm-TcpkTlsBypass -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'IL prover - deterministic verdicts' {

    It 'CONFIRMS a release-build `=> true` callback (ldc.i4.1 ; ret)' {
        $il = @'
// App.Net::<ConfigureClient>b__0
// returns Boolean, 2 IL instructions
  ldc.i4.1
  ret
'@
        (Verdict $il).Verdict | Should -Be 'unconditional-true'
    }

    It 'CONFIRMS a debug-build `=> true` (constant via local + unconditional br.s)' {
        $il = @'
// App.Net::<ConfigureClient>b__0
// returns Boolean, 6 IL instructions
  nop
  ldc.i4.1
  stloc.0
  br.s        IL_0007
  ldloc.0
  ret
'@
        (Verdict $il).Verdict | Should -Be 'unconditional-true'
    }

    It 'does NOT confirm errors == SslPolicyErrors.None (comparison present)' {
        $il = @'
// App.Net::Validate
// returns Boolean, 6 IL instructions
  ldarg.3
  ldc.i4.0
  ceq
  stloc.0
  ldloc.0
  ret
'@
        $v = Verdict $il
        $v.Verdict  | Should -Be 'conditional'
        $v.CompareOp | Should -Be 'ceq'
    }

    It 'does NOT confirm a body with a conditional branch (brtrue.s)' {
        $il = @'
// App.Net::Validate
// returns Boolean, 6 IL instructions
  ldarg.3
  brtrue.s    IL_0006
  ldc.i4.1
  ret
  ldc.i4.0
  ret
'@
        $v = Verdict $il
        $v.Verdict  | Should -Be 'conditional'
        $v.BranchOp | Should -Be 'brtrue.s'
    }

    It 'does NOT confirm a callback that can return false (ldc.i4.0 ; ret)' {
        $il = @'
// App.Net::Validate
// returns Boolean, 2 IL instructions
  ldc.i4.0
  ret
'@
        (Verdict $il).Verdict | Should -Be 'returns-false-possible'
    }

    It 'does NOT confirm a non-Boolean method' {
        $il = @'
// App.Net::GetName
// returns String, 2 IL instructions
  ldstr       "host"
  ret
'@
        (Verdict $il).Verdict | Should -Be 'not-bool'
    }

    It 'does not throw on empty IL' {
        { Verdict '' } | Should -Not -Throw
        (Verdict '').Verdict | Should -Be 'not-bool'
    }
}

Describe 'Confirm-TcpkTlsBypass - finding pass-through' {

    It 'passes a non cert-validation finding through unchanged' {
        $out = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module static -RuleId 'secrets.api-key' -Severity HIGH -Title 'key' -File 'x.dll' -Confidence 'Confirmed'
            $f | Confirm-TcpkTlsBypass
        }
        $out.RuleId     | Should -Be 'secrets.api-key'
        $out.Confidence | Should -Be 'Confirmed'
    }

    It 'passes a cert finding with a missing file through without promoting it' {
        $missing = Join-Path $env:TEMP ('tcpk-no-such-' + [guid]::NewGuid().ToString('N') + '.dll')
        $out = & (Get-Module TCPK) { param($file)
            $f = New-TcpkFinding -Module static -RuleId 'tls-bypass.cb' -Severity HIGH -Title 'cb' -File $file -Confidence 'Inferred'
            $f | Confirm-TcpkTlsBypass
        } $missing
        $out.Confidence | Should -Be 'Inferred'
    }
}
