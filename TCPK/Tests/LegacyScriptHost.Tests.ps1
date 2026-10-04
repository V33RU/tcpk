#requires -Version 5.1
#
# Pester 5: the legacy Windows script/HTML engine callsite rules.
#
# WHY THESE EXIST. TCPK had seven WebView2 cmdlets plus CefSharp and Electron coverage and
# nothing at all for the engines those replaced. A thick client that embeds MSHTML, hosts
# Active Scripting, or runs MSXML XSLT inherits a surface the operator usually believes is
# switched off: the VBScript execution policy that disables VBScript for the Internet Zone
# never covered MSXML stylesheets (CVE-2018-8619) and did not cover MSHTML in every path
# (CVE-2019-0768). Those are Microsoft's bugs, but EMBEDDING the engine is the vendor's
# decision and the vendor's to fix, which is what makes it in scope here.
#
# WHAT THE NEGATIVE CASES ARE FOR, and why they matter more than the positives. msxml6 is
# the ordinary way to parse XML on Windows and appears in a large share of desktop
# applications. A rule that fired on the presence of MSXML would produce a finding on almost
# every target and mean nothing. The patterns therefore key on XSLT-specific symbols and on
# the two properties that re-enable script and document(), never on the parser itself.
# If someone later "improves" these rules by adding a bare DLL name, these tests fail.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force

    $script:fx = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-legacy-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # Add-Type rather than CSharpCodeProvider: CompileAssemblyFromSource throws
    # PlatformNotSupportedException on .NET Core, so the fixture could never build off
    # .NET Framework and every assertion would silently skip. Literals land in the #US heap
    # either way, which is what Read-TcpkAllText scans.
    function New-MarkerDll([string]$Name, [string]$Body) {
        $dll = Join-Path $script:fx $Name
        try {
            Add-Type -TypeDefinition $Body -OutputAssembly $dll -OutputType Library -ErrorAction Stop
            if (Test-Path $dll) { return $dll }
        } catch { }
        return $null
    }

    $script:htmlDll = New-MarkerDll 'LegacyHtmlHost.dll' @'
public class LegacyHtmlHost {
    public string a = "IWebBrowser2";
    public string b = "IHTMLDocument2";
    public string c = "System.Windows.Forms.WebBrowser";
}
'@
    $script:scriptDll = New-MarkerDll 'LegacyScriptHost.dll' @'
public class LegacyScriptHost {
    public string a = "IActiveScriptParse";
    public string b = "MSScriptControl";
}
'@
    $script:xsltDll = New-MarkerDll 'MsxmlXsltHost.dll' @'
public class MsxmlXsltHost {
    public string a = "AllowXsltScript";
    public string b = "AllowDocumentFunction";
    public string c = "IXSLProcessor";
}
'@
    # The control: ordinary MSXML parsing and a modern WebView2 host. Neither may fire.
    $script:benignDll = New-MarkerDll 'PlainXmlHost.dll' @'
public class PlainXmlHost {
    public string a = "msxml6.dll";
    public string b = "IXMLDOMDocument";
    public string c = "selectSingleNode";
    public string d = "Microsoft.Web.WebView2.Core";
    public string e = "CoreWebView2";
}
'@
    function Get-Rules($Dll) {
        if (-not $Dll) { return $null }
        return @(Test-TcpkCallsites -Path $Dll | Select-Object -ExpandProperty RuleId)
    }
}

AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Legacy engine hosting is detected' {

    It 'flags an app embedding the IE/Trident HTML engine' {
        if (-not $script:htmlDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        Get-Rules $script:htmlDll | Should -Contain 'callsites.legacy-html-control'
    }

    It 'flags an app hosting the Active Scripting engine' {
        if (-not $script:scriptDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        Get-Rules $script:scriptDll | Should -Contain 'callsites.legacy-script-engine-host'
    }

    It 'flags MSXML XSLT, and hardest when script and document() are re-enabled' {
        if (-not $script:xsltDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $f = @(Test-TcpkCallsites -Path $script:xsltDll | Where-Object { $_.RuleId -eq 'callsites.msxml-xslt-transform' })
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'HIGH'
        # The Evidence names which patterns matched, which is how an analyst separates
        # "uses XSLT" from "deliberately turned the protections off".
        $f[0].Evidence | Should -Match 'AllowXsltScript'
    }
}

Describe 'Ordinary XML parsing and modern engines stay silent' {

    It 'does NOT flag plain MSXML parsing as a script host' {
        # The whole point of the pattern choice. msxml6 is how Windows applications parse
        # XML; firing on it would put a finding on nearly every target and say nothing.
        if (-not $script:benignDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $r = Get-Rules $script:benignDll
        $r | Should -Not -Contain 'callsites.msxml-xslt-transform'
    }

    It 'does NOT flag a WebView2 host as a legacy HTML control' {
        if (-not $script:benignDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $r = Get-Rules $script:benignDll
        $r | Should -Not -Contain 'callsites.legacy-html-control'
    }

    It 'leaves the managed XslCompiledTransform path to callsites.xslt-injection' {
        # Two rules must not both claim the same call. The native rule keys on MSXML
        # symbols; the managed one keys on the .NET type names.
        $native = & (Get-Module TCPK) {
            (Get-TcpkData).callsite_patterns | Where-Object { $_.id -eq 'msxml-xslt-transform' } |
                Select-Object -ExpandProperty patterns
        }
        $native | Should -Not -Contain 'XslCompiledTransform'
        $native | Should -Not -Contain 'XsltSettings'
    }
}

Describe 'Rule metadata is complete' {

    It 'every new rule carries a title, CWE and description' -ForEach @(
        @{ Id = 'legacy-html-control' }
        @{ Id = 'legacy-script-engine-host' }
        @{ Id = 'msxml-xslt-transform' }
    ) {
        $p = & (Get-Module TCPK) { param($i)
            (Get-TcpkData).callsite_patterns | Where-Object { $_.id -eq $i }
        } $Id
        $p | Should -Not -BeNullOrEmpty -Because "$Id should exist in secrets.json"
        $p.title       | Should -Not -BeNullOrEmpty
        $p.description | Should -Not -BeNullOrEmpty
        @($p.cwe).Count | Should -BeGreaterThan 0
        @($p.patterns).Count | Should -BeGreaterThan 0
    }
}

Describe 'Named-pipe caller identified by PID' {

    # CVE-free but well documented: a PID is reusable and can be made to point at a binary
    # the caller did not write, so resolving the client PID and checking its image path or
    # signature is a spoofable authorisation decision. This is the commonest authorisation
    # pattern in thick-client helper services, which is why it is HIGH.

    BeforeAll {
        $script:pipeFx = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-pipe-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:pipeFx | Out-Null
        $script:pidDll = Join-Path $script:pipeFx 'PipePidAuth.dll'
        try {
            Add-Type -TypeDefinition @'
public class PipePidAuth {
    public string a = "GetNamedPipeClientProcessId";
    public string b = "NamedPipeServerStream";
}
'@ -OutputAssembly $script:pidDll -OutputType Library -ErrorAction Stop
        } catch { $script:pidDll = $null }
    }
    AfterAll {
        if ($script:pipeFx -and (Test-Path $script:pipeFx)) {
            Remove-Item $script:pipeFx -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'flags a pipe server that resolves the client PID' {
        if (-not $script:pidDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $f = @(Test-TcpkCallsites -Path $script:pidDll | Where-Object { $_.RuleId -eq 'callsites.pipe-client-pid-auth' })
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'HIGH'
    }

    It 'no longer recommends PID verification as the mitigation' {
        # The named-pipe-server advice used to say "GetNamedPipeClientProcessId +
        # VerifyProcess", which is the control this rule exists to flag. TCPK was
        # recommending the weakness.
        $desc = & (Get-Module TCPK) {
            ((Get-TcpkData).callsite_patterns | Where-Object { $_.id -eq 'named-pipe-server' }).description
        }
        $desc | Should -Not -Match 'GetNamedPipeClientProcessId \+ VerifyProcess'
        $desc | Should -Match 'ImpersonateNamedPipeClient'
    }
}

Describe 'Project Zero "other logic" harvest' {

    # Three rules recovered from the 51-bug bucket a keyword classifier had filed as
    # "other logic". All three are vendor-actionable and none were covered.

    BeforeAll {
        $script:zFx = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-z-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:zFx | Out-Null
        function New-ZDll([string]$Name, [string]$Body) {
            $dll = Join-Path $script:zFx $Name
            try { Add-Type -TypeDefinition $Body -OutputAssembly $dll -OutputType Library -ErrorAction Stop } catch { return $null }
            if (Test-Path $dll) { return $dll }
            return $null
        }
        $script:dcomDll = New-ZDll 'WmiClient.dll' @'
public class WmiClient {
    public string a = "ManagementObjectSearcher";
    public string b = "ManagementScope";
}
'@
        $script:sxDll = New-ZDll 'SigVerify.dll' @'
public class SigVerify {
    public string a = "SignedXml";
    public string b = "System.Security.Cryptography.Xml";
}
'@
        $script:tlbDll = New-ZDll 'TlbLoader.dll' @'
public class TlbLoader {
    public string a = "LoadTypeLibEx";
}
'@
        # The documented fix for the WMI case. Must stay silent or the rule punishes
        # the remediation it recommends.
        $script:cimDll = New-ZDll 'CimClient.dll' @'
public class CimClient {
    public string a = "Microsoft.Management.Infrastructure";
    public string b = "CimSession";
}
'@
    }
    AfterAll {
        if ($script:zFx -and (Test-Path $script:zFx)) { Remove-Item $script:zFx -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a .NET DCOM / WMI client (server-controlled BinaryFormatter deserialization)' {
        if (-not $script:dcomDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $f = @(Test-TcpkCallsites -Path $script:dcomDll | Where-Object { $_.RuleId -eq 'callsites.dotnet-dcom-client' })
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'HIGH'
    }

    It 'does NOT flag the CIM client, which is the documented fix' {
        if (-not $script:cimDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        @(Test-TcpkCallsites -Path $script:cimDll | Select-Object -ExpandProperty RuleId) |
            Should -Not -Contain 'callsites.dotnet-dcom-client'
    }

    It 'flags XML signature verification as an XXE sink' {
        if (-not $script:sxDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        @(Test-TcpkCallsites -Path $script:sxDll | Select-Object -ExpandProperty RuleId) |
            Should -Contain 'callsites.signedxml-xxe'
    }

    It 'flags LoadTypeLib moniker fallback' {
        if (-not $script:tlbDll) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        @(Test-TcpkCallsites -Path $script:tlbDll | Select-Object -ExpandProperty RuleId) |
            Should -Contain 'callsites.typelib-moniker-fallback'
    }

    It 'maps each to a DEFINED CVSS archetype' {
        # remote-input-rce was invented during this work and does not exist in the vector
        # table; an undefined archetype scores with the wrong vector silently.
        $src = [IO.File]::ReadAllText((Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Private\_Finding.ps1'))
        $used = [regex]::Matches($src, "A = '([a-z-]+)'") | ForEach-Object { $_.Groups[1].Value }
        $defined = [regex]::Matches($src, "(?m)^\s*'([a-z-]+)'\s*=\s*'CVSS") | ForEach-Object { $_.Groups[1].Value }
        foreach ($a in @('net-rce','untrusted-parse','local-privesc')) {
            $defined | Should -Contain $a
        }
        $src | Should -Not -Match 'remote-input-rce'
    }
}

Describe 'App creates a filesystem link (symlink/reparse residue)' {

    # The twelve Project Zero symlink/reparse CVEs are all Windows-kernel bugs, not vendor
    # bugs. The half a vendor owns is CREATING the link: a redirection primitive that becomes
    # privilege escalation when a privileged component makes one under a user-writable path.
    # This is a positive match (an API the app calls), not an absence proof.

    BeforeAll {
        $script:lnkFx = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-lnk-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:lnkFx | Out-Null
        function New-LnkDll([string]$Name,[string]$Body){
            $d=Join-Path $script:lnkFx $Name
            try { Add-Type -TypeDefinition $Body -OutputAssembly $d -OutputType Library -ErrorAction Stop } catch { return $null }
            if (Test-Path $d){ return $d }; return $null
        }
        $script:mk = New-LnkDll 'MakesLink.dll' @'
public class MakesLink { public string a = "CreateSymbolicLinkW"; public string b = "CreateHardLinkW"; }
'@
        $script:plain = New-LnkDll 'PlainIo.dll' @'
public class PlainIo { public string a = "CreateFileW"; public string b = "ReadFile"; public string c = "WriteFile"; }
'@
    }
    AfterAll { if ($script:lnkFx -and (Test-Path $script:lnkFx)){ Remove-Item $script:lnkFx -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'flags an app that creates symlinks / hard links' {
        if (-not $script:mk){ Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        @(Test-TcpkCallsites -Path $script:mk | Select-Object -ExpandProperty RuleId) |
            Should -Contain 'callsites.creates-filesystem-link'
    }

    It 'does NOT flag plain file I/O' {
        if (-not $script:plain){ Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        @(Test-TcpkCallsites -Path $script:plain | Select-Object -ExpandProperty RuleId) |
            Should -Not -Contain 'callsites.creates-filesystem-link'
    }
}
