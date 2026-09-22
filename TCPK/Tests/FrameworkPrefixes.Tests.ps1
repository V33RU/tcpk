#requires -Version 5.1
#
# $script:TcpkFrameworkPrefixes is the sole provenance filter at 84 call sites, covering
# crypto misuse, deserialization, TLS, reflection, P/Invoke, endpoints and CVE matching. Its
# two failure modes cost very different amounts:
#
#   a MISSING prefix produces noise. A third-party assembly's attack surface is attributed
#   to the vendor, which is how a CRITICAL landed on EntityFramework.dll. Visible, annoying,
#   and someone eventually reports it.
#
#   an OVER-BROAD prefix produces silence. A vendor assembly whose name happens to start
#   with it is skipped at all 84 sites and the finding is never emitted. Nothing appears in
#   the report, so nobody knows to look.
#
# Both directions are asserted here. The second set matters more, and it is the one a
# reviewer eyeballing a list of prefixes will not think to check.

Describe 'Framework prefix provenance filter' {

    BeforeAll {
        Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force -ErrorAction Stop
        $script:IsFx = { param($n) & (Get-Module TCPK) { param($x) Test-TcpkIsFrameworkFile $x } $n }
    }

    Context 'skips code the vendor did not write' {
        It 'skips <_>' -ForEach @(
            # Runtime and WPF assemblies that start with neither System. nor Microsoft.,
            # which is why the original 29-entry list missed every one of them.
            'mscorlib.dll'
            'netstandard.dll'
            'WindowsBase.dll'
            'PresentationCore.dll'
            'PresentationFramework.Aero2.dll'
            'UIAutomationClient.dll'
            'UIAutomationClientsideProviders.dll'
            'Accessibility.dll'
            'ReachFramework.dll'
            'WindowsFormsIntegration.dll'
            'stdole.dll'
            # Third-party packages that ship inside real desktop apps.
            'EntityFramework.dll'
            'SQLitePCLRaw.core.dll'
            'Dapper.dll'
            'Autofac.Extensions.DependencyInjection.dll'
            'ICSharpCode.SharpZipLib.dll'
            'MahApps.Metro.dll'
            'MaterialDesignThemes.Wpf.dll'
            'Xceed.Wpf.Toolkit.dll'
            'DevExpress.Data.v23.1.dll'
            'Npgsql.dll'
            'Renci.SshNet.dll'
            'Newtonsoft.Json.dll'
            'System.Text.Json.dll'
        ) {
            (& $script:IsFx $_) | Should -BeTrue -Because "$_ is not first-party code"
        }
    }

    Context 'never silences the application' {
        It 'scans <_>' -ForEach @(
            # The target's own binaries.
            'DVTA.exe'
            'DBAccess.dll'
            'ExcelLibrary.dll'
            # Prefixes deliberately REJECTED when the list was extended, each because the
            # name is one a vendor could plausibly give their own assembly. If any of these
            # starts being skipped, a real finding has been silenced at 84 call sites.
            'Prism.Core.dll'
            'DocumentFormat.Export.dll'
            'Squirrel.dll'
            'Unity.Client.dll'
            'Fluent.dll'
            'C1.Win.dll'
            # tlbimp wrappers are generated FROM the vendor's own type library and are
            # exactly where the COM surface lives, so Test-TcpkComInterop needs them.
            'Interop.MyVendorLib.dll'
            # The trailing dot on each prefix is load-bearing. A vendor assembly that merely
            # begins with the same letters must still be scanned, which is why the
            # UIAutomation family is listed name by name rather than as a bare prefix.
            'UIAutomationHelper.dll'
            'EntityFrameworkHelper.dll'
            'Dapperish.dll'
            'MahAppsCustom.dll'
        ) {
            (& $script:IsFx $_) | Should -BeFalse -Because "$_ could be the vendor's own code and must be scanned"
        }
    }

    Context 'agrees with the other framework list in the module' {
        It 'classifies everything TcpkFxAsmSkip calls framework' {
            # _ManagedCve.ps1 keeps its own regex of framework assemblies and the two lists
            # disagreeing about what the vendor wrote was the original defect: TcpkFxAsmSkip
            # already knew WindowsBase and PresentationFramework were framework code while
            # TcpkFrameworkPrefixes did not, so the same file was framework to one check and
            # first-party to another.
            foreach ($n in @('mscorlib', 'netstandard', 'WindowsBase', 'PresentationCore',
                             'PresentationFramework', 'ReachFramework', 'Accessibility')) {
                $inOther = & (Get-Module TCPK) { param($x) [bool]($x -match $script:TcpkFxAsmSkip) } $n
                $inOther | Should -BeTrue -Because "$n should still match TcpkFxAsmSkip"
                (& $script:IsFx ($n + '.dll')) | Should -BeTrue -Because "$n.dll must also be framework to the prefix list"
            }
        }
    }
}
