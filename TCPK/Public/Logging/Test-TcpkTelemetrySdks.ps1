function Test-TcpkTelemetrySdks {
<#
.SYNOPSIS
    H02. Third-party telemetry SDK enumeration.

.DESCRIPTION
    Inventories first-party PEs for references to common telemetry SDKs:
    Segment, Aptabase, App Center, Application Insights, Google Analytics,
    Mixpanel, Sentry, Bugsnag, Rollbar, Datadog, Splunk, OpenTelemetry.

    Not a vulnerability; surfaces the data-flow disclosure scope (every
    integrated SDK potentially ships customer events to its vendor).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Each SDK is matched by SDK-SPECIFIC namespace / assembly / type patterns,
    # NOT bare product words. Bare 'Segment' matched 'EnableUdpSegmentationOffload'
    # in Windows Defender (false positive); 'Sentry' would match 'sentry' in any
    # English text, etc. These patterns require the actual library identity.
    $sdks = @(
        @{ Name='Segment';             Patterns=@('Segment.Analytics','Analytics.Segment','segmentio','Segment.Serialization') }
        @{ Name='Aptabase';            Patterns=@('Aptabase.','aptabase.io','InitializeAptabase') }
        @{ Name='AppCenter';           Patterns=@('Microsoft.AppCenter','AppCenter.Analytics','appcenter.ms') }
        @{ Name='ApplicationInsights'; Patterns=@('Microsoft.ApplicationInsights','TelemetryClient','InstrumentationKey') }
        @{ Name='GoogleAnalytics';     Patterns=@('google-analytics.com','www.googletagmanager.com','GoogleAnalytics.') }
        @{ Name='Mixpanel';            Patterns=@('Mixpanel.','api.mixpanel.com','mixpanel.track') }
        @{ Name='Amplitude';           Patterns=@('Amplitude.','api.amplitude.com','amplitude.com/2/httpapi') }
        @{ Name='Sentry';              Patterns=@('Sentry.','sentry.io','SentrySdk','ingest.sentry.io') }
        @{ Name='Bugsnag';             Patterns=@('Bugsnag.','bugsnag.com','notify.bugsnag') }
        @{ Name='Rollbar';             Patterns=@('Rollbar.','rollbar.com','api.rollbar.com') }
        @{ Name='Datadog';             Patterns=@('Datadog.','datadoghq.com','dd-trace') }
        @{ Name='Splunk';              Patterns=@('Splunk.','splunkcloud.com','SplunkLogger') }
        @{ Name='OpenTelemetry';       Patterns=@('OpenTelemetry.','otel.','OpenTelemetry.Trace') }
    )

    $counts = @{}
    $samples = @{}
    $matchedPattern = @{}

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($sdk in $sdks) {
            $local = 0
            $hitPat = $null
            foreach ($pat in $sdk.Patterns) {
                $c = ([regex]::Matches($text, [regex]::Escape($pat))).Count
                if ($c -gt 0) { $local += $c; if (-not $hitPat) { $hitPat = $pat } }
            }
            if ($local -gt 0) {
                if (-not $counts.ContainsKey($sdk.Name)) {
                    $counts[$sdk.Name] = 0; $samples[$sdk.Name] = $pe.FullName; $matchedPattern[$sdk.Name] = $hitPat
                }
                $counts[$sdk.Name] += $local
            }
        }
    }

    foreach ($s in ($counts.Keys | Sort-Object)) {
        New-TcpkFinding -Module 'logging' -RuleId "telemetry.$($s.ToLowerInvariant())" `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "Telemetry SDK integrated: $s ($($counts[$s]) references)" `
            -File $samples[$s] -Evidence "matched pattern '$($matchedPattern[$s])', occurrence count: $($counts[$s])" `
            -Cwe @('CWE-359') `
            -Description "Customer events likely flow to the $s SaaS processor. Verify the in-product privacy disclosures and DPA cover the actual integration scope."
    }
}
