function Test-TcpkAssemblyBindingTrust {
<#
.SYNOPSIS
    A70. Assembly load redirection and CLR trust downgrades in shipped .config files.

.DESCRIPTION
    A .NET application's .config is not just settings: it steers the assembly loader and
    can switch off parts of the runtime's trust model. Three of the switches below turn a
    remote or plantable file into loaded, fully trusted code, and they are one XML line
    each. They sit in the same .config files TCPK already opens for connection strings and
    WCF bindings, so the file is being read anyway.

    Deliberately NOT reported: a bare <bindingRedirect>. Practically every real .NET
    application ships dozens, they are how dependency versions are unified, and flagging
    them would bury the four conditions below in noise. Only redirection that changes
    WHERE an assembly loads from, or that weakens trust, is reported.

    Rules:
      dotnet.codebase-remote            HIGH    <codeBase href> points at http:// or a UNC
                                                path. The loader fetches the assembly from
                                                there and runs it. Anyone who controls that
                                                host or share controls code execution in
                                                this application.
      dotnet.load-from-remote-sources   HIGH    <loadFromRemoteSources enabled="true"/>.
                                                .NET 4 sandboxes assemblies loaded from a
                                                remote origin by default; this switch grants
                                                them full trust instead.
      dotnet.legacy-security-policy     MEDIUM  <NetFx40_LegacySecurityPolicy enabled="true"/>
                                                re-enables the obsolete CAS policy model
                                                that .NET 4 replaced.
      dotnet.probing-path-escape        MEDIUM  <probing privatePath> escapes the
                                                application base with '..'. The loader then
                                                searches a directory outside the install
                                                tree, which is a plant target if it is
                                                user-writable.
      dotnet.publisher-policy-disabled  LOW     <publisherPolicy apply="no"/> makes the
                                                application ignore publisher policy, so a
                                                vendor security update shipped that way is
                                                not picked up.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Extension -eq '.config' -and $_.Length -lt 4194304 })
        } catch { return }
    } elseif ($item.Extension -eq '.config') {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    foreach ($f in $files) {
        $text = ''
        try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $text) { continue }

        # ---- codeBase href pointing off-box -----------------------------------
        # Matched against file CONTENT, never against a path literal, so the \P and \W
        # classes that make -match throw on a Windows path are not in play here.
        foreach ($m in [regex]::Matches($text, '(?i)<\s*codeBase\b[^>]*\bhref\s*=\s*"([^"]+)"')) {
            $href = $m.Groups[1].Value
            $lower = $href.ToLowerInvariant()
            $isRemote = ($lower.StartsWith('http://') -or $lower.StartsWith('ftp://') -or $href.StartsWith('\\'))
            if (-not $isRemote) { continue }
            $how = 'a plaintext HTTP origin'
            if ($href.StartsWith('\\')) { $how = 'a UNC share' }
            elseif ($lower.StartsWith('ftp://')) { $how = 'an FTP origin' }
            New-TcpkFinding -Module 'static' -RuleId 'dotnet.codebase-remote' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Assembly codeBase loads from $how : $($f.Name)" `
                -File $f.FullName -Evidence "codeBase href=$href" `
                -Cwe @('CWE-494', 'CWE-829') `
                -Description ('A <codeBase> element tells the CLR assembly loader to fetch this ' +
                    'dependency from the given location and execute it in the application''s process. ' +
                    'The location here is off the local machine, so whoever controls that host or share ' +
                    'controls code running inside this application. Over plaintext HTTP or FTP a network ' +
                    'attacker substitutes the assembly in transit; over UNC, anyone who can write to the ' +
                    'share does the same. The loader applies no signature requirement of its own.') `
                -Fix 'Ship the dependency inside the application directory and remove the codeBase element. If a remote load is genuinely required, fetch over HTTPS to a publisher-controlled host and verify a strong name or Authenticode signature before loading, rather than delegating the fetch to the loader.'
        }

        # ---- loadFromRemoteSources --------------------------------------------
        $lfrs = [regex]::Match($text, '(?i)<\s*loadFromRemoteSources\b[^>]*\benabled\s*=\s*"?\s*true')
        if ($lfrs.Success) {
            New-TcpkFinding -Module 'static' -RuleId 'dotnet.load-from-remote-sources' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "loadFromRemoteSources grants full trust to remote assemblies: $($f.Name)" `
                -File $f.FullName -Evidence $lfrs.Value `
                -Cwe @('CWE-829', 'CWE-250') `
                -Description ('By default .NET 4 loads an assembly that came from a remote origin (a UNC ' +
                    'share, a downloaded file carrying the zone-identifier mark) into a restricted, ' +
                    'partially trusted sandbox. This switch removes that restriction and grants such ' +
                    'assemblies full trust. Combined with any path the application loads from that a user ' +
                    'or a network attacker can influence, it converts a file-write into code execution at ' +
                    'the application''s privilege level.') `
                -Fix 'Remove the switch and load remote content as data, not as an assembly. If a plugin genuinely must load from a share, verify its strong name or Authenticode signature against an expected publisher before loading, and keep the default sandbox.'
        }

        # ---- legacy CAS policy -------------------------------------------------
        $legacy = [regex]::Match($text, '(?i)<\s*NetFx40_LegacySecurityPolicy\b[^>]*\benabled\s*=\s*"?\s*true')
        if ($legacy.Success) {
            New-TcpkFinding -Module 'static' -RuleId 'dotnet.legacy-security-policy' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Obsolete CAS security policy re-enabled: $($f.Name)" `
                -File $f.FullName -Evidence $legacy.Value `
                -Cwe @('CWE-1104', 'CWE-250') `
                -Description ('This re-enables the Code Access Security policy model that .NET 4 ' +
                    'deprecated and replaced. The legacy model is no longer maintained as a security ' +
                    'boundary, its behaviour differs from the modern transparency model the rest of the ' +
                    'framework assumes, and code that relies on it is making trust decisions with a ' +
                    'mechanism Microsoft has stated should not be used for that purpose.') `
                -Fix 'Remove the switch and port any policy the application depended on to the level-2 security transparency model. If it exists only to keep a legacy plugin working, isolate that plugin in a separate process instead of downgrading the host runtime.'
        }

        # ---- probing path escaping the app base --------------------------------
        foreach ($m in [regex]::Matches($text, '(?i)<\s*probing\b[^>]*\bprivatePath\s*=\s*"([^"]+)"')) {
            $pp = $m.Groups[1].Value
            if (-not ($pp.Contains('..'))) { continue }
            New-TcpkFinding -Module 'static' -RuleId 'dotnet.probing-path-escape' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Assembly probing path escapes the application directory: $($f.Name)" `
                -File $f.FullName -Evidence "privatePath=$pp" `
                -Cwe @('CWE-427', 'CWE-22') `
                -Description ('The assembly loader is told to search this relative path for ' +
                    'dependencies, and the path uses ".." to climb out of the application base ' +
                    'directory. The loader will therefore probe a directory outside the install tree. If ' +
                    'any directory on that resolved path is writable by a non-administrator, a file ' +
                    'planted there with the name of an expected assembly is loaded and executed in this ' +
                    'process. Pair this with a writable-directory finding to close the chain.') `
                -Fix 'Keep privatePath inside the application base (it is designed to accept only subdirectories of it; the escape is a misuse). Ship dependencies under the install directory and confirm that directory is writable only by administrators.'
        }

        # ---- publisher policy disabled -----------------------------------------
        $pol = [regex]::Match($text, '(?i)<\s*publisherPolicy\b[^>]*\bapply\s*=\s*"?\s*no')
        if ($pol.Success) {
            New-TcpkFinding -Module 'static' -RuleId 'dotnet.publisher-policy-disabled' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "Publisher policy ignored for a dependency: $($f.Name)" `
                -File $f.FullName -Evidence $pol.Value `
                -Description ('The application opts out of publisher policy for a shared assembly. ' +
                    'Publisher policy is how a component vendor ships a servicing update that redirects ' +
                    'every consumer to a fixed version; with apply="no" this application keeps binding ' +
                    'to the version it was built against and does not pick that update up. The pinned ' +
                    'version then has to be patched by hand, and a security fix shipped through policy ' +
                    'silently does not apply here.') `
                -Fix 'Prefer an explicit bindingRedirect to a known-good version over disabling publisher policy wholesale, so the pinned version is visible and can be reviewed against advisories for that component.'
        }
    }
}
