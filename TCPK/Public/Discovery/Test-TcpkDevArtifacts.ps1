function Test-TcpkDevArtifacts {
<#
.SYNOPSIS
    A36. Leftover development / build artifacts shipped in the release (TASVS-CONF-1.4,
    TASVS-CODE-2.4).

.DESCRIPTION
    A release build should not carry development leftovers - they enlarge the attack
    surface and leak information (source paths, internal structure, sometimes secrets
    or VCS history). This enumerates shipped files/dirs that should normally be absent
    from a production artifact:

      - debug symbols (*.pdb, *.map)                       -> reverse-engineering aid + path/type leak
      - source files (*.cs/.vb/.cpp/.h/.java)              -> source recoverable / IP + logic leak
      - backup / temp leftovers (*.bak/.orig/.old/.tmp/~)  -> may contain pre-fix or plaintext data
      - dev/debug config (*.Development.json, web.debug.config, *.local.*)
      - API specs (swagger/openapi/*.wadl/*.raml)          -> backend surface disclosure
      - build/project files (*.sln/.csproj/Dockerfile)     -> build internals
      - VCS / editor metadata dirs (.git, .svn, .hg, .vs, .idea)  -> history / secrets

    Findings are Confidence='Confirmed' (the artifact is present); severity reflects
    info-leak / attack-surface impact.

.PARAMETER Path
    Folder (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $cap = 80; $n = 0

    # --- file classifiers (first match wins) ---
    $fileRules = @(
        @{ id='debug-symbols'; sev='MEDIUM'; cwe=@('CWE-489','CWE-540')
           test={ param($f) $f.Extension -in '.pdb','.map' }
           title='Debug symbols shipped'; desc='Debug symbol files (.pdb/.map) are present. They expose source file paths, type/method names, and line numbers - a reverse-engineering aid - and indicate debug metadata was not stripped from the release.'; fix='Exclude .pdb/.map from the shipped artifact (publish without symbols, or strip them).' }
        @{ id='source'; sev='LOW'; cwe=@('CWE-540')
           test={ param($f) $f.Extension -in '.cs','.vb','.cpp','.cxx','.cc','.h','.hpp','.java' }
           title='Source code file shipped'; desc='A first-party source file is shipped in the release. Source discloses logic, hardcoded values, and any embedded secrets directly.'; fix='Ship only compiled artifacts; remove source from the package.' }
        @{ id='backup'; sev='LOW'; cwe=@('CWE-530')
           test={ param($f) ($f.Extension -in '.bak','.orig','.old','.tmp','.swp') -or $f.Name -like '*~' -or $f.Name -ieq 'Thumbs.db' }
           title='Backup / temp leftover shipped'; desc='A backup/temp leftover is present. These often hold a pre-fix copy or plaintext data the release was meant to remove.'; fix='Remove backup/temp files from the build output.' }
        @{ id='dev-config'; sev='LOW'; cwe=@('CWE-11','CWE-489')
           test={ param($f) $f.Name -match '(?i)(\.Development\.(json|config)$|appsettings\.Development\.json$|web\.debug\.config$|\.local\.(json|config|settings)$)' }
           title='Development/debug config shipped'; desc='A development/debug configuration file is present. It commonly enables verbose errors, debug endpoints, or points at non-production services.'; fix='Ship only the production configuration.' }
        @{ id='api-spec'; sev='LOW'; cwe=@('CWE-540')
           test={ param($f) $f.Name -match '(?i)(swagger.*\.(json|yaml|yml)$|openapi.*\.(json|yaml|yml)$|\.wadl$|\.raml$)' }
           title='API specification shipped'; desc='An API specification (swagger/openapi/wadl/raml) is shipped, disclosing the backend surface (endpoints, parameters) to anyone with the client.'; fix='Do not ship API specs with the client.' }
        @{ id='build-file'; sev='INFO'; cwe=@('CWE-540')
           test={ param($f) ($f.Extension -in '.sln','.csproj','.vbproj','.vcxproj') -or $f.Name -ieq 'Dockerfile' -or $f.Name -ieq 'docker-compose.yml' -or $f.Name -ieq '.dockerignore' }
           title='Build/project file shipped'; desc='A build/project file is present, disclosing build structure and dependencies.'; fix='Exclude build/project files from the release artifact.' }
        @{ id='editor'; sev='INFO'; cwe=@('CWE-540')
           test={ param($f) ($f.Extension -in '.suo','.user') -or $f.Name -ieq '.editorconfig' }
           title='Editor/IDE metadata shipped'; desc='IDE/editor metadata is present in the release.'; fix='Exclude IDE metadata from the build output.' }
    )

    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($n -ge $cap) { break }
        foreach ($r in $fileRules) {
            if (& $r.test $f) {
                New-TcpkFinding -Module 'static' -RuleId "devartifact.$($r.id)" `
                    -Severity $r.sev -Confidence 'Confirmed' `
                    -Title "$($r.title): $($f.Name)" `
                    -File $f.FullName -Evidence "shipped artifact ($($f.Length) bytes)" -Cwe $r.cwe `
                    -Description $r.desc -Fix $r.fix
                $n++
                break
            }
        }
    }

    # --- VCS / editor metadata directories ---
    $dirRules = @{
        '.git'='VCS metadata (.git) - full history, possibly secrets'
        '.svn'='VCS metadata (.svn)'
        '.hg'='VCS metadata (.hg)'
        '.vs'='Visual Studio cache (.vs)'
        '.idea'='JetBrains IDE metadata (.idea)'
    }
    foreach ($d in (Get-ChildItem -LiteralPath $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($n -ge $cap) { break }
        if ($dirRules.ContainsKey($d.Name.ToLowerInvariant())) {
            $sev = if ($d.Name -ieq '.git') { 'MEDIUM' } else { 'LOW' }
            New-TcpkFinding -Module 'static' -RuleId 'devartifact.vcs-dir' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Repository/IDE metadata directory shipped: $($d.Name)" `
                -File $d.FullName -Evidence $dirRules[$d.Name.ToLowerInvariant()] -Cwe @('CWE-527','CWE-540') `
                -Description 'A version-control or IDE metadata directory is shipped. A .git directory can expose the full source history and committed secrets.' `
                -Fix 'Remove VCS/IDE metadata directories from the release artifact.'
            $n++
        }
    }
}
