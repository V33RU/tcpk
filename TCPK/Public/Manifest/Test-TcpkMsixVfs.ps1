function Test-TcpkMsixVfs {
<#
.SYNOPSIS
    B14. VFS redirections a packaged (Desktop Bridge) app declares over system folders.

.DESCRIPTION
    A Desktop Bridge / Centennial package can ship a VFS directory whose subfolders name
    the system locations the package overlays. At run time a kernel filter driver rewrites
    paths so that a file the application opens at, say, C:\Windows\System32\foo.dll is
    served from the package instead. It exists so converted Win32 applications keep working
    without being rewritten, and the declaration is entirely the vendor's choice.

    WHY IT IS WORTH REPORTING. The redirection moves the package's own files into paths the
    application's code treats as trusted. Code that opens a system path is normally entitled
    to assume a non-administrator could not have replaced the file there; inside a packaged
    application with a VFS mapping that assumption no longer holds, because the file
    actually comes from the install directory. So a weak ACL on the install tree, which on
    its own is an ordinary finding, becomes a way to put content at a SYSTEM path as the
    application sees it. The two halves are reported separately (see install-dir.user-writable
    and acl.programdata-user-writable) and this is the half that says the redirection exists.

    It is also the precondition Project Zero needed for CVE-2018-0877: the VFS reparse
    behaviour was abusable without the package installing a mount point of its own, which is
    the part the Store review would have caught. That bug is Microsoft's and is fixed. The
    declaration is the vendor's and is still worth knowing about, because it tells a reviewer
    which system paths this application does not actually read from disk.

    SEVERITY. Redirecting the Windows or System32 trees is graded above redirecting
    ProgramFiles or the AppData trees: a converted application overlaying its own
    ProgramFiles layout is ordinary, while one overlaying System32 has put files where the
    operating system's own binaries live, from the application's point of view.

    WHAT THIS DOES NOT CLAIM. Nothing here says the redirection is wrong, or that the app is
    exploitable. A VFS folder is a supported, documented packaging feature and plenty of
    converted applications need one. This reports that it exists, which paths it covers and
    how many files sit under each, so the reviewer can decide.

.PARAMETER Path
    MSIX file or extracted directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $expanded = Expand-TcpkMsix -Path $Path
    if (-not $expanded) { return }

    $vfsRoot = Join-Path $expanded 'VFS'
    if (-not (Test-Path -LiteralPath $vfsRoot -PathType Container)) { return }

    # The documented VFS folder names and the location each one overlays. Names not in this
    # table are reported too, as unknown rather than ignored: the set has grown over time
    # and a package naming something else is more interesting, not less.
    $known = [ordered]@{
        'SystemX86'              = @{ Target = 'C:\Windows\System32 (32-bit view)'; Tier = 'system' }
        'SystemX64'              = @{ Target = 'C:\Windows\System32';               Tier = 'system' }
        'Windows'                = @{ Target = 'C:\Windows';                        Tier = 'system' }
        'FontsFolder'            = @{ Target = 'C:\Windows\Fonts';                  Tier = 'system' }
        'SystemDrive'            = @{ Target = 'C:\';                               Tier = 'system' }
        'ProgramFilesX86'        = @{ Target = 'C:\Program Files (x86)';            Tier = 'programs' }
        'ProgramFilesX64'        = @{ Target = 'C:\Program Files';                  Tier = 'programs' }
        'ProgramFilesCommonX86'  = @{ Target = 'C:\Program Files (x86)\Common Files'; Tier = 'programs' }
        'ProgramFilesCommonX64'  = @{ Target = 'C:\Program Files\Common Files';     Tier = 'programs' }
        'Common AppData'         = @{ Target = 'C:\ProgramData';                    Tier = 'data' }
        'AppVPackageDrive'       = @{ Target = 'package drive';                     Tier = 'data' }
        'LocalAppData'           = @{ Target = '%LOCALAPPDATA%';                    Tier = 'data' }
        'AppData'                = @{ Target = '%APPDATA%';                         Tier = 'data' }
    }

    $mapped = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in @(Get-ChildItem -LiteralPath $vfsRoot -Directory -ErrorAction SilentlyContinue)) {
        $meta = $known[$d.Name]
        $files = @()
        try { $files = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -ErrorAction SilentlyContinue) } catch { }
        $mapped.Add([pscustomobject]@{
            Name   = $d.Name
            Target = if ($meta) { $meta.Target } else { '(not a documented VFS folder name)' }
            Tier   = if ($meta) { $meta.Tier }   else { 'unknown' }
            Count  = $files.Count
            # Name the executable content specifically: that is what a redirection over a
            # system path actually changes for the loader.
            Code   = @($files | Where-Object { $_.Extension -match '(?i)^\.(dll|exe|ocx|sys|cpl|ax|node)$' }).Count
        })
    }
    if (-not $mapped.Count) { return }

    $sysLike = @($mapped | Where-Object { $_.Tier -eq 'system' -or $_.Tier -eq 'unknown' })
    $sev = if ($sysLike.Count) { 'MEDIUM' } else { 'LOW' }

    $detail = ($mapped | ForEach-Object {
        "{0} -> {1} ({2} file(s), {3} executable)" -f $_.Name, $_.Target, $_.Count, $_.Code
    }) -join '; '

    $why = if ($sysLike.Count) {
        'At least one mapping covers a Windows system location, so code in this application ' +
        'that opens a System32 or Windows path is served the package copy rather than the ' +
        'file on disk.'
    } else {
        'The mappings cover program and data locations rather than the Windows system tree, ' +
        'which is the ordinary shape for a converted desktop application.'
    }

    New-TcpkFinding -Module 'manifest' -RuleId 'msix.vfs-redirection' `
        -Severity $sev -Confidence 'Confirmed' `
        -Title "Package redirects $($mapped.Count) system location(s) through VFS" `
        -File $vfsRoot `
        -Evidence $detail `
        -Cwe @('CWE-706','CWE-427') `
        -Description ('This package ships a VFS directory, so the listed locations are overlaid ' +
            'by files from the package at run time. ' + $why + ' The consequence for review is ' +
            'that a path which looks trusted in this application''s source is not necessarily ' +
            'read from where it appears: it comes from the install tree. Pair this with the ' +
            'install-directory ACL findings, because a redirection over a system path plus a ' +
            'user-writable install tree means a standard user can place content at what the ' +
            'application treats as a system location. A VFS folder is a supported packaging ' +
            'feature and its presence is not by itself a defect.') `
        -Fix ('Keep VFS mappings to the narrowest set the application actually needs, and prefer ' +
            'rewriting the application to use its own package-relative paths over overlaying ' +
            'Windows system directories. Ensure the install tree is writable only by ' +
            'administrators, since every VFS-served file is read from there.')

    # Executable content under a system-tier mapping is the part a loader consumes, so it is
    # called out separately rather than left inside the summary evidence.
    foreach ($m in ($sysLike | Where-Object { $_.Code -gt 0 })) {
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.vfs-system-code' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "VFS maps executable content over a system location: $($m.Name)" `
            -File (Join-Path $vfsRoot $m.Name) `
            -Evidence "$($m.Name) -> $($m.Target); $($m.Code) executable file(s) of $($m.Count) total" `
            -Cwe @('CWE-427','CWE-706') `
            -Description ('The package places executable files (DLL / EXE / OCX / SYS) into a VFS ' +
                'folder that overlays a Windows system location. Inside this application those ' +
                'files answer at a system path, so a module load that looks like it resolves to ' +
                'System32 resolves to the package instead. Confirm each file is one the vendor ' +
                'intends to ship rather than a copy of a system library shadowing the real one, ' +
                'and confirm the install tree cannot be written by a standard user.') `
            -Fix ('Do not ship system-library copies through VFS. Load vendor binaries from the ' +
                'package''s own directory by an explicit path instead of relying on a redirected ' +
                'system path.')
    }
}
