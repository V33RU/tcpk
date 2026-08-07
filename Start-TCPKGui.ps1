#requires -Version 5.1
<#
.SYNOPSIS
    TCPK GUI -- portable interactive pentest console.

.DESCRIPTION
    WinForms-based front end for TCPK. Lets the operator:
      - Pick a target (MSIX file or extracted install dir)
      - Auto-detect PackageName / PackageFamilyName / ProcessName
      - Pick an audit profile (Quick / Standard / Full)
      - Watch every check fire LIVE with timing and finding count
      - Watch findings populate the table as they come in, severity-coloured
      - Open the resulting HTML / JSON / Markdown reports with one click

    Drop this folder onto a USB drive; double-click TCPK.bat to launch.
    No install needed.
#>
[CmdletBinding()]
param()

# Resolve the TCPK module path. This must work whether the GUI is launched as a script
# (-File: $PSScriptRoot is set) OR from a self-built ps2exe launcher (ps2exe leaves
# $PSScriptRoot empty, so we also probe the host binary's own directory, the AppDomain
# base dir, and the working directory). Keep the whole TCPK folder together: the launcher
# must sit beside the TCPK\ module folder. TCPK ships no compiled .exe -- see
# REQUIREMENTS.md section 5 for why, and for how to build one yourself if you want it.
$tcpkBaseDirs = New-Object 'System.Collections.Generic.List[string]'
if ($PSScriptRoot) { $tcpkBaseDirs.Add($PSScriptRoot) }
try { $tcpkBaseDirs.Add([AppDomain]::CurrentDomain.BaseDirectory) } catch {}
try { $tcpkBaseDirs.Add((Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))) } catch {}
try { $tcpkBaseDirs.Add((Get-Location).Path) } catch {}

$tcpkPsd1 = $null
foreach ($base in ($tcpkBaseDirs | Where-Object { $_ } | Select-Object -Unique)) {
    foreach ($rel in @('TCPK\TCPK.psd1', 'TCPK.psd1', '..\TCPK\TCPK\TCPK.psd1')) {
        $candidate = Join-Path $base $rel
        if (Test-Path $candidate) { $tcpkPsd1 = (Resolve-Path $candidate).Path; break }
    }
    if ($tcpkPsd1) { break }
}
if (-not $tcpkPsd1) {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $searched = ($tcpkBaseDirs | Where-Object { $_ } | Select-Object -Unique) -join "`n  "
    [System.Windows.Forms.MessageBox]::Show(
        "TCPK module (TCPK\TCPK.psd1) was not found next to the launcher.`n`nKeep the whole folder together -- TCPK.bat must sit beside the TCPK\ module folder. Searched:`n  $searched",
        'TCPK GUI -- module missing', 'OK', 'Error') | Out-Null
    exit 1
}

# Load TCPK and WinForms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Import-Module $tcpkPsd1 -Force

# Real module version (from the manifest) -- shown in the audit banner. Falls back to
# reading the .psd1 directly if the module object isn't queryable for any reason.
$script:TcpkVersion = try {
    $v = (Get-Module TCPK | Select-Object -First 1).Version
    if (-not $v) { $v = (Import-PowerShellDataFile -Path $tcpkPsd1).ModuleVersion }
    "$v"
} catch { '' }

# Severity colours
$script:SevColour = @{
    'CRITICAL' = [System.Drawing.Color]::FromArgb(155, 0, 0)
    'HIGH'     = [System.Drawing.Color]::FromArgb(192, 57, 43)
    'MEDIUM'   = [System.Drawing.Color]::FromArgb(214, 137, 16)
    'LOW'      = [System.Drawing.Color]::FromArgb(17, 122, 101)
    'INFO'     = [System.Drawing.Color]::FromArgb(86, 101, 115)
}

# Per-profile cmdlet selection
$script:Profiles = @{
    'Quick'    = @('Test-TcpkPeMitigations','Test-TcpkPeImports','Test-TcpkPeExports','Test-TcpkSecrets','Test-TcpkEndpoints','Test-TcpkDeserialization','Test-TcpkCallsites','Test-TcpkTlsBypass','Test-TcpkDependencyCves','Test-TcpkMsixCapabilities','Test-TcpkMsixFrameworkDeps')
    'Standard' = $null   # null = full minus deep
    'Full'     = $null   # alias for Standard
}

# Build the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "TCPK -- Thick Client Pentest Kit   [ AUTHORIZED USE ONLY ]"
$form.Size = New-Object System.Drawing.Size(1200, 800)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(1000, 640)
$form.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
# Probe installed fonts inline so Cascadia Mono can be the default before any
# controls are created (InstalledFontCollection is also loaded later for the picker).
$script:DefaultFontName = try {
    $_ifc = New-Object System.Drawing.Text.InstalledFontCollection
    $_fns = $_ifc.Families | ForEach-Object { $_.Name }
    $_ifc.Dispose()
    if ($_fns -contains 'Cascadia Mono') { 'Cascadia Mono' }
    elseif ($_fns -contains 'Cascadia Code') { 'Cascadia Code' }
    else { 'Consolas' }
} catch { 'Consolas' }
$form.Font = New-Object System.Drawing.Font($script:DefaultFontName, 10)

# Window / taskbar icon (assets\tcpk.ico). Replace that file to rebrand.
$script:TcpkAssets = Join-Path $PSScriptRoot 'assets'
$icoPath = Join-Path $script:TcpkAssets 'tcpk.ico'
if (Test-Path $icoPath) { try { $form.Icon = New-Object System.Drawing.Icon($icoPath) } catch {} }

# --- Top panel: target + profile + AI + run ---
$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = 'Top'
$topPanel.Height = 160
$topPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.Controls.Add($topPanel)

# Accent separator delineating the control header from the tabbed work area.
$topSep = New-Object System.Windows.Forms.Panel
$topSep.Dock = 'Bottom'
$topSep.Height = 2
$topSep.BackColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
$topSep.Tag = 'keep'
$topPanel.Controls.Add($topSep)

# Brand badge, top-right of the header (assets\tcpk-badge.png; falls back to tcpk-logo.png).
# Swap the file in assets\ to use your own artwork -- it is loaded at runtime.
$badgePath = Join-Path $script:TcpkAssets 'tcpk-badge.png'
if (-not (Test-Path $badgePath)) { $badgePath = Join-Path $script:TcpkAssets 'tcpk-logo.png' }
if (Test-Path $badgePath) {
    $picLogo = New-Object System.Windows.Forms.PictureBox
    $picLogo.SizeMode = 'Zoom'
    $picLogo.Size = New-Object System.Drawing.Size(168, 148)
    $picLogo.Location = New-Object System.Drawing.Point(1024, 4)
    $picLogo.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
    $picLogo.BackColor = [System.Drawing.Color]::Transparent
    try { $picLogo.Image = [System.Drawing.Image]::FromFile($badgePath) } catch {}
    $topPanel.Controls.Add($picLogo)
    $picLogo.BringToFront()
}

$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Target (MSIX or folder):"; $lblTarget.ForeColor = [System.Drawing.Color]::White
$lblTarget.Location = New-Object System.Drawing.Point(14, 11)
$lblTarget.Size = New-Object System.Drawing.Size(200, 18)
$topPanel.Controls.Add($lblTarget)

$txtTarget = New-Object System.Windows.Forms.TextBox
$txtTarget.Location = New-Object System.Drawing.Point(238, 8)
$txtTarget.Size = New-Object System.Drawing.Size(576, 24)
$txtTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtTarget.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtTarget.ForeColor = [System.Drawing.Color]::White
$txtTarget.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($txtTarget)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Location = New-Object System.Drawing.Point(820, 8)
$btnBrowse.Size = New-Object System.Drawing.Size(90, 24)
$btnBrowse.FlatStyle = 'Flat'; $btnBrowse.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnBrowse.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$btnBrowse.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnBrowse)

$btnAutoDetect = New-Object System.Windows.Forms.Button
$btnAutoDetect.Text = "Auto-Detect"
$btnAutoDetect.Location = New-Object System.Drawing.Point(914, 8)
$btnAutoDetect.Size = New-Object System.Drawing.Size(106, 24)
$btnAutoDetect.FlatStyle = 'Flat'; $btnAutoDetect.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnAutoDetect.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$btnAutoDetect.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnAutoDetect)

# Application-identity line: filled by Auto-Detect BEFORE the audit runs, so the operator
# sees what kind of app this is (type / runtime / UI / signer) up front.
$lblIdent = New-Object System.Windows.Forms.Label
$lblIdent.Text = "App identity: click Auto-Detect to identify the target (type / runtime / UI / signer)."
$lblIdent.Location = New-Object System.Drawing.Point(14, 136)
$lblIdent.Size = New-Object System.Drawing.Size(992, 20)
$lblIdent.AutoEllipsis = $true
$lblIdent.ForeColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
$lblIdent.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblIdent.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($lblIdent)

$lblProfile = New-Object System.Windows.Forms.Label
$lblProfile.Text = "Profile:"; $lblProfile.ForeColor = [System.Drawing.Color]::White
$lblProfile.Location = New-Object System.Drawing.Point(14, 43)
$lblProfile.Size = New-Object System.Drawing.Size(70, 18)
$topPanel.Controls.Add($lblProfile)

$cmbProfile = New-Object System.Windows.Forms.ComboBox
$cmbProfile.Location = New-Object System.Drawing.Point(88, 40)
$cmbProfile.Size = New-Object System.Drawing.Size(120, 24)
$cmbProfile.DropDownStyle = 'DropDownList'
$cmbProfile.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbProfile.ForeColor = [System.Drawing.Color]::White
@('Quick','Standard','Full') | ForEach-Object { [void]$cmbProfile.Items.Add($_) }
$cmbProfile.SelectedIndex = 2
$topPanel.Controls.Add($cmbProfile)

$lblPkg = New-Object System.Windows.Forms.Label
$lblPkg.Text = "PackageName:"; $lblPkg.ForeColor = [System.Drawing.Color]::White
$lblPkg.Location = New-Object System.Drawing.Point(220, 43)
$lblPkg.Size = New-Object System.Drawing.Size(100, 18)
$topPanel.Controls.Add($lblPkg)

$txtPkg = New-Object System.Windows.Forms.TextBox
$txtPkg.Location = New-Object System.Drawing.Point(324, 40)
$txtPkg.Size = New-Object System.Drawing.Size(126, 24)
$txtPkg.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtPkg.ForeColor = [System.Drawing.Color]::White
$topPanel.Controls.Add($txtPkg)

$lblProc = New-Object System.Windows.Forms.Label
$lblProc.Text = "ProcessName:"; $lblProc.ForeColor = [System.Drawing.Color]::White
$lblProc.Location = New-Object System.Drawing.Point(460, 43)
$lblProc.Size = New-Object System.Drawing.Size(100, 18)
$topPanel.Controls.Add($lblProc)

$txtProc = New-Object System.Windows.Forms.TextBox
$txtProc.Location = New-Object System.Drawing.Point(564, 40)
$txtProc.Size = New-Object System.Drawing.Size(126, 24)
$txtProc.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtProc.ForeColor = [System.Drawing.Color]::White
$topPanel.Controls.Add($txtProc)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run Audit"
$btnRun.Location = New-Object System.Drawing.Point(820, 38)
$btnRun.Size = New-Object System.Drawing.Size(118, 28)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnRun.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnRun)

# Pause / Resume the running audit. Pause holds the audit at the next check boundary
# (a shared signal file the background job watches) so the operator can change the
# target / environment, then Resume continues. Enabled only while an audit is running.
$script:PauseFlag = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-pause-$PID.flag")
$btnPause = New-Object System.Windows.Forms.Button
$btnPause.Text = "Pause"
$btnPause.Location = New-Object System.Drawing.Point(942, 40)
$btnPause.Size = New-Object System.Drawing.Size(64, 24)
$btnPause.Enabled = $false; $btnPause.FlatStyle = 'Flat'; $btnPause.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnPause.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$btnPause.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnPause)
$btnPause.Add_Click({
    if (Test-Path -LiteralPath $script:PauseFlag) {
        Remove-Item -LiteralPath $script:PauseFlag -Force -ErrorAction SilentlyContinue
        $btnPause.Text = "Pause"
        Update-Status "Resumed -- audit continuing."
    } else {
        New-Item -ItemType File -Path $script:PauseFlag -Force | Out-Null
        $btnPause.Text = "Resume"
        Update-Status "Paused -- make your changes on the target, then click Resume."
    }
})

# Online CVE toggle -- on the main scan-options row so it is visible on every screen (not buried
# in the SBOM tab). Checked by default: live CVE via OSV (NuGet/Electron) + NVD/CPE (native libs).
# Uncheck for an offline, air-gapped run (bundled catalog only).
$chkOnlineCve = New-Object System.Windows.Forms.CheckBox
$chkOnlineCve.Text = "Online CVE"; $chkOnlineCve.ForeColor = [System.Drawing.Color]::White
$chkOnlineCve.Location = New-Object System.Drawing.Point(700, 41)
$chkOnlineCve.Size = New-Object System.Drawing.Size(112, 22)
$chkOnlineCve.Checked = $true
$topPanel.Controls.Add($chkOnlineCve)
$ttOnlineCve = New-Object System.Windows.Forms.ToolTip
$ttOnlineCve.SetToolTip($chkOnlineCve, "Live CVE lookup: OSV (NuGet/Electron) + NVD/CPE (native libs: OpenSSL/zlib/sqlite). Uncheck = offline catalog only. Sends only package/CPE name+version.")

# --- AI row (y=108) -----------------------------------------------------------
$chkAi = New-Object System.Windows.Forms.CheckBox
$chkAi.Text = "AI-verify findings"; $chkAi.ForeColor = [System.Drawing.Color]::White
$chkAi.Location = New-Object System.Drawing.Point(14, 75)
$chkAi.Size = New-Object System.Drawing.Size(148, 22)
$chkAi.Checked = $false   # unchecked by default -- let the operator opt in
$topPanel.Controls.Add($chkAi)

$lblAi = New-Object System.Windows.Forms.Label
$lblAi.Text = "Model:"; $lblAi.ForeColor = [System.Drawing.Color]::White
$lblAi.Location = New-Object System.Drawing.Point(166, 77)
$lblAi.Size = New-Object System.Drawing.Size(50, 18)
$topPanel.Controls.Add($lblAi)

$cmbAi = New-Object System.Windows.Forms.ComboBox
$cmbAi.Location = New-Object System.Drawing.Point(220, 74)
$cmbAi.Size = New-Object System.Drawing.Size(120, 24)
$cmbAi.DropDownStyle = 'DropDownList'
$cmbAi.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbAi.ForeColor = [System.Drawing.Color]::White
# Provider list. 'custom' = any other OpenAI-compatible endpoint (set its URL in llm-config.json).
@('ollama (local)','claude','openai','gemini','grok','deepseek','custom') | ForEach-Object { [void]$cmbAi.Items.Add($_) }
$cmbAi.SelectedIndex = 0
$topPanel.Controls.Add($cmbAi)

# Free-text model box: type ANY model the provider exposes -- nothing is hardcoded.
# A sensible default is pre-filled per provider; click "Test AI" to load the live
# list from your key (Get-TcpkLlmModels) into the dropdown for convenience.
$txtAiModel = New-Object System.Windows.Forms.ComboBox
$txtAiModel.Location = New-Object System.Drawing.Point(344, 74)
$txtAiModel.Size = New-Object System.Drawing.Size(148, 24)
$txtAiModel.DropDownStyle = 'DropDown'
$txtAiModel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtAiModel.ForeColor = [System.Drawing.Color]::White
$txtAiModel.Text = 'qwen2.5-coder:7b'   # default for ollama (provider[0]); overtype with anything
$topPanel.Controls.Add($txtAiModel)

$lblKey = New-Object System.Windows.Forms.Label
$lblKey.Text = "API key:"; $lblKey.ForeColor = [System.Drawing.Color]::White
$lblKey.Location = New-Object System.Drawing.Point(496, 77)
$lblKey.Size = New-Object System.Drawing.Size(68, 18)
$topPanel.Controls.Add($lblKey)

$txtAiKey = New-Object System.Windows.Forms.TextBox
$txtAiKey.Location = New-Object System.Drawing.Point(568, 74)
$txtAiKey.Size = New-Object System.Drawing.Size(164, 24)
$txtAiKey.UseSystemPasswordChar = $true
$txtAiKey.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtAiKey.ForeColor = [System.Drawing.Color]::White
$txtAiKey.Enabled = $false   # disabled for local ollama
$topPanel.Controls.Add($txtAiKey)

$btnTestAi = New-Object System.Windows.Forms.Button
$btnTestAi.Text = "Test AI"
$btnTestAi.Location = New-Object System.Drawing.Point(740, 74)
$btnTestAi.Size = New-Object System.Drawing.Size(74, 24)
$btnTestAi.FlatStyle = 'Flat'; $btnTestAi.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnTestAi.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$topPanel.Controls.Add($btnTestAi)

$lblAiStatus = New-Object System.Windows.Forms.Label
$lblAiStatus.Text = ""
$lblAiStatus.Location = New-Object System.Drawing.Point(820, 77)
$lblAiStatus.Size = New-Object System.Drawing.Size(360, 18)
$lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$topPanel.Controls.Add($lblAiStatus)

# --- Appearance row (y=146): font, size, theme ---
$installedFonts = @()
try { $installedFonts = (New-Object System.Drawing.Text.InstalledFontCollection).Families | ForEach-Object { $_.Name } } catch { }
$wishFonts = @(
    'Fira Code','FiraCode Nerd Font','Cascadia Code','Cascadia Mono','JetBrains Mono','JetBrainsMono Nerd Font',
    'Hack','Hack Nerd Font','Source Code Pro','IBM Plex Mono','Inconsolata','Anonymous Pro','Ubuntu Mono',
    'DejaVu Sans Mono','Meslo LG M','MesloLGM Nerd Font','Roboto Mono','Consolas','Lucida Console','Courier New'
)
$codingFonts = @($wishFonts | Where-Object { $installedFonts -contains $_ })
if (-not ($codingFonts -contains 'Consolas')) { $codingFonts += 'Consolas' }

$lblFont = New-Object System.Windows.Forms.Label
$lblFont.Text = "Font:"; $lblFont.ForeColor = [System.Drawing.Color]::White; $lblFont.Location = New-Object System.Drawing.Point(14, 111); $lblFont.Size = New-Object System.Drawing.Size(42, 18)
$topPanel.Controls.Add($lblFont)

$cmbFont = New-Object System.Windows.Forms.ComboBox
$cmbFont.Location = New-Object System.Drawing.Point(60, 108); $cmbFont.Size = New-Object System.Drawing.Size(160, 24)
$cmbFont.DropDownStyle = 'DropDownList'
$cmbFont.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbFont.ForeColor = [System.Drawing.Color]::White
$codingFonts | ForEach-Object { [void]$cmbFont.Items.Add($_) }
$cmbFont.SelectedItem = $(
    if ($codingFonts -contains 'Cascadia Mono')  { 'Cascadia Mono' }
    elseif ($codingFonts -contains 'Cascadia Code') { 'Cascadia Code' }
    elseif ($codingFonts -contains 'Fira Code')  { 'Fira Code' }
    else { 'Consolas' }
)
$cmbFont.Add_SelectedIndexChanged({ Apply-UiFont })
$topPanel.Controls.Add($cmbFont)

$lblSize = New-Object System.Windows.Forms.Label
$lblSize.Text = "Size:"; $lblSize.ForeColor = [System.Drawing.Color]::White; $lblSize.Location = New-Object System.Drawing.Point(224, 111); $lblSize.Size = New-Object System.Drawing.Size(42, 18)
$topPanel.Controls.Add($lblSize)

$cmbSize = New-Object System.Windows.Forms.ComboBox
$cmbSize.Location = New-Object System.Drawing.Point(270, 108); $cmbSize.Size = New-Object System.Drawing.Size(56, 24)
$cmbSize.DropDownStyle = 'DropDownList'
$cmbSize.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbSize.ForeColor = [System.Drawing.Color]::White
@(8, 9, 10, 11, 12, 14, 16) | ForEach-Object { [void]$cmbSize.Items.Add($_) }
$cmbSize.SelectedItem = 10
$cmbSize.Add_SelectedIndexChanged({ Apply-UiFont })
$topPanel.Controls.Add($cmbSize)

$btnTheme = New-Object System.Windows.Forms.Button
$btnTheme.Text = "Theme: Dark"; $btnTheme.Location = New-Object System.Drawing.Point(330, 108); $btnTheme.Size = New-Object System.Drawing.Size(120, 24)
$btnTheme.Tag = 'keep'
$btnTheme.Add_Click({
    $script:DarkTheme = -not $script:DarkTheme
    $btnTheme.Text = "Theme: $(if ($script:DarkTheme) { 'Dark' } else { 'Light' })"
    Apply-UiTheme
})
$topPanel.Controls.Add($btnTheme)

# Provider preset map: display-name -> @{ name; default; needsKey }
# NO hardcoded model lists. 'default' is just a starting suggestion you can overtype
# with ANY model the provider exposes; "Test AI" loads the live list from your key.
$script:AiPresets = @{
    'ollama (local)' = @{ name='ollama';   default='qwen2.5-coder:7b'; needsKey=$false }
    'claude'         = @{ name='claude';    default='claude-sonnet-4-5'; needsKey=$true }
    'openai'         = @{ name='openai';    default='gpt-4o';            needsKey=$true }
    'gemini'         = @{ name='gemini';    default='gemini-2.0-flash';  needsKey=$true }
    'grok'           = @{ name='grok';      default='grok-2-latest';     needsKey=$true }
    'deepseek'       = @{ name='deepseek';  default='deepseek-chat';     needsKey=$true }
    'custom'         = @{ name='custom';    default='';                  needsKey=$true }
}

# When provider changes: pre-fill a sensible default model (overtypeable) + toggle key field.
$cmbAi.Add_SelectedIndexChanged({
    $sel = $cmbAi.SelectedItem
    $p = $script:AiPresets[$sel]
    if ($p) {
        $txtAiModel.Items.Clear()   # no hardcoded list -- type any model, or click "Test AI" to load live
        $txtAiModel.Text = $p.default
        $txtAiKey.Enabled = $p.needsKey
        if (-not $p.needsKey) { $txtAiKey.Text = '' }
        $lblAiStatus.Text = if ($p.needsKey) {
            "$sel needs an API key -- type any model, or 'Test AI' to load its live list"
        } else {
            "local -- no key needed; type any model you've pulled (e.g. qwen2.5-coder:7b)"
        }
    }
})

# --- Tabbed main area: "Audit" (live log + findings) and "Recon / Target" ---
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'

# --- Dashboard tab: at-a-glance security posture (added FIRST so it is the landing tab).
# TabPageCollection.Insert() silently no-ops on this WinForms build, so the tab must be
# created + Add()ed before every other tab to land at index 0. Its controls are built a
# little further down (after the Recon tab); Update-Dashboard fills it from the findings.
$script:DashCountLbl   = @{}    # severity -> big count Label
$script:DashCardPanels = @()    # card panels (re-themed on toggle)
$tabDash = New-Object System.Windows.Forms.TabPage
$tabDash.Text = ' Dashboard '
$tabDash.BackColor = [System.Drawing.Color]::FromArgb(13, 16, 22)
[void]$tabs.TabPages.Add($tabDash)

$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = ' Audit '
$tabAudit.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
[void]$tabs.TabPages.Add($tabAudit)

$tabRecon = New-Object System.Windows.Forms.TabPage
$tabRecon.Text = ' Recon '
$tabRecon.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
[void]$tabs.TabPages.Add($tabRecon)

# Paint-data holders (read by the owner-drawn panels; set by Update-Dashboard)
$script:DashCounts   = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
$script:DashAssure   = @{ Proven = 0; Leads = 0; LikelyFp = 0 }
$script:DashCellBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

# ===== Bottom (Fill): Top findings table =====
$dashTopBox = New-Object System.Windows.Forms.Panel
$dashTopBox.Dock = 'Fill'
$dashTopBox.Padding = New-Object System.Windows.Forms.Padding(22, 2, 22, 14)
$tabDash.Controls.Add($dashTopBox)

$dashTopTitle = New-Object System.Windows.Forms.Label
$dashTopTitle.Text = 'Top findings'
$dashTopTitle.Dock = 'Top'; $dashTopTitle.Height = 24
$dashTopTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10.5, [System.Drawing.FontStyle]::Bold)

$lvDashTop = New-Object System.Windows.Forms.ListView
$lvDashTop.Dock = 'Fill'
$lvDashTop.View = 'Details'
$lvDashTop.FullRowSelect = $true
$lvDashTop.OwnerDraw = $true
$lvDashTop.HeaderStyle = 'Nonclickable'
$lvDashTop.BorderStyle = 'None'
$lvDashTop.Font = New-Object System.Drawing.Font('Segoe UI', 9)
[void]$lvDashTop.Columns.Add('SEV', 60)
[void]$lvDashTop.Columns.Add('RULE', 220)
[void]$lvDashTop.Columns.Add('FINDING', 340)
[void]$lvDashTop.Columns.Add('CONFIDENCE', 140)
[void]$lvDashTop.Columns.Add('CVSS', 60)
[void]$lvDashTop.Columns.Add('LOCATION', 200)
$lvDashTop.Add_DrawColumnHeader({
    param($s, $e)
    try {
        $bg = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(22, 28, 38) } else { [System.Drawing.Color]::FromArgb(232, 235, 240) }
        $fg = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(150, 156, 164) } else { [System.Drawing.Color]::FromArgb(90, 96, 104) }
        $b = New-Object System.Drawing.SolidBrush($bg); $e.Graphics.FillRectangle($b, $e.Bounds); $b.Dispose()
        $r = $e.Bounds; $r.X += 6; $r.Width -= 8
        $fl = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.Header.Text, $s.Font, $r, $fg, $fl)
    } catch { $e.DrawDefault = $true }
})
$lvDashTop.Add_DrawItem({ param($s, $e) })   # per-cell drawing happens in DrawSubItem
$lvDashTop.Add_DrawSubItem({
    param($s, $e)
    try {
        $g = $e.Graphics
        # selection highlight (owner-draw draws no default selection); subtle lifted band
        $selBg = if ($e.Item.Selected) {
            if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(32, 42, 56) } else { [System.Drawing.Color]::FromArgb(214, 228, 240) }
        } else { $s.BackColor }
        $bb = New-Object System.Drawing.SolidBrush($selBg); $g.FillRectangle($bb, $e.Bounds); $bb.Dispose()
        $txt = "$($e.SubItem.Text)"
        $sev = "$($e.Item.Tag)"
        $font = $s.Font
        # theme-aware colours: teal RULE + green/grey CONFIDENCE need deeper tones on white
        $ruleCol = if ($script:DarkTheme) { if ($script:Accent) { $script:Accent } else { [System.Drawing.Color]::FromArgb(45, 212, 191) } } else { [System.Drawing.Color]::FromArgb(13, 130, 118) }
        $okCol   = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(126, 217, 140) } else { [System.Drawing.Color]::FromArgb(17, 122, 101) }
        $fpCol   = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(150, 120, 120) } else { [System.Drawing.Color]::FromArgb(150, 60, 60) }
        $leadCol = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(176, 184, 194) } else { [System.Drawing.Color]::FromArgb(90, 96, 104) }
        $col  = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(225, 229, 236) } else { [System.Drawing.Color]::FromArgb(30, 36, 45) }
        switch ($e.ColumnIndex) {
            0 { if ($script:SevColour.ContainsKey($txt)) { $col = $script:SevColour[$txt] }; $font = $script:DashCellBold }
            1 { $col = $ruleCol }
            3 {
                if     ($txt -match '^Confirmed')  { $col = $okCol }
                elseif ($txt -match '^Likely-FP')  { $col = $fpCol }
                else   { $col = $leadCol }
            }
            4 { if ($script:SevColour.ContainsKey($sev)) { $col = $script:SevColour[$sev] }; $font = $script:DashCellBold }
            5 { $col = [System.Drawing.Color]::FromArgb(140, 145, 150) }
        }
        $r = $e.Bounds; $r.X += 6; $r.Width -= 8
        $fl = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
        [System.Windows.Forms.TextRenderer]::DrawText($g, $txt, $font, $r, $col, $fl)
    } catch { $e.DrawDefault = $true }
})
$dashTopBox.Controls.Add($lvDashTop)
$dashTopBox.Controls.Add($dashTopTitle)

# ===== Middle row (Top): Findings-by-severity | Assurance =====
$dashMid = New-Object System.Windows.Forms.TableLayoutPanel
$dashMid.Dock = 'Top'; $dashMid.Height = 210
$dashMid.ColumnCount = 2; $dashMid.RowCount = 1
$dashMid.Padding = New-Object System.Windows.Forms.Padding(22, 4, 22, 6)
[void]$dashMid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 56)))
[void]$dashMid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 44)))
[void]$dashMid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

# Left: Findings by severity (per-row bars)
$dashSevBox = New-Object System.Windows.Forms.Panel
$dashSevBox.Dock = 'Fill'; $dashSevBox.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$dashSevTitle = New-Object System.Windows.Forms.Label
$dashSevTitle.Text = 'Findings by severity'; $dashSevTitle.Dock = 'Top'; $dashSevTitle.Height = 24
$dashSevTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10.5, [System.Drawing.FontStyle]::Bold)
$dashSevBars = New-Object System.Windows.Forms.Panel
$dashSevBars.Dock = 'Fill'; $dashSevBars.Tag = 'keep'
$dashSevBars.Add_Paint({
    param($s, $e)
    try {
        $g = $e.Graphics; $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias; $g.Clear($s.BackColor)
        $order = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
        $names = @{ CRITICAL = 'Critical'; HIGH = 'High'; MEDIUM = 'Medium'; LOW = 'Low'; INFO = 'Info' }
        $maxc = 1; foreach ($k in $order) { if ([int]$script:DashCounts[$k] -gt $maxc) { $maxc = [int]$script:DashCounts[$k] } }
        $padX = 4; $labelW = 74; $countW = 40
        $barX = $padX + $labelW; $barMax = [Math]::Max(20, $s.ClientSize.Width - $barX - $countW - $padX)
        $rowH = [int]($s.ClientSize.Height / 5); if ($rowH -lt 20) { $rowH = 20 }
        $lblFont = New-Object System.Drawing.Font('Segoe UI', 9)
        $lblCol  = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(205, 211, 219) } else { [System.Drawing.Color]::FromArgb(55, 61, 69) }
        $numCol  = if ($script:DarkTheme) { [System.Drawing.Color]::White } else { [System.Drawing.Color]::FromArgb(26, 32, 41) }
        $lblBrush = New-Object System.Drawing.SolidBrush($lblCol)
        $numBrush = New-Object System.Drawing.SolidBrush($numCol)
        $trackCol = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(38, 44, 54) } else { [System.Drawing.Color]::FromArgb(226, 230, 236) }
        $track = New-Object System.Drawing.SolidBrush($trackCol)
        $sfL = New-Object System.Drawing.StringFormat; $sfL.LineAlignment = 'Center'
        $sfR = New-Object System.Drawing.StringFormat; $sfR.Alignment = 'Far'; $sfR.LineAlignment = 'Center'
        for ($i = 0; $i -lt 5; $i++) {
            $k = $order[$i]; $c = [int]$script:DashCounts[$k]; $y = $i * $rowH
            $g.DrawString($names[$k], $lblFont, $lblBrush, (New-Object System.Drawing.RectangleF([single]$padX, [single]$y, [single]$labelW, [single]$rowH)), $sfL)
            $barY = $y + [int]($rowH / 2) - 4
            $g.FillRectangle($track, [single]$barX, [single]$barY, [single]$barMax, 8.0)
            if ($c -gt 0) {
                $w = [single]($barMax * ($c / $maxc)); if ($w -lt 3) { $w = 3 }
                $col = if ($script:SevColour.ContainsKey($k)) { $script:SevColour[$k] } else { [System.Drawing.Color]::Gray }
                $b = New-Object System.Drawing.SolidBrush($col); $g.FillRectangle($b, [single]$barX, [single]$barY, $w, 8.0); $b.Dispose()
            }
            $g.DrawString("$c", $script:DashCellBold, $numBrush, (New-Object System.Drawing.RectangleF([single]($barX + $barMax), [single]$y, [single]$countW, [single]$rowH)), $sfR)
        }
        $lblFont.Dispose(); $lblBrush.Dispose(); $numBrush.Dispose(); $track.Dispose(); $sfL.Dispose(); $sfR.Dispose()
    } catch { }
})
$dashSevBox.Controls.Add($dashSevBars)
$dashSevBox.Controls.Add($dashSevTitle)
$dashMid.Controls.Add($dashSevBox, 0, 0)

# Right: Assurance (Proven / Leads / Likely-FP donut + legend)
$dashAssBox = New-Object System.Windows.Forms.Panel
$dashAssBox.Dock = 'Fill'; $dashAssBox.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$dashAssTitle = New-Object System.Windows.Forms.Label
$dashAssTitle.Text = 'Assurance  (proven vs leads)'; $dashAssTitle.Dock = 'Top'; $dashAssTitle.Height = 24
$dashAssTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10.5, [System.Drawing.FontStyle]::Bold)
$dashAssurance = New-Object System.Windows.Forms.Panel
$dashAssurance.Dock = 'Fill'; $dashAssurance.Tag = 'keep'
$dashAssurance.Add_Paint({
    param($s, $e)
    try {
        $g = $e.Graphics; $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias; $g.Clear($s.BackColor)
        $proven = [int]$script:DashAssure.Proven; $leads = [int]$script:DashAssure.Leads; $fp = [int]$script:DashAssure.LikelyFp
        $tot = $proven + $leads + $fp
        $accent = if ($script:Accent) { $script:Accent } else { [System.Drawing.Color]::FromArgb(45, 212, 191) }
        $greyc = [System.Drawing.Color]::FromArgb(96, 103, 113); $fpc = [System.Drawing.Color]::FromArgb(158, 124, 124)
        $cx = 62; $cy = [int]($s.ClientSize.Height / 2); $rad = 52; $inner = 30
        $ring = New-Object System.Drawing.Rectangle(($cx - $rad), ($cy - $rad), ($rad * 2), ($rad * 2))
        if ($tot -le 0) {
            $pen = New-Object System.Drawing.Pen(([System.Drawing.Color]::FromArgb(46, 52, 62)), 16); $g.DrawEllipse($pen, $ring); $pen.Dispose()
        } else {
            $buckets = @(@{ c = $proven; col = $accent }, @{ c = $leads; col = $greyc }, @{ c = $fp; col = $fpc })
            $start = -90.0
            foreach ($bk in $buckets) {
                if ($bk.c -le 0) { continue }
                $sweep = [single](360.0 * ($bk.c / $tot))
                $br = New-Object System.Drawing.SolidBrush($bk.col); $g.FillPie($br, $ring, [single]$start, $sweep); $br.Dispose()
                $start += $sweep
            }
            $hole = New-Object System.Drawing.SolidBrush($s.BackColor); $g.FillEllipse($hole, ($cx - $inner), ($cy - $inner), ($inner * 2), ($inner * 2)); $hole.Dispose()
            $tf = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
            $tbCol = if ($script:DarkTheme) { [System.Drawing.Color]::White } else { [System.Drawing.Color]::FromArgb(26, 32, 41) }
            $tb = New-Object System.Drawing.SolidBrush($tbCol)
            $sf = New-Object System.Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
            $g.DrawString("$tot", $tf, $tb, (New-Object System.Drawing.RectangleF(($cx - $inner), ($cy - $inner), ($inner * 2), ($inner * 2))), $sf)
            $tf.Dispose(); $tb.Dispose(); $sf.Dispose()
        }
        $lx = $cx + $rad + 20; $ly = $cy - 40
        $legFont = New-Object System.Drawing.Font('Segoe UI', 9)
        $fgCol = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(210, 216, 224) } else { [System.Drawing.Color]::FromArgb(40, 46, 54) }
        $fgb = New-Object System.Drawing.SolidBrush($fgCol)
        $numX = [Math]::Max($lx + 120, $s.ClientSize.Width - 34)
        $rows = @(@{ lab = 'Proven';    col = $accent; n = $proven }, @{ lab = 'Leads';     col = $greyc; n = $leads }, @{ lab = 'Likely-FP'; col = $fpc;   n = $fp })
        $i = 0
        foreach ($r in $rows) {
            $ry = $ly + $i * 27
            $sq = New-Object System.Drawing.SolidBrush($r.col); $g.FillRectangle($sq, $lx, $ry, 12, 12); $sq.Dispose()
            $g.DrawString($r.lab, $legFont, $fgb, [single]($lx + 20), [single]($ry - 2))
            $g.DrawString("$($r.n)", $script:DashCellBold, $fgb, (New-Object System.Drawing.RectangleF([single]$numX, [single]($ry - 2), 30.0, 18.0)))
            $i++
        }
        $legFont.Dispose(); $fgb.Dispose()
    } catch { }
})
$dashAssBox.Controls.Add($dashAssurance)
$dashAssBox.Controls.Add($dashAssTitle)
$dashMid.Controls.Add($dashAssBox, 1, 0)
$tabDash.Controls.Add($dashMid)

# ===== KPI card row (Top): 5 severity tiles + MAX CVSS =====
$dashCards = New-Object System.Windows.Forms.FlowLayoutPanel
$dashCards.Dock = 'Top'
$dashCards.Height = 114
$dashCards.Padding = New-Object System.Windows.Forms.Padding(18, 6, 18, 4)
$dashCards.WrapContents = $true
$dashCards.FlowDirection = 'LeftToRight'
$tabDash.Controls.Add($dashCards)

# card factory (also used for the MAX CVSS tile)
function New-DashCard([string]$name, $accentStripe) {
    $card = New-Object System.Windows.Forms.Panel
    $card.Size = New-Object System.Drawing.Size(168, 94)
    $card.Margin = New-Object System.Windows.Forms.Padding(0, 0, 14, 0)
    $card.BackColor = [System.Drawing.Color]::FromArgb(19, 24, 33)
    $card.Tag = 'keep'
    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Left'; $stripe.Width = 5
    $stripe.BackColor = if ($accentStripe) { $accentStripe } else { [System.Drawing.Color]::FromArgb(120, 120, 120) }
    $card.Controls.Add($stripe)
    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Dock = 'Bottom'; $lblName.Height = 22; $lblName.Text = $name; $lblName.TextAlign = 'MiddleLeft'
    $lblName.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblName.Padding = New-Object System.Windows.Forms.Padding(14, 0, 0, 4)
    $lblName.ForeColor = [System.Drawing.Color]::FromArgb(176, 184, 194)
    $card.Controls.Add($lblName)
    $lblCount = New-Object System.Windows.Forms.Label
    $lblCount.Dock = 'Fill'; $lblCount.Text = '-'; $lblCount.TextAlign = 'MiddleCenter'
    $lblCount.Font = New-Object System.Drawing.Font('Segoe UI', 28, [System.Drawing.FontStyle]::Bold)
    $lblCount.ForeColor = [System.Drawing.Color]::FromArgb(230, 234, 241)
    $card.Controls.Add($lblCount)
    $card | Add-Member -NotePropertyName SevStripe  -NotePropertyValue $stripe -Force
    $card | Add-Member -NotePropertyName SevNameLbl -NotePropertyValue $lblName -Force
    $card | Add-Member -NotePropertyName CountLbl   -NotePropertyValue $lblCount -Force
    return $card
}

foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
    $card = New-DashCard $sev $null
    $script:DashCountLbl[$sev] = $card.CountLbl
    $script:DashCardPanels += $card
    $dashCards.Controls.Add($card)
}
# MAX CVSS tile (accent stripe; number is the highest computed CVSS score)
$maxStripe = if ($script:Accent) { $script:Accent } else { [System.Drawing.Color]::FromArgb(45, 212, 191) }
$dashMaxCard = New-DashCard 'MAX CVSS' $maxStripe
$script:DashMaxCvssLbl = $dashMaxCard.CountLbl
$script:DashMaxCvssLbl.Font = New-Object System.Drawing.Font('Segoe UI', 26, [System.Drawing.FontStyle]::Bold)
$script:DashCardPanels += $dashMaxCard
$dashCards.Controls.Add($dashMaxCard)

# ===== Header (Top): added LAST so it docks ABOVE the cards =====
$dashHeader = New-Object System.Windows.Forms.Panel
$dashHeader.Dock = 'Top'; $dashHeader.Height = 56
$dashHeader.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 0)
$dashTitle = New-Object System.Windows.Forms.Label
$dashTitle.Text = 'Audit summary'
$dashTitle.Dock = 'Top'; $dashTitle.Height = 30
$dashTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 15, [System.Drawing.FontStyle]::Bold)
$dashTitle.ForeColor = [System.Drawing.Color]::FromArgb(233, 237, 243)
$dashSub = New-Object System.Windows.Forms.Label
$dashSub.Text = 'No audit run yet.'
$dashSub.Dock = 'Top'; $dashSub.Height = 18
$dashSub.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$dashSub.ForeColor = [System.Drawing.Color]::FromArgb(140, 145, 150)
$dashHeader.Controls.Add($dashSub)
$dashHeader.Controls.Add($dashTitle)
$tabDash.Controls.Add($dashHeader)

# Fill body must be front-most so the Top-docked rows carve their strips first.
$dashTopBox.BringToFront()

# Split (live log + findings) lives inside the Audit tab
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.SplitterDistance = 460
$split.Orientation = 'Vertical'
$tabAudit.Controls.Add($split)

# Recon view inside the Recon tab
$txtRecon = New-Object System.Windows.Forms.RichTextBox
$txtRecon.Dock = 'Fill'
$txtRecon.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtRecon.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
$txtRecon.ForeColor = [System.Drawing.Color]::White
$txtRecon.ReadOnly = $true
$txtRecon.WordWrap = $false
$txtRecon.DetectUrls = $true
$txtRecon.Text = "Run an audit -- the full target reconnaissance profile (application details, tech stack, network endpoints, listening ports, SDK inventory, attack surface) will appear here."

# Recon tab header: slim title strip + accent separator (logo removed per request;
# added AFTER the Fill control so the Top dock reserves the strip and the text fills).
$reconHeader = New-Object System.Windows.Forms.Panel
$reconHeader.Dock = 'Top'
$reconHeader.Height = 24
$reconHeader.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
$reconTitle = New-Object System.Windows.Forms.Label
$reconTitle.Text = "Target reconnaissance profile"
$reconTitle.Dock = 'Fill'
$reconTitle.Padding = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
$reconHeader.Controls.Add($reconTitle)
$reconSep = New-Object System.Windows.Forms.Label
$reconSep.Text = ''
$reconSep.Dock = 'Bottom'
$reconSep.Height = 2
$reconSep.BackColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
$reconSep.Tag = 'keep'
$reconHeader.Controls.Add($reconSep)
$tabRecon.Controls.Add($reconHeader)
$tabRecon.Controls.Add($txtRecon)

# --- Exploit tab (CVE matches + exploitable findings; gated PoC generation) ---
$tabExploit = New-Object System.Windows.Forms.TabPage
$tabExploit.Text = ' Exploits '
$tabExploit.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabExploit)

# Fill: horizontal split (item list on top, detail/output below)
$expSplit = New-Object System.Windows.Forms.SplitContainer
$expSplit.Dock = 'Fill'
$expSplit.Orientation = 'Horizontal'
$expSplit.SplitterDistance = 250
$tabExploit.Controls.Add($expSplit)

$lvExp = New-Object System.Windows.Forms.ListView
$lvExp.Dock = 'Fill'; $lvExp.View = 'Details'; $lvExp.FullRowSelect = $true; $lvExp.GridLines = $true; $lvExp.MultiSelect = $false
$lvExp.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lvExp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $lvExp.ForeColor = [System.Drawing.Color]::White
[void]$lvExp.Columns.Add('Kind', 60)
[void]$lvExp.Columns.Add('Sev', 70)
[void]$lvExp.Columns.Add('ID', 240)
[void]$lvExp.Columns.Add('Module / Area', 210)
[void]$lvExp.Columns.Add('Status', 220)
$expSplit.Panel1.Controls.Add($lvExp)

$txtExpDetail = New-Object System.Windows.Forms.RichTextBox
$txtExpDetail.Dock = 'Fill'; $txtExpDetail.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtExpDetail.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $txtExpDetail.ForeColor = [System.Drawing.Color]::White
$txtExpDetail.ReadOnly = $true
$txtExpDetail.Text = "Run an audit, then select a row to see the exploit / verification detail. Tick the authorization box to enable PoC generation."
$expSplit.Panel2.Controls.Add($txtExpDetail)

# Top banner: authorization + gate
$expBanner = New-Object System.Windows.Forms.Panel
$expBanner.Dock = 'Top'; $expBanner.Height = 58; $expBanner.BackColor = [System.Drawing.Color]::FromArgb(60, 20, 20)
$lblExpWarn = New-Object System.Windows.Forms.Label
$lblExpWarn.Text = "EXPLOIT modules generate PoC artifacts (Frida scripts, proxy DLLs, manifests) for AUTHORIZED testing only."
$lblExpWarn.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 180)
$lblExpWarn.Location = New-Object System.Drawing.Point(12, 8); $lblExpWarn.Size = New-Object System.Drawing.Size(1000, 18)
$expBanner.Controls.Add($lblExpWarn)
$chkExpEnable = New-Object System.Windows.Forms.CheckBox
$chkExpEnable.Text = "I am authorized to test this target -- enable exploit modules"
$chkExpEnable.ForeColor = [System.Drawing.Color]::White
$chkExpEnable.Location = New-Object System.Drawing.Point(12, 30); $chkExpEnable.Size = New-Object System.Drawing.Size(500, 22)
$expBanner.Controls.Add($chkExpEnable)
$tabExploit.Controls.Add($expBanner)

# --- The "Dynamic / Active tools" toolbar was moved to the Runtime / Live tab, which now
# hosts every process-based check -- the read-only ones AND the gated active tools together.
# The Exploit / CVE tab is left to CVE matches + gated PoC generation (below). ---

# Bottom: run button + status
$expBottom = New-Object System.Windows.Forms.Panel
$expBottom.Dock = 'Bottom'; $expBottom.Height = 44; $expBottom.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btnExpRun = New-Object System.Windows.Forms.Button
$btnExpRun.Text = "Generate PoC + Verify"; $btnExpRun.Dock = 'Right'; $btnExpRun.Width = 200; $btnExpRun.Enabled = $false
$btnExpRun.BackColor = [System.Drawing.Color]::FromArgb(155, 0, 0); $btnExpRun.ForeColor = [System.Drawing.Color]::White
$btnExpRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$expBottom.Controls.Add($btnExpRun)
$lblExpStatus = New-Object System.Windows.Forms.Label
$lblExpStatus.Dock = 'Fill'; $lblExpStatus.TextAlign = 'MiddleLeft'; $lblExpStatus.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$lblExpStatus.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$lblExpStatus.Text = "Exploit gate: OFF  --  tick the authorization box above to enable."
$expBottom.Controls.Add($lblExpStatus)
$tabExploit.Controls.Add($expBottom)

# --- SBOM tab (software bill of materials + embedded CVEs) ---
# NB: add the Dock=Top hint FIRST, then the Dock=Fill ListView LAST -- otherwise the
# ListView fills the whole tab and its column-header row is hidden behind the hint.
$tabSbom = New-Object System.Windows.Forms.TabPage
$tabSbom.Text = ' SBOM '
$tabSbom.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabSbom)
# header panel: hint + live filter (ONE Top panel) then the Fill ListView added last
$sbomHeader = New-Object System.Windows.Forms.Panel
$sbomHeader.Dock = 'Top'; $sbomHeader.Height = 50; $sbomHeader.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$sbomHint = New-Object System.Windows.Forms.Label
$sbomHint.AutoSize = $true; $sbomHint.Location = New-Object System.Drawing.Point(6, 6); $sbomHint.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$sbomHint.Text = "Run an audit -- every shipped component (name, version, purl, SHA-256) + any matched CVEs (from sbom.cdx.json)."
$sbomLblF = New-Object System.Windows.Forms.Label
$sbomLblF.AutoSize = $true; $sbomLblF.Location = New-Object System.Drawing.Point(6, 28); $sbomLblF.Text = "Filter:"; $sbomLblF.ForeColor = [System.Drawing.Color]::White
$txtSbomFilter = New-Object System.Windows.Forms.TextBox
$txtSbomFilter.Location = New-Object System.Drawing.Point(52, 25); $txtSbomFilter.Size = New-Object System.Drawing.Size(470, 22)
$txtSbomFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtSbomFilter.ForeColor = [System.Drawing.Color]::White
$txtSbomFilter.Add_TextChanged({ Filter-Sbom })
# Live-CVE (OSV) toggle. OFF by default = offline catalog only. Ticking it makes the NEXT
# audit ALSO query the OSV API for the shipped NuGet components (sends only package
# name + version). It lives on this tab because CVE matches surface here, and its state
# persists for the session -- one tick covers every audit you run.
$sbomHeader.Controls.AddRange(@($sbomHint, $sbomLblF, $txtSbomFilter))
$tabSbom.Controls.Add($sbomHeader)
$lvSbom = New-Object System.Windows.Forms.ListView
$lvSbom.Dock = 'Fill'; $lvSbom.View = 'Details'; $lvSbom.FullRowSelect = $true; $lvSbom.GridLines = $true
$lvSbom.HeaderStyle = 'Nonclickable'
$lvSbom.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lvSbom.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $lvSbom.ForeColor = [System.Drawing.Color]::White
[void]$lvSbom.Columns.Add('Component', 210)
[void]$lvSbom.Columns.Add('Version', 110)
[void]$lvSbom.Columns.Add('Type', 70)
[void]$lvSbom.Columns.Add('Publisher', 170)
[void]$lvSbom.Columns.Add('purl', 290)
[void]$lvSbom.Columns.Add('SHA-256', 200)
[void]$lvSbom.Columns.Add('CVEs', 170)
$tabSbom.Controls.Add($lvSbom)
$lvSbom.BringToFront()

# --- DLL exploit-mitigation matrix tab ---
$tabHard = New-Object System.Windows.Forms.TabPage
$tabHard.Text = ' Mitigations '
$tabHard.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabHard)
$hardHeader = New-Object System.Windows.Forms.Panel
$hardHeader.Dock = 'Top'; $hardHeader.Height = 50; $hardHeader.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$hardHint = New-Object System.Windows.Forms.Label
$hardHint.AutoSize = $true; $hardHint.Location = New-Object System.Drawing.Point(6, 6); $hardHint.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hardHint.Text = "Run an audit -- per-DLL mitigations (ASLR / DEP / CFG / HighEntropyVA / SafeSEH / GS stack cookie / ForceIntegrity). Red = WEAK, orange = PARTIAL, green = HARDENED."
$hardLblF = New-Object System.Windows.Forms.Label
$hardLblF.AutoSize = $true; $hardLblF.Location = New-Object System.Drawing.Point(6, 28); $hardLblF.Text = "Filter:"; $hardLblF.ForeColor = [System.Drawing.Color]::White
$txtHardFilter = New-Object System.Windows.Forms.TextBox
$txtHardFilter.Location = New-Object System.Drawing.Point(52, 25); $txtHardFilter.Size = New-Object System.Drawing.Size(470, 22)
$txtHardFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHardFilter.ForeColor = [System.Drawing.Color]::White
$txtHardFilter.Add_TextChanged({ Filter-Hardening })
$hardHeader.Controls.AddRange(@($hardHint, $hardLblF, $txtHardFilter))
$tabHard.Controls.Add($hardHeader)
$lvHard = New-Object System.Windows.Forms.ListView
$lvHard.Dock = 'Fill'; $lvHard.View = 'Details'; $lvHard.FullRowSelect = $true; $lvHard.GridLines = $true
$lvHard.HeaderStyle = 'Nonclickable'
$lvHard.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lvHard.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $lvHard.ForeColor = [System.Drawing.Color]::White
[void]$lvHard.Columns.Add('DLL', 230)
[void]$lvHard.Columns.Add('Arch', 60)
[void]$lvHard.Columns.Add('ASLR', 60)
[void]$lvHard.Columns.Add('DEP', 55)
[void]$lvHard.Columns.Add('CFG', 55)
[void]$lvHard.Columns.Add('HighEntropyVA', 100)
[void]$lvHard.Columns.Add('SafeSEH', 70)
[void]$lvHard.Columns.Add('GS', 55)
[void]$lvHard.Columns.Add('ForceIntegrity', 95)
[void]$lvHard.Columns.Add('Status', 80)
[void]$lvHard.Columns.Add('Missing', 240)
$tabHard.Controls.Add($lvHard)
$lvHard.BringToFront()

# --- DLL Signing tab (signed / not signed -- information only) ---
$tabSign = New-Object System.Windows.Forms.TabPage
$tabSign.Text = ' Signing '
$tabSign.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabSign)
$signHeader = New-Object System.Windows.Forms.Panel
$signHeader.Dock = 'Top'; $signHeader.Height = 50; $signHeader.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$signHint = New-Object System.Windows.Forms.Label
$signHint.AutoSize = $true; $signHint.Location = New-Object System.Drawing.Point(6, 6); $signHint.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$signHint.Text = "Run an audit -- per-DLL code-signing status (information only). Red = UNSIGNED / TAMPERED / UNTRUSTED, green = SIGNED / CATALOG."
$signLblF = New-Object System.Windows.Forms.Label
$signLblF.AutoSize = $true; $signLblF.Location = New-Object System.Drawing.Point(6, 28); $signLblF.Text = "Filter:"; $signLblF.ForeColor = [System.Drawing.Color]::White
$txtSignFilter = New-Object System.Windows.Forms.TextBox
$txtSignFilter.Location = New-Object System.Drawing.Point(52, 25); $txtSignFilter.Size = New-Object System.Drawing.Size(470, 22)
$txtSignFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtSignFilter.ForeColor = [System.Drawing.Color]::White
$txtSignFilter.Add_TextChanged({ Filter-Signing })
$signHeader.Controls.AddRange(@($signHint, $signLblF, $txtSignFilter))
$tabSign.Controls.Add($signHeader)
$lvSign = New-Object System.Windows.Forms.ListView
$lvSign.Dock = 'Fill'; $lvSign.View = 'Details'; $lvSign.FullRowSelect = $true; $lvSign.GridLines = $true
$lvSign.HeaderStyle = 'Nonclickable'
$lvSign.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lvSign.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $lvSign.ForeColor = [System.Drawing.Color]::White
[void]$lvSign.Columns.Add('DLL', 240)
[void]$lvSign.Columns.Add('Signed', 70)
[void]$lvSign.Columns.Add('Status', 95)
[void]$lvSign.Columns.Add('Signer', 280)
[void]$lvSign.Columns.Add('Algorithm', 110)
[void]$lvSign.Columns.Add('Valid From', 90)
[void]$lvSign.Columns.Add('Expires', 90)
[void]$lvSign.Columns.Add('Type', 90)
$tabSign.Controls.Add($lvSign)
$lvSign.BringToFront()

# --- Logs / Runtime tab (verbose timed trace + runtime analysis) ---
$tabLogs = New-Object System.Windows.Forms.TabPage
$tabLogs.Text = ' Logs '
$tabLogs.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
[void]$tabs.TabPages.Add($tabLogs)
$txtLogs = New-Object System.Windows.Forms.RichTextBox
$txtLogs.Dock = 'Fill'; $txtLogs.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLogs.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18); $txtLogs.ForeColor = [System.Drawing.Color]::White
$txtLogs.ReadOnly = $true; $txtLogs.WordWrap = $false
$txtLogs.Text = "Run an audit -- a verbose, timed runtime trace (per-check timing, success/info/error for every step) and a runtime-analysis summary appear here."
$tabLogs.Controls.Add($txtLogs)

# --- Interception + Live Exploit tabs (2.4.x active layer) ---------------------
# Two gated tabs surfacing the active/exploit cmdlets that were previously CLI-only:
#   Interception        : Invoke-TcpkIntercept (mitmproxy Proxy / Tamper, or parse a capture)
#   Live Exploit / Creds: Invoke-TcpkHookBypass (frida return override),
#                         Get-TcpkStoredCredentials (Credential Manager dump),
#                         Test-TcpkCredentialLiveness (replay a credential against a live service)
# Each tab has its OWN authorization gate + output console. The helpers take the target
# console/gate as parameters so the two tabs stay independent.
$icptWarn = [System.Drawing.Color]::FromArgb(255,180,180)

function Write-IcptLine($box, [string]$text, [System.Drawing.Color]$color) {
    $box.SelectionStart = $box.TextLength
    $box.SelectionLength = 0
    $box.SelectionColor = $color
    $box.AppendText($text)
    try { $box.ScrollToCaret() } catch {}
}
function Test-IcptGate($gate, $box) {
    if (-not $gate.Checked) {
        Write-IcptLine $box "`r`n[gate] Tick 'I am authorized' above to enable the active tools.`r`n" $icptWarn
        return $false
    }
    try { Enable-TcpkExploit -Acknowledge | Out-Null } catch {}
    return $true
}
# Run one active/parse cmdlet, stream its findings into the given console (severity-coloured).
# Synchronous with a wait cursor -- the active modes launch the target, so the window
# pauses for the capture/instrument duration, matching the Exploit tab's dynamic tools.
# Shared runner for every tool tab (Runtime, Intercept, Decompiler, ...).
#
# Three things happen around the call, all of which used to be missing:
#
# 1. OPTIONAL CLEAR. Repeated clicks appended forever, so a pane could hold four identical
#    GuiInspector blocks and three ListeningPorts blocks with nothing separating them, and
#    there was no way to tell the current result from the previous one. Callers that set
#    $script:IcptClearNext get a fresh pane.
# 2. A TIMESTAMPED HEADER. Even when deliberately accumulating (comparing two checks), the
#    run separator now carries wall-clock time, so old and new output are distinguishable.
# 3. CPU / RAM FOR THIS ACTION. These checks run SYNCHRONOUSLY on the UI thread, so the
#    toolbar gauge cannot tick while one is in flight -- the message pump is blocked. What
#    IS measurable, and is more useful, is the cost of the check itself: CPU seconds burned
#    and peak working set, reported as a footer line. The gauge shows idle/worker state; this
#    shows what the action actually cost.
function Invoke-IcptTool($box, [string]$title, [scriptblock]$call) {
    if ($script:IcptClearNext) { try { $box.Clear() } catch { }; $script:IcptClearNext = $false }

    Write-IcptLine $box ("`r`n== {0} ==  [{1}]`r`n" -f $title, (Get-Date -Format 'HH:mm:ss')) ([System.Drawing.Color]::FromArgb(102,217,239))
    Update-Status "$title ... (the window may pause while this runs)"
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()

    # Baseline this process before the call. Process.CPU is total processor seconds across
    # all cores, so the delta over wall time is the average load this action produced.
    $me = $null; $cpu0 = 0.0; $ws0 = 0
    try { $me = [System.Diagnostics.Process]::GetCurrentProcess(); $cpu0 = $me.TotalProcessorTime.TotalSeconds; $ws0 = $me.WorkingSet64 } catch { }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $res = & $call
        $n = 0
        foreach ($f in @($res)) {
            if (-not $f) { continue }
            $n++
            $c = $script:SevColour[[string]$f.Severity]; if (-not $c) { $c = [System.Drawing.Color]::White }
            Write-IcptLine $box ("[{0}] {1}`r`n" -f $f.Severity, $f.Title) $c
            Write-IcptLine $box ("      Confidence: {0}`r`n" -f $f.Confidence) ([System.Drawing.Color]::FromArgb(95,100,110))
            if ($f.Cwe -and $f.Cwe.Count) { Write-IcptLine $box ("      CWE:        {0}`r`n" -f ($f.Cwe -join ', ')) ([System.Drawing.Color]::FromArgb(210,190,55)) }
            if ($f.Evidence)  { Write-IcptLine $box ("      Evidence:   {0}`r`n" -f $f.Evidence) ([System.Drawing.Color]::FromArgb(155,160,165)) }
            if ($f.Fix)       { Write-IcptLine $box ("      Fix:        {0}`r`n" -f $f.Fix)      ([System.Drawing.Color]::FromArgb(80,190,85)) }
            Write-IcptLine $box "`r`n" ([System.Drawing.Color]::White)
        }
        if ($n -eq 0) { Write-IcptLine $box "(no findings returned)`r`n" ([System.Drawing.Color]::FromArgb(150,150,150)) }
        else {
            Write-IcptLine $box ("-> {0} finding(s)`r`n" -f $n) ([System.Drawing.Color]::FromArgb(166,226,46))
            # Merge into $script:LastFindings so the Dashboard reflects dynamic findings too.
            $toMerge = @($res | Where-Object { $_ })
            if ($toMerge.Count) {
                if ($script:LastFindings) {
                    $merged = [System.Collections.Generic.List[object]]::new()
                    foreach ($x in $script:LastFindings) { $merged.Add($x) }
                    foreach ($x in $toMerge)             { $merged.Add($x) }
                    $script:LastFindings = $merged
                } else {
                    $script:LastFindings = [System.Collections.Generic.List[object]]::new()
                    foreach ($x in $toMerge) { $script:LastFindings.Add($x) }
                }
                try { Update-Dashboard } catch { }
            }
        }
    } catch {
        Write-IcptLine $box ("ERROR: {0}`r`n" -f $_.Exception.Message) ([System.Drawing.Color]::FromArgb(249,38,114))
    } finally {
        $sw.Stop()
        try {
            if ($me) {
                $me.Refresh()
                $secs = $sw.Elapsed.TotalSeconds
                $cpuUsed = [Math]::Max(0.0, $me.TotalProcessorTime.TotalSeconds - $cpu0)
                $nc  = [Math]::Max(1, [Environment]::ProcessorCount)
                $ce  = if ($secs -gt 0.05) { $cpuUsed / $secs } else { 0.0 }
                $pct = [int]([Math]::Min(100, ($ce / $nc) * 100))
                $wsMb = Get-TcpkPrivateWsMb -ProcId $me.Id -FallbackBytes $me.WorkingSet64
                $dMb  = [int](($me.WorkingSet64 - $ws0) / 1MB)   # delta stays on the same counter it was baselined with
                $sign = if ($dMb -ge 0) { '+' } else { '' }
                Write-IcptLine $box ("   [{0:N1}s  cpu {1}s = {2:N1} core(s), {3}% of machine  ram {4} MB ({5}{6} MB)]`r`n" -f `
                    $secs, [Math]::Round($cpuUsed, 1), $ce, $pct, $wsMb, $sign, $dMb) ([System.Drawing.Color]::FromArgb(120,130,140))
                Update-ScanResources -CpuPct $pct -RamMb $wsMb -Cores $ce -Src 'gui'
            }
        } catch { }
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        Update-Status "Ready."
    }
}

# ================= TAB A: Interception (traffic capture) =================
$tabIcptA = New-Object System.Windows.Forms.TabPage
$tabIcptA.Text = ' Intercept '
$tabIcptA.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabIcptA)

# Authorization banner
$bannerA = New-Object System.Windows.Forms.Panel
$bannerA.Dock = 'Top'; $bannerA.Height = 50; $bannerA.BackColor = [System.Drawing.Color]::FromArgb(60,20,20)
$lblWarnA = New-Object System.Windows.Forms.Label
$lblWarnA.Text = "ACTIVE traffic interception. This LAUNCHES the target through mitmproxy and observes / rewrites its traffic. LAB / AUTHORIZED targets only."
$lblWarnA.ForeColor = $icptWarn
$lblWarnA.Location = New-Object System.Drawing.Point(12,6); $lblWarnA.Size = New-Object System.Drawing.Size(1140,18)
$bannerA.Controls.Add($lblWarnA)
$chkGateA = New-Object System.Windows.Forms.CheckBox
$chkGateA.Text = "I am authorized to test this target -- enable active tools"
$chkGateA.ForeColor = [System.Drawing.Color]::White
$chkGateA.Location = New-Object System.Drawing.Point(12,26); $chkGateA.Size = New-Object System.Drawing.Size(470,22)
$bannerA.Controls.Add($chkGateA)
$tabIcptA.Controls.Add($bannerA)

# Controls panel
$ctlA = New-Object System.Windows.Forms.Panel
$ctlA.Dock = 'Top'; $ctlA.Height = 120; $ctlA.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)

# App exe row
# Right-edge controls (Browse button + exe text box) are positioned by a SizeChanged
# handler rather than WinForms Anchor.  Anchor snapshots the "distance from right" at
# control-add time, but at that point the parent panel hasn't been given its real width
# yet (form not shown), so the snapshot is wrong and buttons end up off-screen.
$lblExeA = New-Object System.Windows.Forms.Label
$lblExeA.Text = "App exe (.exe to launch through the proxy):"; $lblExeA.ForeColor = [System.Drawing.Color]::White
$lblExeA.Location = New-Object System.Drawing.Point(12,8); $lblExeA.Size = New-Object System.Drawing.Size(336,18)
$ctlA.Controls.Add($lblExeA)
$txtExeA = New-Object System.Windows.Forms.TextBox
$txtExeA.Location = New-Object System.Drawing.Point(352,5); $txtExeA.Size = New-Object System.Drawing.Size(500,24); $txtExeA.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtExeA.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtExeA.ForeColor = [System.Drawing.Color]::White
$txtExeA.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$ctlA.Controls.Add($txtExeA)
$btnBrowseA = New-Object System.Windows.Forms.Button
$btnBrowseA.Text = "Browse..."; $btnBrowseA.Location = New-Object System.Drawing.Point(840,5); $btnBrowseA.Size = New-Object System.Drawing.Size(88,24)
$btnBrowseA.FlatStyle = 'Flat'; $btnBrowseA.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnBrowseA.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$btnBrowseA.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$ctlA.Controls.Add($btnBrowseA)
# Single SizeChanged on $ctlA handles everything: Browse button, exe text box,
# group box width, tamper bar, and both action buttons.
# $ctlA is Dock=Top so its SizeChanged fires reliably when the form resizes.
# $gbTraffic has no Right-anchor; its width is set explicitly here instead, which
# avoids the WinForms bug where Anchor snapshots the wrong parent width at startup.
$ctlA.Add_SizeChanged({
    $cw = $ctlA.ClientSize.Width
    if ($cw -lt 200) { return }

    # App exe row
    $browsW = 88; $rm = 10
    $bx = $cw - $browsW - $rm
    $btnBrowseA.Location = New-Object System.Drawing.Point($bx, 5)
    $tw = $bx - 8 - 352
    if ($tw -gt 60) { $txtExeA.Size = New-Object System.Drawing.Size($tw, 24) }

    # Group box spans the full panel width
    $gbw = $cw - 20
    $gbTraffic.Size = New-Object System.Drawing.Size($gbw, 80)

    # Tamper bar and stacked buttons inside the group box
    $btnW = 168; $btnRm = 12
    $bbx  = $gbw - $btnW - $btnRm
    $btnCap.Location  = New-Object System.Drawing.Point($bbx, 16)
    $btnLoad.Location = New-Object System.Drawing.Point($bbx, 48)
    $ttw = $bbx - 8 - 386
    if ($ttw -gt 60) { $txtTamper.Size = New-Object System.Drawing.Size($ttw, 24) }
})
$btnBrowseA.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtExeA.Text = $dlg.FileName }
})

# Traffic interception group -- single compact row:
#   Mode | Duration | Tamper bar (stretches) | [Launch + capture]
#                                             | [Load capture...  ]  <- stacked below
# Same reason as above: use SizeChanged instead of Anchor for right-edge items.
$gbTraffic = New-Object System.Windows.Forms.GroupBox
$gbTraffic.Text = "Traffic interception (mitmproxy)"; $gbTraffic.ForeColor = [System.Drawing.Color]::White
$gbTraffic.Location = New-Object System.Drawing.Point(10,36)
$gbTraffic.Size = New-Object System.Drawing.Size(600,80)
$gbTraffic.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$ctlA.Controls.Add($gbTraffic)

$lblMode = New-Object System.Windows.Forms.Label; $lblMode.Text = "Mode:"; $lblMode.ForeColor = [System.Drawing.Color]::White; $lblMode.Location = New-Object System.Drawing.Point(10,25); $lblMode.Size = New-Object System.Drawing.Size(44,18); $gbTraffic.Controls.Add($lblMode)
$cmbMode = New-Object System.Windows.Forms.ComboBox; $cmbMode.Location = New-Object System.Drawing.Point(56,22); $cmbMode.Size = New-Object System.Drawing.Size(90,24); $cmbMode.DropDownStyle = 'DropDownList'
$cmbMode.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $cmbMode.ForeColor = [System.Drawing.Color]::White
@('Proxy','Tamper') | ForEach-Object { [void]$cmbMode.Items.Add($_) }; $cmbMode.SelectedIndex = 0; $gbTraffic.Controls.Add($cmbMode)

$lblDur = New-Object System.Windows.Forms.Label; $lblDur.Text = "Duration(s):"; $lblDur.ForeColor = [System.Drawing.Color]::White; $lblDur.Location = New-Object System.Drawing.Point(154,25); $lblDur.Size = New-Object System.Drawing.Size(100,18); $gbTraffic.Controls.Add($lblDur)
$numDur = New-Object System.Windows.Forms.NumericUpDown; $numDur.Location = New-Object System.Drawing.Point(258,22); $numDur.Size = New-Object System.Drawing.Size(56,24); $numDur.Minimum = 3; $numDur.Maximum = 600; $numDur.Value = 20
$numDur.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $numDur.ForeColor = [System.Drawing.Color]::White; $gbTraffic.Controls.Add($numDur)

$lblTam = New-Object System.Windows.Forms.Label; $lblTam.Text = "Tamper:"; $lblTam.ForeColor = [System.Drawing.Color]::White; $lblTam.Location = New-Object System.Drawing.Point(318,25); $lblTam.Size = New-Object System.Drawing.Size(64,18); $gbTraffic.Controls.Add($lblTam)
$txtTamper = New-Object System.Windows.Forms.TextBox; $txtTamper.Location = New-Object System.Drawing.Point(386,22); $txtTamper.Size = New-Object System.Drawing.Size(200,24)
$txtTamper.Multiline = $false; $txtTamper.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtTamper.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtTamper.ForeColor = [System.Drawing.Color]::White
$txtTamper.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$gbTraffic.Controls.Add($txtTamper)

$tipTam = New-Object System.Windows.Forms.ToolTip
$tipTam.SetToolTip($txtTamper, "Tamper rules: find=>replace, one per line. Active in Tamper mode only.")
$tipTam.SetToolTip($lblTam,    "Tamper rules: find=>replace, one per line. Active in Tamper mode only.")

$btnCap = New-Object System.Windows.Forms.Button; $btnCap.Text = "Launch + capture"
$btnCap.Size = New-Object System.Drawing.Size(168,28); $btnCap.Location = New-Object System.Drawing.Point(430,16)
$btnCap.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$btnCap.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnCap.ForeColor = [System.Drawing.Color]::White; $btnCap.FlatStyle = 'Flat'; $gbTraffic.Controls.Add($btnCap)

$btnLoad = New-Object System.Windows.Forms.Button; $btnLoad.Text = "Load capture file..."
$btnLoad.Size = New-Object System.Drawing.Size(168,28); $btnLoad.Location = New-Object System.Drawing.Point(430,48)
$btnLoad.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$btnLoad.FlatStyle = 'Flat'; $btnLoad.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnLoad.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190); $gbTraffic.Controls.Add($btnLoad)

$btnCap.Add_Click({
    if (-not (Test-IcptGate $chkGateA $txtOutA)) { return }
    $exe = $txtExeA.Text.Trim()
    if (-not $exe) { Write-IcptLine $txtOutA "`r`n[!] Set the app exe path first.`r`n" $icptWarn; return }
    $mode = [string]$cmbMode.SelectedItem
    $dur = [int]$numDur.Value
    $rules = @($txtTamper.Lines | Where-Object { $_.Trim() })
    Invoke-IcptTool $txtOutA "Interception ($mode, ${dur}s): $exe" {
        $p = @{ Target = $exe; Mode = $mode; ConfirmDynamic = $true; DurationSec = $dur }
        if ($mode -eq 'Tamper' -and $rules.Count) { $p.TamperRules = $rules }
        Invoke-TcpkIntercept @p
    }
})
$btnLoad.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Capture files (*.jsonl;*.json;*.txt)|*.jsonl;*.json;*.txt|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') {
        $file = $dlg.FileName
        Invoke-IcptTool $txtOutA "Parse capture: $file" { Invoke-TcpkIntercept -FlowFile $file }
    }
})
$tabIcptA.Controls.Add($ctlA)

$txtOutA = New-Object System.Windows.Forms.RichTextBox
$txtOutA.Dock = 'Fill'; $txtOutA.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtOutA.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtOutA.ForeColor = [System.Drawing.Color]::White
$txtOutA.ReadOnly = $true; $txtOutA.WordWrap = $false
$txtOutA.Text = "Traffic interception console.`r`n`r`nSet the app exe, tick the authorization box, then:`r`n  Launch + capture -- run the target through mitmproxy (Proxy observes; Tamper rewrites in flight).`r`n  Load capture file -- parse an existing mitmproxy JSONL capture into findings.`r`n`r`nmitmdump must be on PATH or in tools\. For MSIX / packaged apps that ignore the proxy, drive the capture with Burp + Proxifier instead. Findings stream here, severity-coloured."
$tabIcptA.Controls.Add($txtOutA)
$txtOutA.BringToFront()

# ================= TAB: Traffic (packet-capture analysis) =================
# Read-only: dissects a .pcap/.pcapng you already captured with Wireshark, via tshark. No gate,
# no launch, no admin -- it only reads a capture file (Invoke-TcpkPcapReview). Complements the
# Intercept tab (HTTP through a proxy) by seeing everything on the wire, non-HTTP included.
$tabPcap = New-Object System.Windows.Forms.TabPage
$tabPcap.Text = ' Pcap '
$tabPcap.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabPcap)

$ctlP = New-Object System.Windows.Forms.Panel
$ctlP.Dock = 'Top'; $ctlP.Height = 126; $ctlP.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$lblPcap = New-Object System.Windows.Forms.Label
$lblPcap.Text = "Packet capture (.pcap / .pcapng) -- analyse it via your installed Wireshark (tshark). Read-only, needs no admin."
$lblPcap.ForeColor = [System.Drawing.Color]::White
$lblPcap.Location = New-Object System.Drawing.Point(12,6); $lblPcap.Size = New-Object System.Drawing.Size(1140,18)
$ctlP.Controls.Add($lblPcap)
$lblPcapF = New-Object System.Windows.Forms.Label
$lblPcapF.Text = "Capture file:"; $lblPcapF.ForeColor = [System.Drawing.Color]::White
$lblPcapF.Location = New-Object System.Drawing.Point(12,34); $lblPcapF.Size = New-Object System.Drawing.Size(110,18)
$ctlP.Controls.Add($lblPcapF)
$txtPcap = New-Object System.Windows.Forms.TextBox
$txtPcap.Location = New-Object System.Drawing.Point(126,31); $txtPcap.Size = New-Object System.Drawing.Size(370,24); $txtPcap.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtPcap.BackColor = [System.Drawing.Color]::FromArgb(36,36,40); $txtPcap.ForeColor = [System.Drawing.Color]::FromArgb(110,115,120)
$txtPcap.ReadOnly = $true; $txtPcap.Text = 'Drop a .pcap / .pcapng here -- or click Browse'
$txtPcap.AllowDrop = $true
$txtPcap.Add_DragEnter({
    if ($args[1].Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $args[1].Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else { $args[1].Effect = [System.Windows.Forms.DragDropEffects]::None }
})
$txtPcap.Add_DragDrop({
    $files = @($args[1].Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
    if ($files.Count -gt 0) { $txtPcap.Text = $files[0]; $txtPcap.ForeColor = [System.Drawing.Color]::White }
})
$txtPcap.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
$ctlP.Controls.Add($txtPcap)
$btnPcapBrowse = New-Object System.Windows.Forms.Button
$btnPcapBrowse.Text = "Browse"; $btnPcapBrowse.Location = New-Object System.Drawing.Point(502,31); $btnPcapBrowse.Size = New-Object System.Drawing.Size(68,24)
$btnPcapBrowse.FlatStyle = 'Flat'; $btnPcapBrowse.BackColor = [System.Drawing.Color]::FromArgb(28,78,130); $btnPcapBrowse.ForeColor = [System.Drawing.Color]::White
$btnPcapBrowse.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
$ctlP.Controls.Add($btnPcapBrowse)
$btnPcapBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = 'Select packet capture'
    $dlg.Filter = "Captures (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtPcap.Text = $dlg.FileName; $txtPcap.ForeColor = [System.Drawing.Color]::White }
})
$btnPcapGo = New-Object System.Windows.Forms.Button
$btnPcapGo.Text = "Analyse capture"; $btnPcapGo.Location = New-Object System.Drawing.Point(576,31); $btnPcapGo.Size = New-Object System.Drawing.Size(140,24)
$btnPcapGo.BackColor = [System.Drawing.Color]::FromArgb(0,90,120); $btnPcapGo.ForeColor = [System.Drawing.Color]::White; $btnPcapGo.FlatStyle = 'Flat'
$ctlP.Controls.Add($btnPcapGo)
$btnPcapGo.Add_Click({
    $file = $txtPcap.Text.Trim()
    if (-not $file -or -not (Test-Path -LiteralPath $file)) {
        Write-IcptLine $txtOutP "`r`n[!] Pick a valid .pcap / .pcapng file first.`r`n" $icptWarn; return
    }
    $p = @{ Path = $file }
    if ($txtKeylog.Text.Trim()) { $p.KeylogFile = $txtKeylog.Text.Trim() }
    if ($txtRsa.Text.Trim())    { $p.RsaKeyFile = $txtRsa.Text.Trim() }
    $script:_tshark = try { (Get-Command tshark -ErrorAction Stop).Source } catch { $null }

    # Clear output, switch to Findings sub-tab, then run main security analysis
    $txtOutP.Clear()
    $subPcapTabs.SelectedIndex = 0
    $script:_pcapRunParams    = $p
    $script:_lastPcapFindings = @()
    Invoke-IcptTool $txtOutP "Analyse pcap: $(Split-Path $file -Leaf)" {
        $__pcapR = @(Invoke-TcpkPcapReview @script:_pcapRunParams)
        $script:_lastPcapFindings = $__pcapR
        $__pcapR
    }

    # Populate Conversations tab (also drives Network Graph)
    $lvConv.Items.Clear()
    $convs = @()
    $gNodes = @()
    try {
        $convParams = @{ Path=$file }
        if ($txtKeylog.Text.Trim()) { $convParams.KeylogFile = $txtKeylog.Text.Trim() }
        if ($txtRsa.Text.Trim())    { $convParams.RsaKeyFile = $txtRsa.Text.Trim() }
        $convs = @(Get-TcpkPcapConversations @convParams -ErrorAction Stop)
        $script:_allConvs = $convs
        $script:_convReady = $false
        $cmbConvProtoF.Items.Clear(); [void]$cmbConvProtoF.Items.Add('All')
        @($convs | ForEach-Object { "$($_.Protocol)" } | Where-Object { $_ } | Sort-Object -Unique) | ForEach-Object { [void]$cmbConvProtoF.Items.Add($_) }
        $cmbConvProtoF.SelectedIndex = 0; $txtConvIpF.Text = ''; $txtConvPortF.Text = ''
        $script:_convReady = $true; & $script:_applyConvFilter
        # Build network graph data (circular layout, up to 200 conversations)
        $script:graphConvs = @($convs | Where-Object { $_.SrcIP -and $_.DstIP } | Select-Object -First 200)
        $gNodes = @($script:graphConvs | ForEach-Object { $_.SrcIP, $_.DstIP } | Where-Object { $_ } | Sort-Object -Unique)
        $script:graphPositions = @{}
        if ($gNodes.Count -gt 0) {
            $gn = $gNodes.Count
            $gcx = if ($pbGraph.Width  -gt 20) { $pbGraph.Width  / 2.0 } else { 500.0 }
            $gcy = if ($pbGraph.Height -gt 20) { $pbGraph.Height / 2.0 } else { 350.0 }
            $grad = [Math]::Min($gcx, $gcy) * 0.78
            for ($gi = 0; $gi -lt $gn; $gi++) {
                $ga = 2 * [Math]::PI * $gi / $gn - [Math]::PI / 2
                $script:graphPositions[$gNodes[$gi]] = @{ X = $gcx + $grad * [Math]::Cos($ga); Y = $gcy + $grad * [Math]::Sin($ga) }
            }
        }
        $pbGraph.Invalidate()
    } catch {
        Write-IcptLine $txtOutP ("   [!] Conversations error: {0}`r`n" -f $_.Exception.Message) ([System.Drawing.Color]::FromArgb(249,38,114))
        [void]$lvConv.Items.Add((New-Object System.Windows.Forms.ListViewItem("[!] Error: $($_.Exception.Message)")))
    }
    Write-IcptLine $txtOutP ("   Conversations: {0} flows | Network Graph: {1} node(s) -- see tabs`r`n" -f $convs.Count, $gNodes.Count) ([System.Drawing.Color]::FromArgb(100,110,120))
    if ($convs.Count -eq 0) {
        $tsharkBin = try { (Get-Command tshark -ErrorAction Stop).Source } catch { $null }
        if ($tsharkBin) {
            $diagRows = @(& $tsharkBin -r $file -n -T fields '-E' "separator=`t" -e ip.src -e ip.dst -c 3 2>$null)
            if ($diagRows.Count -gt 0) {
                Write-IcptLine $txtOutP ("   [DIAG] tshark ip.src sample: {0}`r`n" -f "$($diagRows[0])") ([System.Drawing.Color]::FromArgb(140,140,140))
            } else {
                Write-IcptLine $txtOutP "   [DIAG] tshark returned no ip.src/ip.dst rows -- capture may be non-IP (ARP-only, BT, etc.)`r`n" ([System.Drawing.Color]::FromArgb(255,180,60))
            }
        } else {
            Write-IcptLine $txtOutP "   [DIAG] tshark not found in PATH -- install Wireshark and ensure tshark.exe is on PATH`r`n" ([System.Drawing.Color]::FromArgb(255,180,60))
        }
    }
    [System.Windows.Forms.Application]::DoEvents()

    # Populate TLS Handshakes tree
    $tvTls.Nodes.Clear()
    $tlsCount = 0
    try {
        $tlsParams = @{ Path=$file }
        if ($txtKeylog.Text.Trim()) { $tlsParams.KeylogFile = $txtKeylog.Text.Trim() }
        if ($txtRsa.Text.Trim())    { $tlsParams.RsaKeyFile = $txtRsa.Text.Trim() }
        $tlsSessions = Get-TcpkPcapTlsTree @tlsParams -ErrorAction Stop
        if ($tlsSessions -and $tlsSessions.Keys.Count) {
            $tlsCount = $tlsSessions.Keys.Count
            foreach ($sKey in $tlsSessions.Keys) {
                $hs = $tlsSessions[$sKey]
                $srvNode = New-Object System.Windows.Forms.TreeNode("Server  $sKey")
                $srvNode.ForeColor = [System.Drawing.Color]::FromArgb(100,185,255)

                foreach ($ch in $hs.ClientHellos) {
                    $chNode = New-Object System.Windows.Forms.TreeNode("ClientHello  [frame $($ch.Frame)  +$($ch.TimeRel)s]  from $($ch.Client)")
                    $chNode.ForeColor = [System.Drawing.Color]::FromArgb(110,200,110)

                    # ── Record / handshake layer metadata ────────────────────────────────
                    if ($ch.RecordVersion)    { [void]$chNode.Nodes.Add("Record layer version:   $($ch.RecordVersion)") }
                    if ($ch.HandshakeVersion) { [void]$chNode.Nodes.Add("Handshake version:      $($ch.HandshakeVersion)") }
                    if ($ch.Random)           { [void]$chNode.Nodes.Add("Random:                 $($ch.Random)") }
                    if ($ch.SessionID) { [void]$chNode.Nodes.Add("Session ID: $($ch.SessionID)") }
                    if ($ch.SNI)       { [void]$chNode.Nodes.Add("SNI (server name): $($ch.SNI)") }

                    # ── Cipher suites offered ────────────────────────────────────────────
                    if ($ch.OfferedCiphers.Count -gt 0) {
                        $realCnt   = @($ch.OfferedCiphers | Where-Object { -not $_.IsGrease }).Count
                        $greaseCnt = $ch.OfferedCiphers.Count - $realCnt
                        $cnLabel   = "Cipher suites offered ($realCnt"
                        if ($greaseCnt -gt 0) { $cnLabel += " + $greaseCnt GREASE" }
                        $cnLabel  += ')'
                        $cn = New-Object System.Windows.Forms.TreeNode($cnLabel)
                        $cn.ForeColor = [System.Drawing.Color]::FromArgb(200,200,200)
                        foreach ($c in $ch.OfferedCiphers) {
                            $label = $c.Display
                            if ($c.IsGrease) {
                                $label += '  [GREASE - RFC 8701 probe]'
                                $ci = New-Object System.Windows.Forms.TreeNode($label)
                                $ci.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)
                            } elseif ($c.Weak) {
                                $label += "  [WEAK: $($c.Weak.Reason)]"
                                $ci = New-Object System.Windows.Forms.TreeNode($label)
                                $ci.ForeColor = [System.Drawing.Color]::FromArgb(255,90,90)
                            } else {
                                $ci = New-Object System.Windows.Forms.TreeNode($label)
                                $ci.ForeColor = [System.Drawing.Color]::FromArgb(180,210,180)
                            }
                            [void]$cn.Nodes.Add($ci)
                        }
                        $cn.Expand(); [void]$chNode.Nodes.Add($cn)
                    }

                    # ── Compression methods ──────────────────────────────────────────────
                    if ($ch.CompressionMethods.Count -gt 0) {
                        $cmn = New-Object System.Windows.Forms.TreeNode("Compression methods ($($ch.CompressionMethods.Count))")
                        foreach ($cm in $ch.CompressionMethods) {
                            $cmi = New-Object System.Windows.Forms.TreeNode("$cm")
                            $cmi.ForeColor = if ("$cm" -match 'DEFLATE|CRIME') {
                                [System.Drawing.Color]::FromArgb(255,140,60)
                            } else { [System.Drawing.Color]::FromArgb(160,160,160) }
                            [void]$cmn.Nodes.Add($cmi)
                        }
                        [void]$chNode.Nodes.Add($cmn)
                    }

                    # ── Extensions ───────────────────────────────────────────────────────
                    if ($ch.SupportedVersions.Count -gt 0) {
                        $vn = New-Object System.Windows.Forms.TreeNode("Extension: supported_versions ($($ch.SupportedVersions.Count))")
                        $vn.ForeColor = [System.Drawing.Color]::FromArgb(160,200,220)
                        foreach ($v in $ch.SupportedVersions) {
                            $vi = New-Object System.Windows.Forms.TreeNode("$v")
                            $vi.ForeColor = if ("$v" -match 'deprecated|SSL|1\.0|1\.1') {
                                [System.Drawing.Color]::FromArgb(255,140,60)
                            } else { [System.Drawing.Color]::FromArgb(140,200,220) }
                            [void]$vn.Nodes.Add($vi)
                        }
                        $vn.Expand(); [void]$chNode.Nodes.Add($vn)
                    }
                    if ($ch.ALPN.Count -gt 0) {
                        $an = New-Object System.Windows.Forms.TreeNode("Extension: application_layer_protocol_negotiation ($($ch.ALPN.Count))")
                        $an.ForeColor = [System.Drawing.Color]::FromArgb(200,200,160)
                        foreach ($a in $ch.ALPN) {
                            $ai = New-Object System.Windows.Forms.TreeNode("$a")
                            $ai.ForeColor = [System.Drawing.Color]::FromArgb(180,180,140)
                            [void]$an.Nodes.Add($ai)
                        }
                        $an.Expand(); [void]$chNode.Nodes.Add($an)
                    }
                    if ($ch.SupportedGroups.Count -gt 0) {
                        $gn = New-Object System.Windows.Forms.TreeNode("Extension: supported_groups ($($ch.SupportedGroups.Count))")
                        $gn.ForeColor = [System.Drawing.Color]::FromArgb(160,220,180)
                        foreach ($g in $ch.SupportedGroups) {
                            $gi = New-Object System.Windows.Forms.TreeNode("$g")
                            $gi.ForeColor = [System.Drawing.Color]::FromArgb(140,200,160)
                            [void]$gn.Nodes.Add($gi)
                        }
                        $gn.Expand(); [void]$chNode.Nodes.Add($gn)
                    }
                    if ($ch.KeyShareGroups.Count -gt 0) {
                        $ksn = New-Object System.Windows.Forms.TreeNode("Extension: key_share -- groups with client key material ($($ch.KeyShareGroups.Count))")
                        $ksn.ForeColor = [System.Drawing.Color]::FromArgb(140,210,160)
                        foreach ($ks in $ch.KeyShareGroups) {
                            $ksi = New-Object System.Windows.Forms.TreeNode("$ks")
                            $ksi.ForeColor = [System.Drawing.Color]::FromArgb(120,190,140)
                            [void]$ksn.Nodes.Add($ksi)
                        }
                        $ksn.Expand(); [void]$chNode.Nodes.Add($ksn)
                    }
                    if ($ch.SignatureAlgorithms.Count -gt 0) {
                        $sgn = New-Object System.Windows.Forms.TreeNode("Extension: signature_algorithms ($($ch.SignatureAlgorithms.Count))")
                        $sgn.ForeColor = [System.Drawing.Color]::FromArgb(180,180,220)
                        foreach ($sg in $ch.SignatureAlgorithms) {
                            $sgi = New-Object System.Windows.Forms.TreeNode("$sg")
                            $sgi.ForeColor = [System.Drawing.Color]::FromArgb(160,160,200)
                            [void]$sgn.Nodes.Add($sgi)
                        }
                        [void]$chNode.Nodes.Add($sgn)
                    }
                    # Full extension inventory -- every extension type present in this Hello
                    if ($ch.ExtensionTypes.Count -gt 0) {
                        $etn = New-Object System.Windows.Forms.TreeNode("All extensions present ($($ch.ExtensionTypes.Count))")
                        $etn.ForeColor = [System.Drawing.Color]::FromArgb(190,170,210)
                        foreach ($et in $ch.ExtensionTypes) {
                            $eti = New-Object System.Windows.Forms.TreeNode("$et")
                            $eti.ForeColor = [System.Drawing.Color]::FromArgb(170,150,190)
                            [void]$etn.Nodes.Add($eti)
                        }
                        [void]$chNode.Nodes.Add($etn)
                    }

                    [void]$srvNode.Nodes.Add($chNode)
                    $chNode.Expand()
                }

                foreach ($sh in $hs.ServerHellos) {
                    $cipherLabel = if ($sh.SelectedCipherDisplay) { "$($sh.SelectedCipherDisplay)" } else { "$($sh.SelectedCipher)" }
                    $weakTag  = if ($sh.WeakCipher) { "  [WEAK: $($sh.WeakCipher.Reason)]" } else { '' }
                    $shLabel  = "ServerHello  [frame $($sh.Frame)]  $($sh.NegotiatedVersion)  /  $cipherLabel$weakTag"
                    $shNode   = New-Object System.Windows.Forms.TreeNode($shLabel)
                    $shNode.ForeColor = if ($sh.WeakCipher) { [System.Drawing.Color]::FromArgb(255,90,90) } else { [System.Drawing.Color]::FromArgb(255,180,60) }
                    $kgLabel = if ($sh.KeyGroupDisplay -and "$($sh.KeyGroupDisplay)" -ne "$($sh.KeyGroup)") { "$($sh.KeyGroupDisplay)" } elseif ($sh.KeyGroup) { "$($sh.KeyGroup)" } else { '' }
                    if ($kgLabel)      { [void]$shNode.Nodes.Add("Key exchange group: $kgLabel") }
                    if ($sh.ALPN)      { [void]$shNode.Nodes.Add("ALPN selected: $($sh.ALPN)") }
                    if ($sh.SessionID) { [void]$shNode.Nodes.Add("Session ID: $($sh.SessionID)") }
                    if ($sh.WeakCipher){ [void]$shNode.Nodes.Add("WEAK cipher: $($sh.WeakCipher.Reason)") }
                    [void]$srvNode.Nodes.Add($shNode)
                    $shNode.Expand()
                }

                foreach ($ct in $hs.Certificates) {
                    $certNode = New-Object System.Windows.Forms.TreeNode("Certificate  [frame $($ct.Frame)]")
                    $certNode.ForeColor = [System.Drawing.Color]::FromArgb(220,160,60)
                    if ($ct.SANs.Count -gt 0) {
                        $sn = New-Object System.Windows.Forms.TreeNode("Subject Alternative Names -- DNS ($($ct.SANs.Count))")
                        foreach ($s in $ct.SANs) { [void]$sn.Nodes.Add("$s") }
                        $sn.Expand(); [void]$certNode.Nodes.Add($sn)
                    }
                    $allFields = @($ct.Subject | Where-Object {$_} | Select-Object -Unique)
                    if ($allFields.Count -gt 0) {
                        $fn = New-Object System.Windows.Forms.TreeNode("Subject / Issuer fields ($($allFields.Count))")
                        foreach ($f in $allFields) { [void]$fn.Nodes.Add("$f") }
                        [void]$certNode.Nodes.Add($fn)
                    }
                    if ($ct.Validity.Count -gt 0) {
                        $vl = New-Object System.Windows.Forms.TreeNode("Validity period")
                        foreach ($t in $ct.Validity) { [void]$vl.Nodes.Add("$t") }
                        $vl.Expand(); [void]$certNode.Nodes.Add($vl)
                    }
                    $certNode.Expand(); [void]$srvNode.Nodes.Add($certNode)
                }

                if ($hs.Alerts.Count -gt 0) {
                    $alRoot = New-Object System.Windows.Forms.TreeNode("TLS Alerts ($($hs.Alerts.Count))")
                    $alRoot.ForeColor = [System.Drawing.Color]::FromArgb(255,80,80)
                    foreach ($al in $hs.Alerts) {
                        $alLabel = "[$($al.Level)]  $($al.Desc)  --  frame $($al.Frame)"
                        if ($al.SrcIP) { $alLabel += "  sent by $($al.SrcIP)" }
                        $aln = New-Object System.Windows.Forms.TreeNode($alLabel)
                        $aln.ForeColor = if ($al.Level -eq 'Fatal') { [System.Drawing.Color]::FromArgb(255,80,80) } else { [System.Drawing.Color]::FromArgb(255,160,60) }
                        [void]$alRoot.Nodes.Add($aln)
                    }
                    $alRoot.Expand(); [void]$srvNode.Nodes.Add($alRoot)
                }
                if ($hs.CCSCount -gt 0) {
                    [void]$srvNode.Nodes.Add("ChangeCipherSpec frames: $($hs.CCSCount)")
                }

                [void]$tvTls.Nodes.Add($srvNode)
                $srvNode.Expand()
            }
        } else {
            # No handshakes -- show TLS/SSL flows from conversations so the tab is still useful
            $whyNode = New-Object System.Windows.Forms.TreeNode('No ClientHello / ServerHello packets in this capture.')
            $whyNode.ForeColor = [System.Drawing.Color]::FromArgb(200,180,60)
            [void]$whyNode.Nodes.Add('The TLS session was already established when capture started.')
            [void]$whyNode.Nodes.Add('To see handshakes: start capture FIRST, then restart the device or app.')
            $whyNode.Expand()
            [void]$tvTls.Nodes.Add($whyNode)

            $tlsFlows = @($script:_allConvs | Where-Object { "$($_.Protocol)" -match 'TLS|SSL|QUIC' })
            if ($tlsFlows.Count -gt 0) {
                $flowRoot = New-Object System.Windows.Forms.TreeNode("TLS / SSL flows in capture  ($($tlsFlows.Count) flows  -- handshake not captured)")
                $flowRoot.ForeColor = [System.Drawing.Color]::FromArgb(100,185,255)
                foreach ($f in $tlsFlows) {
                    $label = "$($f.SrcIP):$($f.SrcPort)  ->  $($f.DstIP):$($f.DstPort)  [$($f.Protocol)]  $($f.Packets) pkts  $($f.Bytes) B"
                    $fn = New-Object System.Windows.Forms.TreeNode($label)
                    $fn.ForeColor = [System.Drawing.Color]::FromArgb(160,220,160)
                    if ($f.FirstInfo) { [void]$fn.Nodes.Add("First frame: $($f.FirstInfo)") }
                    [void]$flowRoot.Nodes.Add($fn)
                }
                $flowRoot.Expand()
                [void]$tvTls.Nodes.Add($flowRoot)
            }
        }
    } catch {
        $tlsErrMsg = $_.Exception.Message
        [void]$tvTls.Nodes.Add("TLS tree error: $tlsErrMsg")
        Write-IcptLine $txtOutP ("   [!] TLS error: {0}`r`n" -f $tlsErrMsg) ([System.Drawing.Color]::FromArgb(249,38,114))
    }
    Write-IcptLine $txtOutP ("   TLS sessions: {0} server(s) -- see TLS Handshakes tab`r`n" -f $tlsCount) ([System.Drawing.Color]::FromArgb(100,110,120))
    [System.Windows.Forms.Application]::DoEvents()

    # Populate BT / Zigbee tab
    $script:_pcapBtFile = $file; $txtOutBt.Text = ''
    Invoke-IcptTool $txtOutBt "BT/Zigbee: $(Split-Path $script:_pcapBtFile -Leaf)" {
        $btF = @(Get-TcpkPcapBtFindings    -Path $script:_pcapBtFile -ErrorAction SilentlyContinue)
        $zbF = @(Get-TcpkPcapZigbeeFindings -Path $script:_pcapBtFile -ErrorAction SilentlyContinue)
        $all = @($btF) + @($zbF) | Where-Object { $_ }
        if ($all) { $all } else {
            New-TcpkFinding -Module 'network' -RuleId 'pcap.no-bt-zigbee' -Severity 'INFO' -Confidence 'Inferred' `
                -Title 'No Bluetooth or Zigbee traffic detected' `
                -Evidence 'no btle/btl2cap/bthci_cmd/zbee_nwk frames in capture' `
                -Description "This capture contains no Bluetooth or Zigbee frames.`r`nBluetooth: capture via HCI snoop log, Ubertooth One, or Wireshark Bluetooth interface.`r`nZigbee: capture via RZUSBSTICK, ApiMote, Sniffle, or any 802.15.4 sniffer (LINKTYPE_IEEE802_15_4)." `
                -Fix ''
        }
    }

    # Populate Vulnerabilities sub-tab (CRITICAL / HIGH / MEDIUM only)
    $lvVuln.Items.Clear()
    $__vCount = 0
    foreach ($__vf in $script:_lastPcapFindings) {
        if ("$($__vf.Severity)" -notin @('CRITICAL','HIGH','MEDIUM')) { continue }
        $__vCount++
        $__vLvi = New-Object System.Windows.Forms.ListViewItem("$($__vf.Severity)")
        [void]$__vLvi.SubItems.Add("$($__vf.RuleId)")
        [void]$__vLvi.SubItems.Add("$($__vf.Title)")
        [void]$__vLvi.SubItems.Add("$($__vf.Evidence)")
        [void]$__vLvi.SubItems.Add("$($__vf.Fix)")
        $__vLvi.ForeColor = switch ("$($__vf.Severity)") {
            'CRITICAL' { [System.Drawing.Color]::FromArgb(255,80,80) }
            'HIGH'     { [System.Drawing.Color]::FromArgb(255,145,45) }
            'MEDIUM'   { [System.Drawing.Color]::FromArgb(255,215,55) }
            default    { [System.Drawing.Color]::White }
        }
        [void]$lvVuln.Items.Add($__vLvi)
    }
    if ($__vCount -eq 0) {
        [void]$lvVuln.Items.Add((New-Object System.Windows.Forms.ListViewItem('(no CRITICAL / HIGH / MEDIUM findings detected -- see Findings tab for INFO results)')))
    }
    $lblVulnCount.Text = "Vulnerabilities: $__vCount actionable (CRITICAL/HIGH/MEDIUM)  |  $(Split-Path $file -Leaf)"
})

# Decrypt fields (optional): TLS keylog (all TLS incl 1.3) and/or server RSA private key (RSA kx only)
$lblKeylog = New-Object System.Windows.Forms.Label; $lblKeylog.Text = "TLS keylog:"; $lblKeylog.ForeColor = [System.Drawing.Color]::White; $lblKeylog.Location = New-Object System.Drawing.Point(12,66); $lblKeylog.Size = New-Object System.Drawing.Size(96,18); $ctlP.Controls.Add($lblKeylog)
$txtKeylog = New-Object System.Windows.Forms.TextBox; $txtKeylog.Location = New-Object System.Drawing.Point(112,63); $txtKeylog.Size = New-Object System.Drawing.Size(296,24); $txtKeylog.Font = New-Object System.Drawing.Font('Consolas', 9); $txtKeylog.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtKeylog.ForeColor = [System.Drawing.Color]::White; $ctlP.Controls.Add($txtKeylog)
$btnKeylog = New-Object System.Windows.Forms.Button; $btnKeylog.Text = ".."; $btnKeylog.Location = New-Object System.Drawing.Point(414,63); $btnKeylog.Size = New-Object System.Drawing.Size(32,24); $btnKeylog.FlatStyle = 'Flat'; $btnKeylog.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnKeylog.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190); $ctlP.Controls.Add($btnKeylog)
$btnKeylog.Add_Click({ $dlg = New-Object System.Windows.Forms.OpenFileDialog; if ($dlg.ShowDialog() -eq 'OK') { $txtKeylog.Text = $dlg.FileName } })
$lblRsa = New-Object System.Windows.Forms.Label; $lblRsa.Text = "RSA key:"; $lblRsa.ForeColor = [System.Drawing.Color]::White; $lblRsa.Location = New-Object System.Drawing.Point(452,66); $lblRsa.Size = New-Object System.Drawing.Size(66,18); $ctlP.Controls.Add($lblRsa)
$txtRsa = New-Object System.Windows.Forms.TextBox; $txtRsa.Location = New-Object System.Drawing.Point(522,63); $txtRsa.Size = New-Object System.Drawing.Size(248,24); $txtRsa.Font = New-Object System.Drawing.Font('Consolas', 9); $txtRsa.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtRsa.ForeColor = [System.Drawing.Color]::White; $ctlP.Controls.Add($txtRsa)
$btnRsa = New-Object System.Windows.Forms.Button; $btnRsa.Text = ".."; $btnRsa.Location = New-Object System.Drawing.Point(776,63); $btnRsa.Size = New-Object System.Drawing.Size(32,24); $btnRsa.FlatStyle = 'Flat'; $btnRsa.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnRsa.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190); $ctlP.Controls.Add($btnRsa)
$btnRsa.Add_Click({ $dlg = New-Object System.Windows.Forms.OpenFileDialog; if ($dlg.ShowDialog() -eq 'OK') { $txtRsa.Text = $dlg.FileName } })
$lblDecHint = New-Object System.Windows.Forms.Label; $lblDecHint.Text = "keylog: all TLS  |  RSA key: RSA-kx only"; $lblDecHint.ForeColor = [System.Drawing.Color]::FromArgb(140,140,140); $lblDecHint.Location = New-Object System.Drawing.Point(812,66); $lblDecHint.Size = New-Object System.Drawing.Size(360,18); $ctlP.Controls.Add($lblDecHint)

# Row 3 (y=95): string search across all frames
$lblSearchStr = New-Object System.Windows.Forms.Label; $lblSearchStr.Text = "String search:"; $lblSearchStr.ForeColor = [System.Drawing.Color]::White; $lblSearchStr.Location = New-Object System.Drawing.Point(12,98); $lblSearchStr.Size = New-Object System.Drawing.Size(118,18); $ctlP.Controls.Add($lblSearchStr)
$txtPcapSearch = New-Object System.Windows.Forms.TextBox; $txtPcapSearch.Location = New-Object System.Drawing.Point(132,95); $txtPcapSearch.Size = New-Object System.Drawing.Size(504,24); $txtPcapSearch.Font = New-Object System.Drawing.Font('Consolas', 9); $txtPcapSearch.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtPcapSearch.ForeColor = [System.Drawing.Color]::White; $ctlP.Controls.Add($txtPcapSearch)
$chkSearchRegex = New-Object System.Windows.Forms.CheckBox; $chkSearchRegex.Text = "Regex"; $chkSearchRegex.ForeColor = [System.Drawing.Color]::White; $chkSearchRegex.Location = New-Object System.Drawing.Point(644,97); $chkSearchRegex.Size = New-Object System.Drawing.Size(60,20); $ctlP.Controls.Add($chkSearchRegex)
$lblProtoFilter = New-Object System.Windows.Forms.Label; $lblProtoFilter.Text = "Protocol:"; $lblProtoFilter.ForeColor = [System.Drawing.Color]::White; $lblProtoFilter.Location = New-Object System.Drawing.Point(712,98); $lblProtoFilter.Size = New-Object System.Drawing.Size(80,18); $ctlP.Controls.Add($lblProtoFilter)
$cmbProtoFilter = New-Object System.Windows.Forms.ComboBox; $cmbProtoFilter.Location = New-Object System.Drawing.Point(782,95); $cmbProtoFilter.Size = New-Object System.Drawing.Size(136,24); $cmbProtoFilter.DropDownStyle = 'DropDownList'; $cmbProtoFilter.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $cmbProtoFilter.ForeColor = [System.Drawing.Color]::White; $cmbProtoFilter.FlatStyle = 'Flat'; foreach ($pv in @('All','http','dns','tls','smtp','ftp','ssh','btle','btl2cap','zbee_nwk','wpan')) { [void]$cmbProtoFilter.Items.Add($pv) }; $cmbProtoFilter.SelectedIndex = 0; $ctlP.Controls.Add($cmbProtoFilter)
$btnPcapSearch = New-Object System.Windows.Forms.Button; $btnPcapSearch.Text = "Search"; $btnPcapSearch.Location = New-Object System.Drawing.Point(924,95); $btnPcapSearch.Size = New-Object System.Drawing.Size(74,24); $btnPcapSearch.FlatStyle = 'Flat'; $btnPcapSearch.BackColor = [System.Drawing.Color]::FromArgb(50,60,100); $btnPcapSearch.ForeColor = [System.Drawing.Color]::White; $ctlP.Controls.Add($btnPcapSearch)

# SizeChanged: reposition all right-edge controls in the search row (avoids Anchor timing issues)
$ctlP.Add_SizeChanged({
    $w = $ctlP.ClientSize.Width
    if ($w -lt 400) { return }
    $btnPcapSearch.Left  = $w - 82
    $cmbProtoFilter.Left = $btnPcapSearch.Left - 144
    $lblProtoFilter.Left = $cmbProtoFilter.Left - 86
    $chkSearchRegex.Left = $lblProtoFilter.Left - 68
    $txtPcapSearch.Width = $chkSearchRegex.Left - $txtPcapSearch.Left - 6
})

$btnPcapSearch.Add_Click({
    $file = $txtPcap.Text.Trim()
    $term = $txtPcapSearch.Text.Trim()
    if (-not $file -or -not (Test-Path -LiteralPath $file)) {
        [System.Windows.Forms.MessageBox]::Show('Load a .pcap file first.', 'TCPK', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return
    }
    if (-not $term) {
        [System.Windows.Forms.MessageBox]::Show('Enter a search string.', 'TCPK', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return
    }
    $lvSearch.Items.Clear()
    $subPcapTabs.SelectedIndex = 3
    try {
        $sp = @{ Path=$file; Pattern=$term }
        $pf = "$($cmbProtoFilter.SelectedItem)".Trim()
        if ($pf -and $pf -ne 'All') { $sp.Protocol = $pf }
        if ($chkSearchRegex.Checked) { $sp.Regex = $true }
        if ($txtKeylog.Text.Trim()) { $sp.KeylogFile = $txtKeylog.Text.Trim() }
        if ($txtRsa.Text.Trim())    { $sp.RsaKeyFile = $txtRsa.Text.Trim() }
        $results = @(Search-TcpkPcapString @sp -ErrorAction SilentlyContinue)
        if ($results.Count) {
            foreach ($r in $results) {
                $lvi = New-Object System.Windows.Forms.ListViewItem("$($r.'frame.number')")
                [void]$lvi.SubItems.Add("$($r.'frame.time_relative')")
                [void]$lvi.SubItems.Add("$($r.'ip.src')")
                [void]$lvi.SubItems.Add("$($r.'ip.dst')")
                [void]$lvi.SubItems.Add("$($r.'_ws.col.Protocol')")
                [void]$lvi.SubItems.Add("$($r.'_ws.col.Info')")
                [void]$lvSearch.Items.Add($lvi)
            }
        } else {
            $noMatchLvi = New-Object System.Windows.Forms.ListViewItem("(no frames matched '$term')")
            [void]$lvSearch.Items.Add($noMatchLvi)
        }
    } catch {
        $errLvi = New-Object System.Windows.Forms.ListViewItem("Error: $($_.Exception.Message)")
        [void]$lvSearch.Items.Add($errLvi)
    }
})

# Active: replay / IDOR / JWT (gated) -- turn a captured request into an active backend check
$gbActive = New-Object System.Windows.Forms.GroupBox
$gbActive.Text = "Active: replay / IDOR / JWT (gated -- authorized targets only)"; $gbActive.ForeColor = [System.Drawing.Color]::White
$gbActive.Location = New-Object System.Drawing.Point(10,8); $gbActive.Size = New-Object System.Drawing.Size(1150,214)
$gbActive.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$lblReqP = New-Object System.Windows.Forms.Label; $lblReqP.Text = "Raw HTTP request (identity A, requesting A's own object):"; $lblReqP.ForeColor = [System.Drawing.Color]::White; $lblReqP.Location = New-Object System.Drawing.Point(12,22); $lblReqP.Size = New-Object System.Drawing.Size(450,18); $gbActive.Controls.Add($lblReqP)
$txtReqP = New-Object System.Windows.Forms.TextBox; $txtReqP.Multiline = $true; $txtReqP.ScrollBars = 'Vertical'; $txtReqP.Location = New-Object System.Drawing.Point(12,40); $txtReqP.Size = New-Object System.Drawing.Size(700,50); $txtReqP.Font = New-Object System.Drawing.Font('Consolas', 9); $txtReqP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtReqP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtReqP)
$lblTgtP = New-Object System.Windows.Forms.Label; $lblTgtP.Text = "Target host/URL:"; $lblTgtP.ForeColor = [System.Drawing.Color]::White; $lblTgtP.Location = New-Object System.Drawing.Point(12,98); $lblTgtP.Size = New-Object System.Drawing.Size(130,18); $gbActive.Controls.Add($lblTgtP)
$txtTargetP = New-Object System.Windows.Forms.TextBox; $txtTargetP.Location = New-Object System.Drawing.Point(144,95); $txtTargetP.Size = New-Object System.Drawing.Size(270,24); $txtTargetP.Font = New-Object System.Drawing.Font('Consolas', 9); $txtTargetP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtTargetP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtTargetP)
$chkConfirmP = New-Object System.Windows.Forms.CheckBox; $chkConfirmP.Text = "confirm (send)"; $chkConfirmP.ForeColor = [System.Drawing.Color]::White; $chkConfirmP.Location = New-Object System.Drawing.Point(430,97); $chkConfirmP.Size = New-Object System.Drawing.Size(132,20); $gbActive.Controls.Add($chkConfirmP)
$chkUnsafeP = New-Object System.Windows.Forms.CheckBox; $chkUnsafeP.Text = "allow unsafe verbs"; $chkUnsafeP.ForeColor = [System.Drawing.Color]::White; $chkUnsafeP.Location = New-Object System.Drawing.Point(566,97); $chkUnsafeP.Size = New-Object System.Drawing.Size(162,20); $gbActive.Controls.Add($chkUnsafeP)
$lblSwapP = New-Object System.Windows.Forms.Label; $lblSwapP.Text = "IDOR swap id:"; $lblSwapP.ForeColor = [System.Drawing.Color]::White; $lblSwapP.Location = New-Object System.Drawing.Point(12,126); $lblSwapP.Size = New-Object System.Drawing.Size(106,18); $gbActive.Controls.Add($lblSwapP)
$txtSwapP = New-Object System.Windows.Forms.TextBox; $txtSwapP.Location = New-Object System.Drawing.Point(120,123); $txtSwapP.Size = New-Object System.Drawing.Size(82,24); $txtSwapP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtSwapP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtSwapP)
$lblSecondP = New-Object System.Windows.Forms.Label; $lblSecondP.Text = "B token:"; $lblSecondP.ForeColor = [System.Drawing.Color]::White; $lblSecondP.Location = New-Object System.Drawing.Point(206,126); $lblSecondP.Size = New-Object System.Drawing.Size(68,18); $gbActive.Controls.Add($lblSecondP)
$txtSecondP = New-Object System.Windows.Forms.TextBox; $txtSecondP.Location = New-Object System.Drawing.Point(278,123); $txtSecondP.Size = New-Object System.Drawing.Size(190,24); $txtSecondP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtSecondP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtSecondP)
$lblLocP = New-Object System.Windows.Forms.Label; $lblLocP.Text = "id loc:"; $lblLocP.ForeColor = [System.Drawing.Color]::White; $lblLocP.Location = New-Object System.Drawing.Point(470,126); $lblLocP.Size = New-Object System.Drawing.Size(62,18); $gbActive.Controls.Add($lblLocP)
$txtLocP = New-Object System.Windows.Forms.TextBox; $txtLocP.Location = New-Object System.Drawing.Point(536,123); $txtLocP.Size = New-Object System.Drawing.Size(68,24); $txtLocP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtLocP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtLocP)
$chkMutateP = New-Object System.Windows.Forms.CheckBox; $chkMutateP.Text = "auto-mutate"; $chkMutateP.ForeColor = [System.Drawing.Color]::White; $chkMutateP.Location = New-Object System.Drawing.Point(614,125); $chkMutateP.Size = New-Object System.Drawing.Size(110,20); $gbActive.Controls.Add($chkMutateP)
$lblJwtP = New-Object System.Windows.Forms.Label; $lblJwtP.Text = "JWT:"; $lblJwtP.ForeColor = [System.Drawing.Color]::White; $lblJwtP.Location = New-Object System.Drawing.Point(12,154); $lblJwtP.Size = New-Object System.Drawing.Size(40,18); $gbActive.Controls.Add($lblJwtP)
$txtJwtP = New-Object System.Windows.Forms.TextBox; $txtJwtP.Location = New-Object System.Drawing.Point(54,151); $txtJwtP.Size = New-Object System.Drawing.Size(406,24); $txtJwtP.Font = New-Object System.Drawing.Font('Consolas', 9); $txtJwtP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtJwtP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtJwtP)
$lblSecretP = New-Object System.Windows.Forms.Label; $lblSecretP.Text = "secret:"; $lblSecretP.ForeColor = [System.Drawing.Color]::White; $lblSecretP.Location = New-Object System.Drawing.Point(470,154); $lblSecretP.Size = New-Object System.Drawing.Size(62,18); $gbActive.Controls.Add($lblSecretP)
$txtSecretP = New-Object System.Windows.Forms.TextBox; $txtSecretP.Location = New-Object System.Drawing.Point(536,151); $txtSecretP.Size = New-Object System.Drawing.Size(168,24); $txtSecretP.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtSecretP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($txtSecretP)
$btnCandP = New-Object System.Windows.Forms.Button; $btnCandP.Text = "ID candidates"; $btnCandP.Location = New-Object System.Drawing.Point(12,180); $btnCandP.Size = New-Object System.Drawing.Size(118,26); $btnCandP.FlatStyle = 'Flat'; $btnCandP.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnCandP.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190); $gbActive.Controls.Add($btnCandP)
$btnReplayP = New-Object System.Windows.Forms.Button; $btnReplayP.Text = "Replay"; $btnReplayP.Location = New-Object System.Drawing.Point(136,180); $btnReplayP.Size = New-Object System.Drawing.Size(90,26); $btnReplayP.FlatStyle = 'Flat'; $btnReplayP.BackColor = [System.Drawing.Color]::FromArgb(0,90,120); $btnReplayP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($btnReplayP)
$btnIdorP = New-Object System.Windows.Forms.Button; $btnIdorP.Text = "IDOR probe"; $btnIdorP.Location = New-Object System.Drawing.Point(224,180); $btnIdorP.Size = New-Object System.Drawing.Size(100,26); $btnIdorP.FlatStyle = 'Flat'; $btnIdorP.BackColor = [System.Drawing.Color]::FromArgb(0,90,120); $btnIdorP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($btnIdorP)
$btnJwtCrackP = New-Object System.Windows.Forms.Button; $btnJwtCrackP.Text = "JWT crack"; $btnJwtCrackP.Location = New-Object System.Drawing.Point(330,180); $btnJwtCrackP.Size = New-Object System.Drawing.Size(100,26); $btnJwtCrackP.FlatStyle = 'Flat'; $btnJwtCrackP.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnJwtCrackP.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190); $gbActive.Controls.Add($btnJwtCrackP)
$btnJwtAttackP = New-Object System.Windows.Forms.Button; $btnJwtAttackP.Text = "JWT attack"; $btnJwtAttackP.Location = New-Object System.Drawing.Point(436,180); $btnJwtAttackP.Size = New-Object System.Drawing.Size(100,26); $btnJwtAttackP.FlatStyle = 'Flat'; $btnJwtAttackP.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnJwtAttackP.ForeColor = [System.Drawing.Color]::White; $gbActive.Controls.Add($btnJwtAttackP)
$lblActHint = New-Object System.Windows.Forms.Label; $lblActHint.Text = "acceptance is decided by response-body comparison, never status alone; findings stream to the console below"; $lblActHint.ForeColor = [System.Drawing.Color]::FromArgb(140,140,140); $lblActHint.Location = New-Object System.Drawing.Point(548,186); $lblActHint.Size = New-Object System.Drawing.Size(600,18); $gbActive.Controls.Add($lblActHint)
$btnCandP.Add_Click({ Invoke-IcptTool $txtOutR "ID candidates" { Get-TcpkRequestIdCandidates -RequestText $txtReqP.Text } })
$btnReplayP.Add_Click({
    if (-not (Test-IcptGate $chkGateR $txtOutR)) { return }
    $p = @{ RequestText = $txtReqP.Text; Target = $txtTargetP.Text.Trim() }
    if ($chkConfirmP.Checked) { $p.ConfirmActive = $true }
    if ($chkUnsafeP.Checked) { $p.AllowUnsafeMethods = $true }
    Invoke-IcptTool $txtOutR "Replay (missing-authz)" { Invoke-TcpkReplay @p }
})
$btnIdorP.Add_Click({
    if (-not (Test-IcptGate $chkGateR $txtOutR)) { return }
    $p = @{ RequestText = $txtReqP.Text; Target = $txtTargetP.Text.Trim() }
    if ($txtSwapP.Text.Trim()) { $p.SwapId = $txtSwapP.Text.Trim() }
    if ($txtSecondP.Text.Trim()) { $p.SecondIdentityToken = $txtSecondP.Text.Trim() }
    if ($txtLocP.Text.Trim()) { $p.Location = $txtLocP.Text.Trim() }
    if ($chkConfirmP.Checked) { $p.ConfirmActive = $true }
    if ($chkMutateP.Checked) { $p.AutoMutate = $true }
    Invoke-IcptTool $txtOutR "IDOR probe" { Invoke-TcpkIdorProbe @p }
})
$btnJwtCrackP.Add_Click({
    if (-not (Test-IcptGate $chkGateR $txtOutR)) { return }
    $p = @{}
    if ($txtJwtP.Text.Trim()) { $p.Token = $txtJwtP.Text.Trim() }
    Invoke-IcptTool $txtOutR "JWT crack (offline)" { Invoke-TcpkJwtCrack @p }
})
$btnJwtAttackP.Add_Click({
    if (-not (Test-IcptGate $chkGateR $txtOutR)) { return }
    $p = @{ Token = $txtJwtP.Text.Trim(); Target = $txtTargetP.Text.Trim() }
    if ($chkConfirmP.Checked) { $p.ConfirmActive = $true }
    if ($txtSecretP.Text.Trim()) { $p.Secret = $txtSecretP.Text.Trim() }
    Invoke-IcptTool $txtOutR "JWT attack (live)" { Invoke-TcpkJwtAttack @p }
})
$tabPcap.Controls.Add($ctlP)

# Sub-TabControl: Findings | Conversations | TLS Handshakes | Search Results | BT / Zigbee
$subPcapTabs = New-Object System.Windows.Forms.TabControl
$subPcapTabs.Dock = 'Fill'; $subPcapTabs.Font = New-Object System.Drawing.Font('Cascadia Mono', 9)
$subPcapTabs.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)

# --- Tab 1: Findings (existing console output) ---
$subPcapFindings = New-Object System.Windows.Forms.TabPage; $subPcapFindings.Text = ' Findings '; $subPcapFindings.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
$txtOutP = New-Object System.Windows.Forms.RichTextBox
$txtOutP.Dock = 'Fill'; $txtOutP.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtOutP.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtOutP.ForeColor = [System.Drawing.Color]::White
$txtOutP.ReadOnly = $true; $txtOutP.WordWrap = $false
$txtOutP.Text = "Packet-capture analysis console.`r`n`r`nLoad a .pcap / .pcapng and click 'Analyse capture'.`r`n`r`nTCPK dissects the file via tshark (ships with Wireshark) -- 21 detection checks:`r`n`r`n  CREDENTIALS    HTTP Basic auth, FTP USER/PASS, SMTP AUTH, HTTP POST form passwords`r`n  CLEARTEXT      HTTP transport, Telnet (23), MQTT (1883), LDAP (389), VNC (5900-5910)`r`n  WEAK TLS       SSL 3.0 / TLS 1.0-1.1 / broken ciphers: NULL, RC4, 3DES, EXPORT, anon`r`n  IN-URL LEAKS   Tokens, API keys, secrets in HTTP query params; JWT Bearer over HTTP`r`n  AUTH ATTACKS   NTLM/Negotiate over HTTP (hash capture risk), SNMP v1/v2c community str.`r`n  COOKIES        Secure / HttpOnly flag absent; session cookies set over cleartext HTTP`r`n  DNS            Query inventory (40+ domains); exfiltration patterns (long labels >40c)`r`n  NETWORK        ARP spoofing (duplicate IP-MAC pairs), endpoint inventory`r`n  PATHS          Sensitive HTTP paths: .env .git /admin /config /credentials /backup`r`n`r`nOther tabs: Conversations (flow table) | TLS Handshakes (tree) | Search Results`r`n            BT/Zigbee (Bluetooth and Zigbee) | Network Graph | Vulnerabilities (table)"
$subPcapFindings.Controls.Add($txtOutP)
[void]$subPcapTabs.TabPages.Add($subPcapFindings)

# --- Tab 2: Conversations ---
$subPcapConv = New-Object System.Windows.Forms.TabPage; $subPcapConv.Text = ' Conversations '; $subPcapConv.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
# Filter bar (Dock=Top)
$pnlConvFilter = New-Object System.Windows.Forms.Panel; $pnlConvFilter.Dock = 'Top'; $pnlConvFilter.Height = 30; $pnlConvFilter.BackColor = [System.Drawing.Color]::FromArgb(28,28,32)
$lblConvIpF = New-Object System.Windows.Forms.Label; $lblConvIpF.Text = 'IP:'; $lblConvIpF.ForeColor = [System.Drawing.Color]::FromArgb(170,175,180); $lblConvIpF.Location = New-Object System.Drawing.Point(4,7); $lblConvIpF.Size = New-Object System.Drawing.Size(24,18); $pnlConvFilter.Controls.Add($lblConvIpF)
$txtConvIpF = New-Object System.Windows.Forms.TextBox; $txtConvIpF.Location = New-Object System.Drawing.Point(30,5); $txtConvIpF.Size = New-Object System.Drawing.Size(148,20); $txtConvIpF.Font = New-Object System.Drawing.Font('Consolas',8.5); $txtConvIpF.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtConvIpF.ForeColor = [System.Drawing.Color]::White; $pnlConvFilter.Controls.Add($txtConvIpF)
$lblConvPortF = New-Object System.Windows.Forms.Label; $lblConvPortF.Text = 'Port:'; $lblConvPortF.ForeColor = [System.Drawing.Color]::FromArgb(170,175,180); $lblConvPortF.Location = New-Object System.Drawing.Point(186,7); $lblConvPortF.Size = New-Object System.Drawing.Size(38,18); $pnlConvFilter.Controls.Add($lblConvPortF)
$txtConvPortF = New-Object System.Windows.Forms.TextBox; $txtConvPortF.Location = New-Object System.Drawing.Point(226,5); $txtConvPortF.Size = New-Object System.Drawing.Size(72,20); $txtConvPortF.Font = New-Object System.Drawing.Font('Consolas',8.5); $txtConvPortF.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtConvPortF.ForeColor = [System.Drawing.Color]::White; $pnlConvFilter.Controls.Add($txtConvPortF)
$lblConvProtoF = New-Object System.Windows.Forms.Label; $lblConvProtoF.Text = 'Protocol:'; $lblConvProtoF.ForeColor = [System.Drawing.Color]::FromArgb(170,175,180); $lblConvProtoF.Location = New-Object System.Drawing.Point(308,7); $lblConvProtoF.Size = New-Object System.Drawing.Size(64,18); $pnlConvFilter.Controls.Add($lblConvProtoF)
$cmbConvProtoF = New-Object System.Windows.Forms.ComboBox; $cmbConvProtoF.Location = New-Object System.Drawing.Point(374,4); $cmbConvProtoF.Size = New-Object System.Drawing.Size(130,22); $cmbConvProtoF.DropDownStyle = 'DropDownList'; $cmbConvProtoF.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $cmbConvProtoF.ForeColor = [System.Drawing.Color]::White; $cmbConvProtoF.FlatStyle = 'Flat'; [void]$cmbConvProtoF.Items.Add('All'); $cmbConvProtoF.SelectedIndex = 0; $pnlConvFilter.Controls.Add($cmbConvProtoF)
$btnConvClearF = New-Object System.Windows.Forms.Button; $btnConvClearF.Text = 'Clear'; $btnConvClearF.Location = New-Object System.Drawing.Point(512,4); $btnConvClearF.Size = New-Object System.Drawing.Size(52,22); $btnConvClearF.FlatStyle = 'Flat'; $btnConvClearF.BackColor = [System.Drawing.Color]::FromArgb(55,55,58); $btnConvClearF.ForeColor = [System.Drawing.Color]::White; $pnlConvFilter.Controls.Add($btnConvClearF)
$lblConvCount = New-Object System.Windows.Forms.Label; $lblConvCount.Text = 'No capture loaded'; $lblConvCount.ForeColor = [System.Drawing.Color]::FromArgb(120,125,130); $lblConvCount.Location = New-Object System.Drawing.Point(572,7); $lblConvCount.Size = New-Object System.Drawing.Size(300,18); $pnlConvFilter.Controls.Add($lblConvCount)
# Conversations ListView (Dock=Fill, full width -- packet detail opens in popup via right-click)
$lvConv = New-Object System.Windows.Forms.ListView
$lvConv.Dock = 'Fill'; $lvConv.View = 'Details'; $lvConv.FullRowSelect = $true; $lvConv.GridLines = $false; $lvConv.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::None
$lvConv.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $lvConv.ForeColor = [System.Drawing.Color]::White
$lvConv.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
foreach ($colDef in @(@('Date',92),@('Time',76),@('Src IP',118),@('Src Port',66),@('Dst IP',118),@('Dst Port',66),@('Protocol',78),@('Packets',60),@('Bytes',66),@('Info',220),@('Src MAC',120),@('Dst MAC',120))) {
    $lvc = New-Object System.Windows.Forms.ColumnHeader; $lvc.Text = $colDef[0]; $lvc.Width = $colDef[1]; [void]$lvConv.Columns.Add($lvc)
}
# Column header row -- ListView system headers are invisible on dark themes
$pnlConvHdr = New-Object System.Windows.Forms.Panel
$pnlConvHdr.Dock = 'Top'; $pnlConvHdr.Height = 22; $pnlConvHdr.BackColor = [System.Drawing.Color]::FromArgb(36,36,44)
$_xOff = 0
foreach ($cd in @(@('Date',92),@('Time',76),@('Src IP',118),@('Src Port',66),@('Dst IP',118),@('Dst Port',66),@('Protocol',78),@('Packets',60),@('Bytes',66),@('Info',220),@('Src MAC',120),@('Dst MAC',120))) {
    $lh = New-Object System.Windows.Forms.Label; $lh.Text = $cd[0]; $lh.TextAlign = 'MiddleLeft'
    $lh.Location = New-Object System.Drawing.Point(($_xOff + 3), 0); $lh.Size = New-Object System.Drawing.Size(($cd[1] - 4), 22)
    $lh.ForeColor = [System.Drawing.Color]::FromArgb(155,165,178); $lh.Font = New-Object System.Drawing.Font('Cascadia Mono', 8)
    $pnlConvHdr.Controls.Add($lh); $_xOff += $cd[1]
}
# Dock order: WinForms docks Top controls in DESCENDING Controls-index order (highest index = absolute top).
# To get Filter(top) -> Header -> List: add pnlConvHdr first (lower index) then pnlConvFilter (higher index).
$subPcapConv.Controls.Add($pnlConvHdr); $subPcapConv.Controls.Add($pnlConvFilter); $subPcapConv.Controls.Add($lvConv)
[void]$subPcapTabs.TabPages.Add($subPcapConv)

# --- Tab 3: TLS Handshakes ---
$subPcapTls = New-Object System.Windows.Forms.TabPage; $subPcapTls.Text = ' TLS Handshakes '; $subPcapTls.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
$tvTls = New-Object System.Windows.Forms.TreeView
$tvTls.Dock = 'Fill'; $tvTls.Font = New-Object System.Drawing.Font('Cascadia Mono', 9)
$tvTls.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $tvTls.ForeColor = [System.Drawing.Color]::FromArgb(210,215,220)
$tvTls.LineColor = [System.Drawing.Color]::FromArgb(80,80,90)
[void]$tvTls.Nodes.Add('Load a capture and click Analyse to populate this tree.')
[void]$tvTls.Nodes.Add('Each server:port node shows ClientHello (offered ciphers, SNI, supported TLS versions)')
[void]$tvTls.Nodes.Add('and ServerHello (negotiated version, selected cipher). Weak ciphers are flagged [WEAK].')
$subPcapTls.Controls.Add($tvTls)
[void]$subPcapTabs.TabPages.Add($subPcapTls)

# Conversations tab: filter scriptblock + events + packet-detail row handler
$script:_allConvs = @(); $script:_convReady = $false; $script:_tshark = $null
$script:_applyConvFilter = {
    if (-not $script:_convReady) { return }
    $ipF    = $txtConvIpF.Text.Trim()
    $portF  = $txtConvPortF.Text.Trim()
    $protoF = if ($cmbConvProtoF.SelectedIndex -le 0) { '' } else { "$($cmbConvProtoF.SelectedItem)" }
    $lvConv.BeginUpdate(); $lvConv.Items.Clear(); $shown = 0
    foreach ($c in $script:_allConvs) {
        if ($ipF   -and "$($c.SrcIP)" -notmatch [Regex]::Escape($ipF) -and "$($c.DstIP)" -notmatch [Regex]::Escape($ipF)) { continue }
        if ($portF -and "$($c.SrcPort)" -ne $portF -and "$($c.DstPort)" -ne $portF) { continue }
        if ($protoF -and "$($c.Protocol)" -ne $protoF) { continue }
        $lvi = New-Object System.Windows.Forms.ListViewItem("$($c.Date)")
        [void]$lvi.SubItems.Add("$($c.Time)"); [void]$lvi.SubItems.Add("$($c.SrcIP)")
        [void]$lvi.SubItems.Add("$($c.SrcPort)"); [void]$lvi.SubItems.Add("$($c.DstIP)")
        [void]$lvi.SubItems.Add("$($c.DstPort)"); [void]$lvi.SubItems.Add("$($c.Protocol)")
        [void]$lvi.SubItems.Add("$($c.Packets)"); [void]$lvi.SubItems.Add("$($c.Bytes)")
        [void]$lvi.SubItems.Add("$($c.FirstInfo)"); [void]$lvi.SubItems.Add("$($c.SrcMAC)"); [void]$lvi.SubItems.Add("$($c.DstMAC)")
        $prl = "$($c.Protocol)".ToLower()
        $lvi.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
        $lvi.ForeColor = if     ($prl -match 'https|tls|ssl')  { [System.Drawing.Color]::FromArgb(90,175,255) }
                         elseif ($prl -match 'http')            { [System.Drawing.Color]::FromArgb(255,150,55) }
                         elseif ($prl -match 'dns')             { [System.Drawing.Color]::FromArgb(205,215,50) }
                         elseif ($prl -match 'smtp|pop|imap')   { [System.Drawing.Color]::FromArgb(240,80,65) }
                         elseif ($prl -match 'ftp')             { [System.Drawing.Color]::FromArgb(235,145,50) }
                         elseif ($prl -match 'ssh')             { [System.Drawing.Color]::FromArgb(65,200,95) }
                         elseif ($prl -match 'udp')             { [System.Drawing.Color]::FromArgb(165,100,235) }
                         else                                   { [System.Drawing.Color]::FromArgb(170,178,188) }
        [void]$lvConv.Items.Add($lvi); $shown++
    }
    $lvConv.EndUpdate()
    $lblConvCount.Text = "Showing $shown of $($script:_allConvs.Count) flow(s)"
}
$txtConvIpF.Add_TextChanged({ & $script:_applyConvFilter })
$txtConvPortF.Add_TextChanged({ & $script:_applyConvFilter })
$cmbConvProtoF.Add_SelectedIndexChanged({ & $script:_applyConvFilter })
$btnConvClearF.Add_Click({ $txtConvIpF.Text = ''; $txtConvPortF.Text = ''; $cmbConvProtoF.SelectedIndex = 0 })

# Shared helper: query tshark for the selected flow and open a popup window with full packet detail
$script:_showConvDetail = {
    param($sel)
    $tsharkBin = if ($script:_tshark) { $script:_tshark } else { try { (Get-Command tshark -ErrorAction Stop).Source } catch { $null } }
    $pcapPath  = if ($script:_pcapRunParams.Path) { $script:_pcapRunParams.Path } else { $null }
    if (-not $tsharkBin -or -not $pcapPath -or -not (Test-Path -LiteralPath $pcapPath)) { return }
    $sip   = $sel.SubItems[2].Text;  $sport = $sel.SubItems[3].Text
    $dip   = $sel.SubItems[4].Text;  $dport = $sel.SubItems[5].Text
    $proto = $sel.SubItems[6].Text;  $pkts  = $sel.SubItems[7].Text
    $bytes = $sel.SubItems[8].Text;  $smac  = $sel.SubItems[10].Text; $dmac = $sel.SubItems[11].Text
    $protoL = $proto.ToLower()
    $txProto = if     ($protoL -match 'tcp|tls|ssl|https|http|ssh|ftp|smtp|pop|imap|rdp|telnet') { 'tcp' }
               elseif ($protoL -match 'udp|dns|quic|snmp|ntp|dhcp|mdns|ssdp|stun')              { 'udp' }
               else { '' }
    $hasPorts = ($sport -ne '') -and ($dport -ne '')
    $convFilter = if ($hasPorts -and $txProto) {
        "($txProto.srcport==$sport and ip.src==$sip and ip.dst==$dip and $txProto.dstport==$dport) or ($txProto.srcport==$dport and ip.src==$dip and ip.dst==$sip and $txProto.dstport==$sport)"
    } elseif ($sip -and $dip) { "(ip.src==$sip and ip.dst==$dip) or (ip.src==$dip and ip.dst==$sip)" } else { return }
    $pktRows = @(& $tsharkBin -r $pcapPath -n -Y $convFilter -T fields '-E' "separator=`t" `
        -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info `
        2>$null | Select-Object -First 500)

    # --- Form ---
    $popForm = New-Object System.Windows.Forms.Form
    $popForm.Text = "Packet Detail  --  ${sip}:${sport} <-> ${dip}:${dport}  [$proto]"
    $popForm.Size = New-Object System.Drawing.Size(1300, 720)
    $popForm.StartPosition = 'CenterParent'
    $popForm.BackColor = [System.Drawing.Color]::FromArgb(18,18,22)
    $popForm.ForeColor = [System.Drawing.Color]::White
    try { $popForm.Icon = $form.Icon } catch {}

    # --- Summary strip ---
    $pnlPopTop = New-Object System.Windows.Forms.Panel
    $pnlPopTop.Dock = 'Top'; $pnlPopTop.Height = 52; $pnlPopTop.BackColor = [System.Drawing.Color]::FromArgb(22,22,30)
    $lblPopSum = New-Object System.Windows.Forms.Label
    $lblPopSum.Dock = 'Fill'; $lblPopSum.Padding = New-Object System.Windows.Forms.Padding(10,6,10,4)
    $lblPopSum.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
    $lblPopSum.ForeColor = [System.Drawing.Color]::FromArgb(200,208,218)
    $lblPopSum.Text = "${sip}:${sport}  <->  ${dip}:${dport}    Protocol: $proto    Packets: $pkts    Bytes: $bytes`nSrc MAC: $smac    Dst MAC: $dmac    $($pktRows.Count) frame(s) (max 500 per flow)"
    $pnlPopTop.Controls.Add($lblPopSum)

    # --- SplitContainer: left = frame list, right = single-packet dissection ---
    $popSplit = New-Object System.Windows.Forms.SplitContainer
    $popSplit.Dock = 'Fill'; $popSplit.Orientation = 'Vertical'
    $popSplit.SplitterWidth = 3; $popSplit.SplitterDistance = 430
    $popSplit.BackColor = [System.Drawing.Color]::FromArgb(30,30,40)
    $popSplit.Panel1.BackColor = [System.Drawing.Color]::FromArgb(18,18,22)
    $popSplit.Panel2.BackColor = [System.Drawing.Color]::FromArgb(15,15,19)

    # Left panel -- custom header row
    $pnlFrHdr = New-Object System.Windows.Forms.Panel
    $pnlFrHdr.Dock = 'Top'; $pnlFrHdr.Height = 20; $pnlFrHdr.BackColor = [System.Drawing.Color]::FromArgb(26,26,36)
    $_fhx = 0
    foreach ($fhd in @(@('#',52),@('Time (s)',102),@('Source',112),@('',18),@('Destination',112),@('Proto',58),@('Len',50),@('Info',300))) {
        $fhl = New-Object System.Windows.Forms.Label; $fhl.Text = $fhd[0]; $fhl.TextAlign = 'MiddleLeft'
        $fhl.Location = New-Object System.Drawing.Point(($_fhx+3),0); $fhl.Size = New-Object System.Drawing.Size(($fhd[1]-3),20)
        $fhl.ForeColor = [System.Drawing.Color]::FromArgb(105,120,138); $fhl.Font = New-Object System.Drawing.Font('Cascadia Mono',7.5)
        $pnlFrHdr.Controls.Add($fhl); $_fhx += $fhd[1]
    }

    # Left panel -- frame ListView
    $lvFr = New-Object System.Windows.Forms.ListView
    $lvFr.Dock = 'Fill'; $lvFr.View = 'Details'; $lvFr.FullRowSelect = $true; $lvFr.GridLines = $false
    $lvFr.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::None
    $lvFr.BackColor = [System.Drawing.Color]::FromArgb(18,18,22)
    $lvFr.ForeColor = [System.Drawing.Color]::FromArgb(188,198,210)
    $lvFr.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
    foreach ($fw in @(52,102,112,18,112,58,50,300)) {
        $fhc = New-Object System.Windows.Forms.ColumnHeader; $fhc.Width = $fw; [void]$lvFr.Columns.Add($fhc)
    }
    foreach ($pr in $pktRows) {
        if (-not "$pr") { continue }
        $fp = "$pr" -split "`t",7; while ($fp.Count -lt 7) { $fp += '' }
        $fvi = New-Object System.Windows.Forms.ListViewItem($fp[0].Trim())
        [void]$fvi.SubItems.Add("$($fp[1])s")
        [void]$fvi.SubItems.Add($fp[2])
        [void]$fvi.SubItems.Add('->')
        [void]$fvi.SubItems.Add($fp[3])
        [void]$fvi.SubItems.Add($fp[4])
        [void]$fvi.SubItems.Add("$($fp[5])B")
        # Strip non-ASCII from Info (tshark Unicode arrows render as garbage in GDI)
        [void]$fvi.SubItems.Add(($fp[6] -replace '[^\x00-\x7F]+', '->'))
        [void]$lvFr.Items.Add($fvi)
    }
    $popSplit.Panel1.Controls.Add($lvFr)
    $popSplit.Panel1.Controls.Add($pnlFrHdr)

    # Right panel -- dissection header label + RichTextBox
    $pnlDHdr = New-Object System.Windows.Forms.Panel
    $pnlDHdr.Dock = 'Top'; $pnlDHdr.Height = 20; $pnlDHdr.BackColor = [System.Drawing.Color]::FromArgb(20,20,28)
    $lblDHdr = New-Object System.Windows.Forms.Label; $lblDHdr.Dock = 'Fill'
    $lblDHdr.Text = 'PACKET DETAIL  --  click a frame on the left'
    $lblDHdr.ForeColor = [System.Drawing.Color]::FromArgb(80,100,120)
    $lblDHdr.Font = New-Object System.Drawing.Font('Cascadia Mono', 7.5)
    $lblDHdr.Padding = New-Object System.Windows.Forms.Padding(8,3,0,0)
    $pnlDHdr.Controls.Add($lblDHdr)

    $rtbDiss = New-Object System.Windows.Forms.RichTextBox
    $rtbDiss.Dock = 'Fill'; $rtbDiss.ReadOnly = $true; $rtbDiss.WordWrap = $false
    $rtbDiss.BackColor = [System.Drawing.Color]::FromArgb(15,15,19)
    $rtbDiss.ForeColor = [System.Drawing.Color]::FromArgb(190,202,215)
    $rtbDiss.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
    $rtbDiss.BorderStyle = 'None'
    $rtbDiss.Text = 'Click any frame on the left to see its full dissection (Frame / Ethernet / IP / TCP / TLS / ...) .'
    $popSplit.Panel2.Controls.Add($rtbDiss)
    $popSplit.Panel2.Controls.Add($pnlDHdr)

    # Frame selection -- run tshark -V for the exact frame number
    $lvFr.Add_SelectedIndexChanged({
        if ($lvFr.SelectedItems.Count -eq 0) { return }
        $selFn = $lvFr.SelectedItems[0].Text.Trim()
        if (-not $selFn) { return }
        $lblDHdr.Text = "PACKET DETAIL  --  frame $selFn   (loading...)"
        $popForm.Refresh()
        $dissLines = @(& $tsharkBin -r $pcapPath -n -Y "frame.number == $selFn" -V 2>$null)
        if ($dissLines) {
            $rtbDiss.Text = ($dissLines -join "`n")
            $lblDHdr.Text = "PACKET DETAIL  --  frame $selFn"
        } else {
            $rtbDiss.Text = "No dissection output for frame $selFn."
            $lblDHdr.Text = "PACKET DETAIL  --  frame $selFn   (no data)"
        }
        try { $rtbDiss.SelectionStart = 0; $rtbDiss.ScrollToCaret() } catch {}
    })

    $popForm.Controls.Add($popSplit)
    $popForm.Controls.Add($pnlPopTop)
    $popForm.Show()
}

# Right-click context menu
$ctxConv = New-Object System.Windows.Forms.ContextMenuStrip
$ctxConv.BackColor = [System.Drawing.Color]::FromArgb(40,40,44); $ctxConv.ForeColor = [System.Drawing.Color]::White
$mnuConvOpen = New-Object System.Windows.Forms.ToolStripMenuItem 'Open packet detail...'
$mnuConvOpen.ForeColor = [System.Drawing.Color]::FromArgb(100,185,255)
[void]$ctxConv.Items.Add($mnuConvOpen)
$lvConv.ContextMenuStrip = $ctxConv
$mnuConvOpen.Add_Click({ if ($lvConv.SelectedItems.Count -eq 0) { return }; & $script:_showConvDetail $lvConv.SelectedItems[0] })
# Double-click also opens the popup
$lvConv.Add_MouseDoubleClick({ if ($lvConv.SelectedItems.Count -eq 0) { return }; & $script:_showConvDetail $lvConv.SelectedItems[0] })

# --- Tab 4: Search Results ---
$subPcapSearch = New-Object System.Windows.Forms.TabPage; $subPcapSearch.Text = ' Search Results '; $subPcapSearch.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
$lvSearch = New-Object System.Windows.Forms.ListView
$lvSearch.Dock = 'Fill'; $lvSearch.View = 'Details'; $lvSearch.FullRowSelect = $true; $lvSearch.GridLines = $true
$lvSearch.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $lvSearch.ForeColor = [System.Drawing.Color]::White
$lvSearch.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
foreach ($colDef in @(@('#',60),@('Time',80),@('Src',130),@('Dst',130),@('Protocol',90),@('Info',600))) {
    $lvc = New-Object System.Windows.Forms.ColumnHeader; $lvc.Text = $colDef[0]; $lvc.Width = $colDef[1]; [void]$lvSearch.Columns.Add($lvc)
}
$searchHintLvi = New-Object System.Windows.Forms.ListViewItem('Use the "String search" bar above to find frames containing any string or regex across the entire capture.')
[void]$lvSearch.Items.Add($searchHintLvi)
$subPcapSearch.Controls.Add($lvSearch)
[void]$subPcapTabs.TabPages.Add($subPcapSearch)

# --- Tab 5: BT / Zigbee ---
$subPcapBt = New-Object System.Windows.Forms.TabPage; $subPcapBt.Text = ' BT / Zigbee '; $subPcapBt.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
$txtOutBt = New-Object System.Windows.Forms.RichTextBox
$txtOutBt.Dock = 'Fill'; $txtOutBt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtOutBt.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtOutBt.ForeColor = [System.Drawing.Color]::White
$txtOutBt.ReadOnly = $true; $txtOutBt.WordWrap = $false
$txtOutBt.Text = "Bluetooth and Zigbee capture analysis.`r`n`r`nLoad a .pcap and click 'Analyse capture'. TCPK auto-detects Bluetooth and Zigbee frames`r`nand runs protocol-specific checks:`r`n`r`nBluetooth / BLE:`r`n  * BLE JustWorks pairing (no MITM protection)   [HIGH]`r`n  * GATT Write / Read operations in cleartext     [HIGH / MEDIUM]`r`n  * BLE advertisement device fingerprinting        [INFO]`r`n  * HCI trace presence (pairing state, link keys)  [INFO]`r`n`r`nZigbee / IEEE 802.15.4:`r`n  * Unencrypted NWK frames (AES-CCM* disabled)     [HIGH]`r`n  * Transport Key broadcast in the air              [CRITICAL]`r`n  * Frame inventory and security summary            [INFO]`r`n`r`nCapture sources:`r`n  BT:     HCI snoop log, Ubertooth One, Wireshark Bluetooth interface, Sniffle`r`n  Zigbee: RZUSBSTICK, ApiMote, Sniffle, any 802.15.4 sniffer (LINKTYPE_IEEE802_15_4)"
$subPcapBt.Controls.Add($txtOutBt)
[void]$subPcapTabs.TabPages.Add($subPcapBt)

# --- Tab 6: Network Graph (GDI+ circular IP-conversation graph) ---
$script:graphConvs = @(); $script:graphPositions = @{}
$subPcapNetGraph = New-Object System.Windows.Forms.TabPage; $subPcapNetGraph.Text = ' Network Graph '; $subPcapNetGraph.BackColor = [System.Drawing.Color]::FromArgb(18,18,22)
$pbGraph = New-Object System.Windows.Forms.PictureBox; $pbGraph.Dock = 'Fill'; $pbGraph.BackColor = [System.Drawing.Color]::FromArgb(18,18,22)
$pbGraph.Add_Paint({
    $g = $args[1].Graphics
    $g.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    if ($script:graphPositions.Count -eq 0) {
        $hbr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(70,75,82))
        $hfn = New-Object System.Drawing.Font('Consolas', 10)
        $g.DrawString('Analyse a capture to build the IP network graph.', $hfn, $hbr, 24, 24)
        $hbr.Dispose(); $hfn.Dispose(); return
    }
    # Protocol-to-RGB helper (inline scriptblock so no function name collision)
    $protoRgb = { param($pr)
        $p = "$pr".ToLower()
        if     ($p -match 'https|tls|ssl')  { 60,145,230 }
        elseif ($p -match 'http')            { 235,130,40 }
        elseif ($p -match 'dns')             { 205,220,45 }
        elseif ($p -match 'smtp|pop|imap')   { 235,70,60 }
        elseif ($p -match 'ftp')             { 235,148,40 }
        elseif ($p -match 'ssh')             { 55,205,90 }
        elseif ($p -match 'udp')             { 165,95,235 }
        else                                 { 80,140,200 }
    }
    foreach ($c in $script:graphConvs) {
        $ps = $script:graphPositions["$($c.SrcIP)"]; $pd = $script:graphPositions["$($c.DstIP)"]
        if (-not $ps -or -not $pd) { continue }
        $al = [int][Math]::Min(200, [Math]::Max(35, 55 + [Math]::Log([double]$c.Bytes + 2) * 9))
        $tk = [float][Math]::Max(0.6, [Math]::Min(4.0, [Math]::Log([double]$c.Bytes + 2) / 3.5))
        $rgb = & $protoRgb $c.Protocol
        $ep = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb($al, $rgb[0], $rgb[1], $rgb[2]), $tk)
        $g.DrawLine($ep, [float]$ps.X, [float]$ps.Y, [float]$pd.X, [float]$pd.Y); $ep.Dispose()
    }
    $nb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(90,185,255))
    $lb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(215,220,228))
    $fn = New-Object System.Drawing.Font('Consolas', 7)
    foreach ($ip in $script:graphPositions.Keys) {
        $p = $script:graphPositions[$ip]; $nx = [float]$p.X; $ny = [float]$p.Y
        $g.FillEllipse($nb, $nx - 5, $ny - 5, 10, 10)
        $g.DrawString($ip, $fn, $lb, $nx + 8, $ny - 7)
    }
    $nb.Dispose(); $lb.Dispose(); $fn.Dispose()
    # Protocol legend (top-left)
    $seenP = @($script:graphConvs | ForEach-Object { "$($_.Protocol)".ToLower() } | Sort-Object -Unique | Select-Object -First 9)
    if ($seenP.Count -gt 0) {
        $lfn = New-Object System.Drawing.Font('Consolas', 7.5)
        $lbg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180,22,22,26))
        $g.FillRectangle($lbg, 8, 8, 145, 14 + $seenP.Count * 14); $lbg.Dispose()
        $lhdr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(130,135,142))
        $g.DrawString('Protocol', $lfn, $lhdr, 13, 10); $lhdr.Dispose()
        $ly = 22
        foreach ($lp in $seenP) {
            $lrgb = & $protoRgb $lp
            $lsb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(210,$lrgb[0],$lrgb[1],$lrgb[2]))
            $g.FillRectangle($lsb, 13, $ly + 2, 10, 8)
            $g.DrawString($lp, $lfn, $lsb, 28, $ly)
            $lsb.Dispose(); $ly += 14
        }
        $lfn.Dispose()
    }
})
$pbGraph.Add_Resize({
    if ($script:graphConvs.Count -eq 0) { return }
    $rn = @($script:graphConvs | ForEach-Object { $_.SrcIP, $_.DstIP } | Where-Object { $_ } | Sort-Object -Unique)
    if ($rn.Count -eq 0) { return }
    $rc = $rn.Count; $rcx = [double]($pbGraph.Width / 2); $rcy = [double]($pbGraph.Height / 2)
    $rr = [Math]::Min($rcx, $rcy) * 0.78; $script:graphPositions = @{}
    for ($ri = 0; $ri -lt $rc; $ri++) {
        $ra = 2 * [Math]::PI * $ri / $rc - [Math]::PI / 2
        $script:graphPositions[$rn[$ri]] = @{ X = $rcx + $rr * [Math]::Cos($ra); Y = $rcy + $rr * [Math]::Sin($ra) }
    }
    $pbGraph.Invalidate()
})
$subPcapNetGraph.Controls.Add($pbGraph)
[void]$subPcapTabs.TabPages.Add($subPcapNetGraph)

# --- Tab 7: Vulnerabilities (structured table -- CRITICAL / HIGH / MEDIUM only) ---
$script:_lastPcapFindings = @()
$subPcapVuln = New-Object System.Windows.Forms.TabPage; $subPcapVuln.Text = ' Vulnerabilities '; $subPcapVuln.BackColor = [System.Drawing.Color]::FromArgb(20,15,15)
$pnlVulnHdr = New-Object System.Windows.Forms.Panel; $pnlVulnHdr.Dock = 'Top'; $pnlVulnHdr.Height = 22; $pnlVulnHdr.BackColor = [System.Drawing.Color]::FromArgb(20,15,15); $subPcapVuln.Controls.Add($pnlVulnHdr)
$lblVulnCount = New-Object System.Windows.Forms.Label; $lblVulnCount.Text = "Vulnerabilities: 0 actionable  |  run Analyse capture to populate"; $lblVulnCount.ForeColor = [System.Drawing.Color]::FromArgb(200,200,200); $lblVulnCount.Dock = 'Fill'; $pnlVulnHdr.Controls.Add($lblVulnCount)
$lvVuln = New-Object System.Windows.Forms.ListView
$lvVuln.Dock = 'Fill'; $lvVuln.View = 'Details'; $lvVuln.FullRowSelect = $true; $lvVuln.GridLines = $true
$lvVuln.BackColor = [System.Drawing.Color]::FromArgb(20,15,15); $lvVuln.ForeColor = [System.Drawing.Color]::White
$lvVuln.Font = New-Object System.Drawing.Font('Cascadia Mono', 8.5)
foreach ($__vCol in @(@('Severity',90),@('Rule ID',160),@('Title',350),@('Evidence',300),@('Fix',300))) {
    $__vc = New-Object System.Windows.Forms.ColumnHeader; $__vc.Text = $__vCol[0]; $__vc.Width = $__vCol[1]; [void]$lvVuln.Columns.Add($__vc)
}
[void]$lvVuln.Items.Add((New-Object System.Windows.Forms.ListViewItem("Run 'Analyse capture' to populate this table.")))
$subPcapVuln.Controls.Add($lvVuln); $lvVuln.BringToFront()
[void]$subPcapTabs.TabPages.Add($subPcapVuln)

$tabPcap.Controls.Add($subPcapTabs)
$subPcapTabs.BringToFront()

# ================= TAB R: Replay / IDOR / JWT =================
$tabIcptR = New-Object System.Windows.Forms.TabPage
$tabIcptR.Text = ' Replay '
$tabIcptR.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabIcptR)

$lblWarnR = New-Object System.Windows.Forms.Label
$lblWarnR.Text = "ACTIVE -- sends live HTTP requests. LAB / AUTHORIZED targets only."
$lblWarnR.ForeColor = $icptWarn
$lblWarnR.Location = New-Object System.Drawing.Point(720,24); $lblWarnR.Size = New-Object System.Drawing.Size(460,36)
$gbActive.Controls.Add($lblWarnR)
$chkGateR = New-Object System.Windows.Forms.CheckBox
$chkGateR.Text = "I am authorized -- enable active tools"
$chkGateR.ForeColor = [System.Drawing.Color]::White
$chkGateR.Location = New-Object System.Drawing.Point(720,62); $chkGateR.Size = New-Object System.Drawing.Size(418,20)
$gbActive.Controls.Add($chkGateR)

$ctlR = New-Object System.Windows.Forms.Panel
$ctlR.Dock = 'Top'; $ctlR.Height = 230; $ctlR.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$ctlR.Controls.Add($gbActive)
$tabIcptR.Controls.Add($ctlR)

$txtOutR = New-Object System.Windows.Forms.RichTextBox
$txtOutR.Dock = 'Fill'; $txtOutR.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtOutR.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtOutR.ForeColor = [System.Drawing.Color]::White
$txtOutR.ReadOnly = $true; $txtOutR.WordWrap = $false
$txtOutR.Text = "Replay / IDOR / JWT console.`r`n`r`nPaste a raw HTTP request, set the target host, and use the controls above to replay without authorization, probe for IDOR, or crack / attack JWT tokens.`r`n`r`nEach finding streams here, severity-coloured. The ''confirm'' checkbox must be checked before any live request is sent."
$tabIcptR.Controls.Add($txtOutR)
$txtOutR.BringToFront()

# ================= TAB B: Live Exploit / Creds =================
$tabIcptB = New-Object System.Windows.Forms.TabPage
$tabIcptB.Text = ' Creds '
$tabIcptB.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabIcptB)

# Authorization banner
$bannerB = New-Object System.Windows.Forms.Panel
$bannerB.Dock = 'Top'; $bannerB.Height = 50; $bannerB.BackColor = [System.Drawing.Color]::FromArgb(60,20,20)
$lblWarnB = New-Object System.Windows.Forms.Label
$lblWarnB.Text = "ACTIVE exploitation. These instrument the target, read stored credentials, and replay them against live services. LAB / AUTHORIZED targets only."
$lblWarnB.ForeColor = $icptWarn
$lblWarnB.Location = New-Object System.Drawing.Point(12,6); $lblWarnB.Size = New-Object System.Drawing.Size(1140,18)
$bannerB.Controls.Add($lblWarnB)
$chkGateB = New-Object System.Windows.Forms.CheckBox
$chkGateB.Text = "I am authorized to test this target -- enable active tools"
$chkGateB.ForeColor = [System.Drawing.Color]::White
$chkGateB.Location = New-Object System.Drawing.Point(12,26); $chkGateB.Size = New-Object System.Drawing.Size(470,22)
$bannerB.Controls.Add($chkGateB)
$tabIcptB.Controls.Add($bannerB)

# Controls panel
$ctlB = New-Object System.Windows.Forms.Panel
$ctlB.Dock = 'Top'; $ctlB.Height = 322; $ctlB.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)

# App exe row (for hook bypass)
$lblExeB = New-Object System.Windows.Forms.Label
$lblExeB.Text = "App exe (.exe to launch + hook):"; $lblExeB.ForeColor = [System.Drawing.Color]::White
$lblExeB.Location = New-Object System.Drawing.Point(12,8); $lblExeB.Size = New-Object System.Drawing.Size(320,18)
$ctlB.Controls.Add($lblExeB)
$txtExeB = New-Object System.Windows.Forms.TextBox
$txtExeB.Location = New-Object System.Drawing.Point(336,5); $txtExeB.Size = New-Object System.Drawing.Size(660,24); $txtExeB.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtExeB.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtExeB.ForeColor = [System.Drawing.Color]::White
$txtExeB.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlB.Controls.Add($txtExeB)
$btnBrowseB = New-Object System.Windows.Forms.Button
$btnBrowseB.Text = "Browse..."; $btnBrowseB.Location = New-Object System.Drawing.Point(1002,5); $btnBrowseB.Size = New-Object System.Drawing.Size(90,24)
$btnBrowseB.FlatStyle = 'Flat'; $btnBrowseB.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnBrowseB.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$btnBrowseB.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlB.Controls.Add($btnBrowseB)
$btnBrowseB.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtExeB.Text = $dlg.FileName }
})

# Native hook bypass group
$gbHook = New-Object System.Windows.Forms.GroupBox
$gbHook.Text = "Native hook bypass (frida)"; $gbHook.ForeColor = [System.Drawing.Color]::White
$gbHook.Location = New-Object System.Drawing.Point(10,36); $gbHook.Size = New-Object System.Drawing.Size(578,150)
$ctlB.Controls.Add($gbHook)
$lblHFn = New-Object System.Windows.Forms.Label; $lblHFn.Text = "Function (native export):"; $lblHFn.ForeColor = [System.Drawing.Color]::White; $lblHFn.Location = New-Object System.Drawing.Point(12,26); $lblHFn.Size = New-Object System.Drawing.Size(200,18); $gbHook.Controls.Add($lblHFn)
$txtHookFn = New-Object System.Windows.Forms.TextBox; $txtHookFn.Location = New-Object System.Drawing.Point(216,23); $txtHookFn.Size = New-Object System.Drawing.Size(200,24)
$txtHookFn.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtHookFn.ForeColor = [System.Drawing.Color]::White
$txtHookFn.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbHook.Controls.Add($txtHookFn)
$lblHMod = New-Object System.Windows.Forms.Label; $lblHMod.Text = "Module (optional):"; $lblHMod.ForeColor = [System.Drawing.Color]::White; $lblHMod.Location = New-Object System.Drawing.Point(12,54); $lblHMod.Size = New-Object System.Drawing.Size(150,18); $gbHook.Controls.Add($lblHMod)
$txtHookMod = New-Object System.Windows.Forms.TextBox; $txtHookMod.Location = New-Object System.Drawing.Point(170,51); $txtHookMod.Size = New-Object System.Drawing.Size(200,24)
$txtHookMod.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtHookMod.ForeColor = [System.Drawing.Color]::White
$txtHookMod.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbHook.Controls.Add($txtHookMod)
$lblHRet = New-Object System.Windows.Forms.Label; $lblHRet.Text = "Return value:"; $lblHRet.ForeColor = [System.Drawing.Color]::White; $lblHRet.Location = New-Object System.Drawing.Point(12,82); $lblHRet.Size = New-Object System.Drawing.Size(108,18); $gbHook.Controls.Add($lblHRet)
$numHookRet = New-Object System.Windows.Forms.NumericUpDown; $numHookRet.Location = New-Object System.Drawing.Point(122,79); $numHookRet.Size = New-Object System.Drawing.Size(70,24); $numHookRet.Minimum = 0; $numHookRet.Maximum = 2147483647; $numHookRet.Value = 1
$numHookRet.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $numHookRet.ForeColor = [System.Drawing.Color]::White; $gbHook.Controls.Add($numHookRet)
$chkHookSkip = New-Object System.Windows.Forms.CheckBox; $chkHookSkip.Text = "Skip body"; $chkHookSkip.ForeColor = [System.Drawing.Color]::White; $chkHookSkip.Location = New-Object System.Drawing.Point(196,81); $chkHookSkip.Size = New-Object System.Drawing.Size(90,20); $gbHook.Controls.Add($chkHookSkip)
$btnHookRun = New-Object System.Windows.Forms.Button; $btnHookRun.Text = "Force return (bypass check)"; $btnHookRun.Location = New-Object System.Drawing.Point(12,112); $btnHookRun.Size = New-Object System.Drawing.Size(228,28)
$btnHookRun.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnHookRun.ForeColor = [System.Drawing.Color]::White; $btnHookRun.FlatStyle = 'Flat'; $gbHook.Controls.Add($btnHookRun)
$btnHookRun.Add_Click({
    if (-not (Test-IcptGate $chkGateB $txtOutB)) { return }
    $exe = $txtExeB.Text.Trim()
    if (-not $exe) { Write-IcptLine $txtOutB "`r`n[!] Set the app exe path first.`r`n" $icptWarn; return }
    $fn = $txtHookFn.Text.Trim()
    if (-not $fn) { Write-IcptLine $txtOutB "`r`n[!] Enter a native export name to hook.`r`n" $icptWarn; return }
    $mod = $txtHookMod.Text.Trim()
    $ret = [int]$numHookRet.Value
    $skip = $chkHookSkip.Checked
    Invoke-IcptTool $txtOutB "Hook bypass: force $fn -> $ret" {
        $p = @{ Target = $exe; Function = $fn; ReturnValue = $ret; ConfirmDynamic = $true }
        if ($mod) { $p.Module = $mod }
        if ($skip) { $p.SkipBody = $true }
        Invoke-TcpkHookBypass @p
    }
})

# Windows stored credentials group
$gbCred = New-Object System.Windows.Forms.GroupBox
$gbCred.Text = "Windows stored credentials (Credential Manager)"; $gbCred.ForeColor = [System.Drawing.Color]::White
$gbCred.Location = New-Object System.Drawing.Point(598,36); $gbCred.Size = New-Object System.Drawing.Size(578,150)
$ctlB.Controls.Add($gbCred)
$lblCFilt = New-Object System.Windows.Forms.Label; $lblCFilt.Text = "Filter (optional target substring):"; $lblCFilt.ForeColor = [System.Drawing.Color]::White; $lblCFilt.Location = New-Object System.Drawing.Point(12,28); $lblCFilt.Size = New-Object System.Drawing.Size(278,18); $gbCred.Controls.Add($lblCFilt)
$txtCredFilter = New-Object System.Windows.Forms.TextBox; $txtCredFilter.Location = New-Object System.Drawing.Point(294,25); $txtCredFilter.Size = New-Object System.Drawing.Size(170,24)
$txtCredFilter.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtCredFilter.ForeColor = [System.Drawing.Color]::White
$txtCredFilter.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbCred.Controls.Add($txtCredFilter)
$chkCredReveal = New-Object System.Windows.Forms.CheckBox; $chkCredReveal.Text = "Reveal secrets (default masks)"; $chkCredReveal.ForeColor = [System.Drawing.Color]::White; $chkCredReveal.Location = New-Object System.Drawing.Point(12,54); $chkCredReveal.Size = New-Object System.Drawing.Size(260,20); $gbCred.Controls.Add($chkCredReveal)
$btnCredDump = New-Object System.Windows.Forms.Button; $btnCredDump.Text = "Dump credential vault"; $btnCredDump.Location = New-Object System.Drawing.Point(12,82); $btnCredDump.Size = New-Object System.Drawing.Size(200,28)
$btnCredDump.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnCredDump.ForeColor = [System.Drawing.Color]::White; $btnCredDump.FlatStyle = 'Flat'; $gbCred.Controls.Add($btnCredDump)
$btnCredDump.Add_Click({
    if (-not (Test-IcptGate $chkGateB $txtOutB)) { return }
    $filt = $txtCredFilter.Text.Trim()
    $rev = $chkCredReveal.Checked
    Invoke-IcptTool $txtOutB "Windows Credential Manager dump" {
        $p = @{ Confirm = $true }
        if ($filt) { $p.Filter = $filt }
        if ($rev) { $p.Reveal = $true }
        Get-TcpkStoredCredentials @p
    }
})

# Credential liveness group (wide, full row)
$gbLive = New-Object System.Windows.Forms.GroupBox
$gbLive.Text = "Credential liveness (replay a recovered credential against a live service)"; $gbLive.ForeColor = [System.Drawing.Color]::White
$gbLive.Location = New-Object System.Drawing.Point(10,192); $gbLive.Size = New-Object System.Drawing.Size(1166,118)
$ctlB.Controls.Add($gbLive)
$lblLProto = New-Object System.Windows.Forms.Label; $lblLProto.Text = "Protocol:"; $lblLProto.ForeColor = [System.Drawing.Color]::White; $lblLProto.Location = New-Object System.Drawing.Point(12,26); $lblLProto.Size = New-Object System.Drawing.Size(76,18); $gbLive.Controls.Add($lblLProto)
$cmbLiveProto = New-Object System.Windows.Forms.ComboBox; $cmbLiveProto.Location = New-Object System.Drawing.Point(92,23); $cmbLiveProto.Size = New-Object System.Drawing.Size(72,24); $cmbLiveProto.DropDownStyle = 'DropDownList'
$cmbLiveProto.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $cmbLiveProto.ForeColor = [System.Drawing.Color]::White
@('http','sql','ftp') | ForEach-Object { [void]$cmbLiveProto.Items.Add($_) }; $cmbLiveProto.SelectedIndex = 0; $gbLive.Controls.Add($cmbLiveProto)
$lblLTgt = New-Object System.Windows.Forms.Label; $lblLTgt.Text = "Target (URL / host / ftp://):"; $lblLTgt.ForeColor = [System.Drawing.Color]::White; $lblLTgt.Location = New-Object System.Drawing.Point(168,26); $lblLTgt.Size = New-Object System.Drawing.Size(230,18); $gbLive.Controls.Add($lblLTgt)
$txtLiveTarget = New-Object System.Windows.Forms.TextBox; $txtLiveTarget.Location = New-Object System.Drawing.Point(402,23); $txtLiveTarget.Size = New-Object System.Drawing.Size(740,24); $txtLiveTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLiveTarget.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtLiveTarget.ForeColor = [System.Drawing.Color]::White
$txtLiveTarget.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbLive.Controls.Add($txtLiveTarget)
$lblLUser = New-Object System.Windows.Forms.Label; $lblLUser.Text = "User:"; $lblLUser.ForeColor = [System.Drawing.Color]::White; $lblLUser.Location = New-Object System.Drawing.Point(12,56); $lblLUser.Size = New-Object System.Drawing.Size(46,18); $gbLive.Controls.Add($lblLUser)
$txtLiveUser = New-Object System.Windows.Forms.TextBox; $txtLiveUser.Location = New-Object System.Drawing.Point(62,53); $txtLiveUser.Size = New-Object System.Drawing.Size(142,24)
$txtLiveUser.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtLiveUser.ForeColor = [System.Drawing.Color]::White; $gbLive.Controls.Add($txtLiveUser)
$lblLPass = New-Object System.Windows.Forms.Label; $lblLPass.Text = "Pass:"; $lblLPass.ForeColor = [System.Drawing.Color]::White; $lblLPass.Location = New-Object System.Drawing.Point(216,56); $lblLPass.Size = New-Object System.Drawing.Size(46,18); $gbLive.Controls.Add($lblLPass)
$txtLivePass = New-Object System.Windows.Forms.TextBox; $txtLivePass.Location = New-Object System.Drawing.Point(266,53); $txtLivePass.Size = New-Object System.Drawing.Size(148,24); $txtLivePass.UseSystemPasswordChar = $true
$txtLivePass.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtLivePass.ForeColor = [System.Drawing.Color]::White; $gbLive.Controls.Add($txtLivePass)
$lblLExtra = New-Object System.Windows.Forms.Label; $lblLExtra.Text = "Bearer / DB:"; $lblLExtra.ForeColor = [System.Drawing.Color]::White; $lblLExtra.Location = New-Object System.Drawing.Point(420,56); $lblLExtra.Size = New-Object System.Drawing.Size(100,18); $gbLive.Controls.Add($lblLExtra)
$txtLiveExtra = New-Object System.Windows.Forms.TextBox; $txtLiveExtra.Location = New-Object System.Drawing.Point(524,53); $txtLiveExtra.Size = New-Object System.Drawing.Size(126,24)
$txtLiveExtra.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtLiveExtra.ForeColor = [System.Drawing.Color]::White; $gbLive.Controls.Add($txtLiveExtra)
$btnLiveRun = New-Object System.Windows.Forms.Button; $btnLiveRun.Text = "Test auth (replay)"; $btnLiveRun.Location = New-Object System.Drawing.Point(672,51); $btnLiveRun.Size = New-Object System.Drawing.Size(180,28)
$btnLiveRun.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnLiveRun.ForeColor = [System.Drawing.Color]::White; $btnLiveRun.FlatStyle = 'Flat'; $gbLive.Controls.Add($btnLiveRun)
$btnLiveRun.Add_Click({
    if (-not (Test-IcptGate $chkGateB $txtOutB)) { return }
    $proto = [string]$cmbLiveProto.SelectedItem
    $tgt = $txtLiveTarget.Text.Trim()
    if (-not $tgt) { Write-IcptLine $txtOutB "`r`n[!] Enter a target URL / host.`r`n" $icptWarn; return }
    $user = $txtLiveUser.Text.Trim()
    $pass = $txtLivePass.Text
    $extra = $txtLiveExtra.Text.Trim()
    Invoke-IcptTool $txtOutB "Credential liveness ($proto): $tgt" {
        $p = @{ Target = $tgt; Protocol = $proto; ConfirmActive = $true }
        if ($user) { $p.Username = $user }
        if ($pass) { $p.Password = $pass }
        if ($extra) { if ($proto -eq 'http') { $p.BearerToken = $extra } else { $p.Database = $extra } }
        Test-TcpkCredentialLiveness @p
    }
})
# Lay the three group boxes out to fill the width: gbHook | gbCred split the top row 50/50,
# gbLive spans the full width below. Driven on resize so it holds at any window size (fixed
# positions left a big empty band on the right of wide windows).
$layoutCtlB = {
    $gap = 10
    $w = $ctlB.ClientSize.Width
    if ($w -lt 460) { return }
    $half = [int](($w - ($gap * 3)) / 2)
    $gbHook.Left = $gap; $gbHook.Width = $half
    $gbCred.Left = ($gap * 2) + $half; $gbCred.Width = $w - $gbCred.Left - $gap
    $gbLive.Left = $gap; $gbLive.Width = $w - ($gap * 2)
}
$ctlB.Add_Resize($layoutCtlB)
& $layoutCtlB

$txtOutB = New-Object System.Windows.Forms.RichTextBox
$txtOutB.Dock = 'Fill'; $txtOutB.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtOutB.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtOutB.ForeColor = [System.Drawing.Color]::White
$txtOutB.ReadOnly = $true; $txtOutB.WordWrap = $false
$txtOutB.Text = "Live exploit + credentials console.`r`n`r`nTick the authorization box, then:`r`n  Hook bypass -- flip a native export's return value via frida (e.g. a client-side license / integrity check).`r`n  Dump credential vault -- read this user's Windows Credential Manager entries.`r`n  Credential liveness -- replay a recovered credential (e.g. one captured in Burp) against a live http / sql / ftp service to prove it authenticates.`r`n`r`nfrida must be on PATH or in tools\ for hook bypass. Findings stream here, severity-coloured.`r`n`r`n(Tip: drag the divider above this console up to give the output more room.)"
# Draggable splitter: controls (top) + output console (bottom). Drag the divider to size the
# output. Panel1 auto-scrolls, so the controls stay reachable even when dragged small.
$splitB = New-Object System.Windows.Forms.SplitContainer
$splitB.Dock = 'Fill'; $splitB.Orientation = 'Horizontal'; $splitB.SplitterWidth = 6
$splitB.BackColor = [System.Drawing.Color]::FromArgb(50,50,50)
$splitB.Panel1MinSize = 48; $splitB.Panel2MinSize = 80; $splitB.Panel1.AutoScroll = $true
$splitB.Panel1.Controls.Add($ctlB)
$splitB.Panel2.Controls.Add($txtOutB)
$tabIcptB.Controls.Add($splitB)
# Set the initial divider once the tab is realised (322 = controls fit exactly; less on a short
# window). Runs once, as soon as the split has a usable height.
$script:splitBInit = $false
$splitB.Add_SizeChanged({
    if ($script:splitBInit) { return }
    $h = $splitB.Height
    if ($h -gt 200) {
        $d = [Math]::Min(322, $h - $splitB.SplitterWidth - $splitB.Panel2MinSize - 4)
        if ($d -ge $splitB.Panel1MinSize) { try { $splitB.SplitterDistance = $d; $script:splitBInit = $true } catch {} }
    }
})

# ================= TAB: Runtime / Live (live-process analysis) =================
# Surfaces the read-only Runtime\ checks (E-series) that were CLI-only. Every button
# drives one Test-Tcpk* cmdlet against a running process (or the target path / system),
# streaming its findings into the console. Values are baked into each click handler via
# [scriptblock]::Create so there are no loop-closure pitfalls. The gated ACTIVE tools (moved
# here from the old Exploit toolbar) also live in this switch; they require the local
# authorization tick (Test-IcptGate $chkRtGate) + Enable-TcpkExploit before they run.
Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
function Invoke-RtCheck([string]$fn, [string]$kind) {
    # Run All clears ONCE at the start, then accumulates its own sequence. It re-enters this
    # function per check, so without the RtInRunAll guard each inner call would clear again
    # and the pane would end up holding only the final check.
    if ($kind -eq 'run-all') {
        if ($chkRtClearRun.Checked) { try { $txtRt.Clear() } catch { } }
        $script:IcptClearNext = $false
    } elseif ($script:RtInRunAll) {
        $script:IcptClearNext = $false
    } else {
        $script:IcptClearNext = [bool]$chkRtClearRun.Checked
    }
    switch ($kind) {
        'proc' {
            $p = $txtRtProc.Text.Trim()
            if (-not $p) { Write-IcptLine $txtRt "`r`n[!] Enter a process name (Refresh to list running).`r`n" $icptWarn; return }
            $pe = $p -replace "'", "''"
            Invoke-IcptTool $txtRt "$fn -ProcessName $p" ([scriptblock]::Create("$fn -ProcessName '$pe'"))
        }
        'trace' {
            $p = $txtRtProc.Text.Trim()
            if (-not $p) { Write-IcptLine $txtRt "`r`n[!] Enter a process name first.`r`n" $icptWarn; return }
            $pe = $p -replace "'", "''"; $sec = [int]$numRtSec.Value
            Write-IcptLine $txtRt "`r`n(capturing for ${sec}s -- exercise the app now; needs admin)`r`n" ([System.Drawing.Color]::FromArgb(214,137,16))
            Invoke-IcptTool $txtRt "$fn -ProcessName $p -Seconds $sec" ([scriptblock]::Create("try{Enable-TcpkExploit -Acknowledge|Out-Null}catch{}; $fn -ProcessName '$pe' -Seconds $sec"))
        }
        'sys'  { Invoke-IcptTool $txtRt "$fn (system-wide)" ([scriptblock]::Create($fn)) }
        'path' {
            $t = $txtTarget.Text.Trim()
            if (-not $t) { Write-IcptLine $txtRt "`r`n[!] Set the Target (install folder) box at the top first.`r`n" $icptWarn; return }
            $te = $t -replace "'", "''"
            Invoke-IcptTool $txtRt "$fn -Path $t" ([scriptblock]::Create("$fn -Path '$te'"))
        }
        # Read-only live memory secret scan (capped at 48 MB, as the old toolbar did).
        'mem' {
            $p = $txtRtProc.Text.Trim()
            if (-not $p) { Write-IcptLine $txtRt "`r`n[!] Enter a process name first.`r`n" $icptWarn; return }
            $pe = $p -replace "'", "''"
            Invoke-IcptTool $txtRt "Mem Secrets: $p" ([scriptblock]::Create("Test-TcpkMemorySecrets -ProcessName '$pe' -MaxScanMB 48"))
        }
        'clipboard' {
            $sec = [int]$numRtSec.Value
            $p = $txtRtProc.Text.Trim()
            $pe = if ($p) { " -ProcessName '$($p -replace "'", "''")'" } else { '' }
            Write-IcptLine $txtRt "`r`n(monitoring clipboard for ${sec}s -- exercise the app now)`r`n" ([System.Drawing.Color]::FromArgb(0,188,212))
            Invoke-IcptTool $txtRt "Clipboard monitor ${sec}s$pe" ([scriptblock]::Create("Test-TcpkClipboardSecrets -DurationSec $sec$pe"))
        }
        # --- gated ACTIVE tools (need the authorization tick + Enable-TcpkExploit) ---
        'gui-unlock' {
            if (-not (Test-IcptGate $chkRtGate $txtRt)) { return }
            $p = $txtRtProc.Text.Trim()
            if (-not $p) { Write-IcptLine $txtRt "`r`n[!] Enter a process name first.`r`n" $icptWarn; return }
            $pe = $p -replace "'", "''"
            Invoke-IcptTool $txtRt "GUI unlock (dry-run): $p" ([scriptblock]::Create("Invoke-TcpkGuiUnlock -ProcessName '$pe'"))
        }
        'pipe-probe' {
            if (-not (Test-IcptGate $chkRtGate $txtRt)) { return }
            $pn = [Microsoft.VisualBasic.Interaction]::InputBox('Pipe name (no \\.\pipe\ prefix):', 'TCPK Pipe Probe', '')
            if (-not $pn) { return }
            $pne = $pn -replace "'", "''"
            Invoke-IcptTool $txtRt "Pipe probe: $pn" ([scriptblock]::Create("Invoke-TcpkPipeProbe -PipeName '$pne'"))
        }
        'flag-flip' {
            if (-not (Test-IcptGate $chkRtGate $txtRt)) { return }
            $p = $txtRtProc.Text.Trim()
            if (-not $p) { Write-IcptLine $txtRt "`r`n[!] Enter a process name first.`r`n" $icptWarn; return }
            $pat = [Microsoft.VisualBasic.Interaction]::InputBox('ASCII/byte pattern to locate (DRY-RUN, no write):', 'TCPK Memory Flag-Flip', '')
            if (-not $pat) { return }
            $pe = $p -replace "'", "''"; $pate = $pat -replace "'", "''"
            Invoke-IcptTool $txtRt "Flag-flip dry-run: $pat" ([scriptblock]::Create("Invoke-TcpkMemoryFlagFlip -ProcessName '$pe' -Pattern '$pate' -NewBytesHex '01'"))
        }
        'input-fuzz' {
            Write-IcptLine $txtRt "`r`n== Input fuzz (intrusive -- run from a console; it launches the target repeatedly) ==`r`n" ([System.Drawing.Color]::FromArgb(102,217,239))
            Write-IcptLine $txtRt "Enable-TcpkExploit -Acknowledge`r`nInvoke-TcpkInputFuzz -TargetExe '<app.exe>' -SeedFile '<sample.ext>' -ArgTemplate '{FUZZ}' -Iterations 25`r`n" ([System.Drawing.Color]::White)
        }
        'run-all' {
            # Set for the whole sequence so the re-entrant calls above do not each clear.
            $script:RtInRunAll = $true
            try {
                foreach ($rs in $script:RtSpecs) {
                    if ($rs.K -in @('gui-unlock','pipe-probe','flag-flip','input-fuzz','clipboard')) { continue }
                    Invoke-RtCheck $rs.Fn $rs.K
                    [System.Windows.Forms.Application]::DoEvents()
                }
            } finally { $script:RtInRunAll = $false }
        }
    }
}

$tabRt = New-Object System.Windows.Forms.TabPage
$tabRt.Text = ' Runtime '
$tabRt.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabRt)

# Process-selector row (Dock=Top) -- dark themed
$rtTop = New-Object System.Windows.Forms.Panel
$rtTop.Dock = 'Top'; $rtTop.Height = 182; $rtTop.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$lblRtProc = New-Object System.Windows.Forms.Label
$lblRtProc.Text = "Process:"; $lblRtProc.ForeColor = [System.Drawing.Color]::White
$lblRtProc.Location = New-Object System.Drawing.Point(12,10); $lblRtProc.Size = New-Object System.Drawing.Size(68,18)
$rtTop.Controls.Add($lblRtProc)
$txtRtProc = New-Object System.Windows.Forms.ComboBox
$txtRtProc.Location = New-Object System.Drawing.Point(82,7); $txtRtProc.Size = New-Object System.Drawing.Size(210,24); $txtRtProc.DropDownStyle = 'DropDown'
$txtRtProc.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $txtRtProc.ForeColor = [System.Drawing.Color]::White
$rtTop.Controls.Add($txtRtProc)
$btnRtRefresh = New-Object System.Windows.Forms.Button
$btnRtRefresh.Text = "Refresh"; $btnRtRefresh.Location = New-Object System.Drawing.Point(296,6); $btnRtRefresh.Size = New-Object System.Drawing.Size(74,26)
$btnRtRefresh.FlatStyle = 'Flat'; $btnRtRefresh.BackColor = [System.Drawing.Color]::FromArgb(40,116,166); $btnRtRefresh.ForeColor = [System.Drawing.Color]::White
$rtTop.Controls.Add($btnRtRefresh)
$btnRtRefresh.Add_Click({
    $sel = $txtRtProc.Text
    $txtRtProc.Items.Clear()
    try { Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique | Sort-Object | ForEach-Object { [void]$txtRtProc.Items.Add($_) } } catch {}
    if ($sel) { $txtRtProc.Text = $sel }
})
$lblRtSec = New-Object System.Windows.Forms.Label
$lblRtSec.Text = "Trace (s):"; $lblRtSec.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$lblRtSec.Location = New-Object System.Drawing.Point(384,10); $lblRtSec.Size = New-Object System.Drawing.Size(84,18)
$rtTop.Controls.Add($lblRtSec)
$numRtSec = New-Object System.Windows.Forms.NumericUpDown
$numRtSec.Location = New-Object System.Drawing.Point(470,7); $numRtSec.Size = New-Object System.Drawing.Size(54,24); $numRtSec.Minimum = 5; $numRtSec.Maximum = 300; $numRtSec.Value = 30
$numRtSec.BackColor = [System.Drawing.Color]::FromArgb(45,45,48); $numRtSec.ForeColor = [System.Drawing.Color]::White
$rtTop.Controls.Add($numRtSec)
$lblRtHint = New-Object System.Windows.Forms.Label
$lblRtHint.Text = "Grey=process  Amber=trace  Blue=system  Green=target-path  Teal=clipboard  Red=gated"
$lblRtHint.Location = New-Object System.Drawing.Point(528,10); $lblRtHint.Size = New-Object System.Drawing.Size(660,18)
$lblRtHint.ForeColor = [System.Drawing.Color]::FromArgb(120,130,140)
$lblRtHint.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$rtTop.Controls.Add($lblRtHint)
$chkRtGate = New-Object System.Windows.Forms.CheckBox
$chkRtGate.Text = "I am authorized -- enable gated tools (red buttons)"
$chkRtGate.ForeColor = [System.Drawing.Color]::FromArgb(255,180,180)
$chkRtGate.Location = New-Object System.Drawing.Point(12,40); $chkRtGate.Size = New-Object System.Drawing.Size(420,20)
$rtTop.Controls.Add($chkRtGate)
$btnRtRunAll = New-Object System.Windows.Forms.Button
$btnRtRunAll.Text = "Run All"; $btnRtRunAll.Location = New-Object System.Drawing.Point(434,37); $btnRtRunAll.Size = New-Object System.Drawing.Size(80,26)
$btnRtRunAll.FlatStyle = 'Flat'; $btnRtRunAll.BackColor = [System.Drawing.Color]::FromArgb(40,116,166); $btnRtRunAll.ForeColor = [System.Drawing.Color]::White
$btnRtRunAll.Add_Click({ Invoke-RtCheck '' 'run-all' })
$rtTop.Controls.Add($btnRtRunAll)
# Default ON. Repeated clicks used to append forever -- four identical GuiInspector blocks
# in one pane with nothing to separate them. Untick to accumulate deliberately, e.g. when
# comparing two checks side by side; the timestamped header keeps runs distinguishable
# either way.
$chkRtClearRun = New-Object System.Windows.Forms.CheckBox
$chkRtClearRun.Text = "Clear on run"
$chkRtClearRun.Checked = $true
$chkRtClearRun.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$chkRtClearRun.Location = New-Object System.Drawing.Point(652,40); $chkRtClearRun.Size = New-Object System.Drawing.Size(114,20)
$rtTop.Controls.Add($chkRtClearRun)

$btnRtCopy = New-Object System.Windows.Forms.Button
$btnRtCopy.Text = "Copy"; $btnRtCopy.Location = New-Object System.Drawing.Point(518,37); $btnRtCopy.Size = New-Object System.Drawing.Size(64,26)
$btnRtCopy.FlatStyle = 'Flat'; $btnRtCopy.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnRtCopy.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$btnRtCopy.Add_Click({
    if ($txtRt.Text.Length -gt 0) { [System.Windows.Forms.Clipboard]::SetText($txtRt.Text); Update-Status "Output copied to clipboard." }
    else { Update-Status "Nothing to copy." }
})
$rtTop.Controls.Add($btnRtCopy)
$btnRtClear = New-Object System.Windows.Forms.Button
$btnRtClear.Text = "Clear"; $btnRtClear.Location = New-Object System.Drawing.Point(586,37); $btnRtClear.Size = New-Object System.Drawing.Size(64,26)
$btnRtClear.FlatStyle = 'Flat'; $btnRtClear.BackColor = [System.Drawing.Color]::FromArgb(60,60,60); $btnRtClear.ForeColor = [System.Drawing.Color]::FromArgb(180,185,190)
$rtTop.Controls.Add($btnRtClear)

# Button grid -- category-coloured, placed directly in the rtTop panel below the process row.
$rtColour = @{
    proc         = [System.Drawing.Color]::FromArgb(55,55,60)
    mem          = [System.Drawing.Color]::FromArgb(55,55,60)
    trace        = [System.Drawing.Color]::FromArgb(70,55,25)
    sys          = [System.Drawing.Color]::FromArgb(35,55,70)
    path         = [System.Drawing.Color]::FromArgb(35,60,40)
    'gui-unlock' = [System.Drawing.Color]::FromArgb(70,30,30)
    'pipe-probe' = [System.Drawing.Color]::FromArgb(70,30,30)
    'flag-flip'  = [System.Drawing.Color]::FromArgb(70,30,30)
    'input-fuzz' = [System.Drawing.Color]::FromArgb(70,30,30)
    clipboard    = [System.Drawing.Color]::FromArgb(25,65,65)
}
$script:RtSpecs = @(
    @{ T='Loaded Modules';    Fn='Test-TcpkLoadedModulePaths';      K='proc' }
    @{ T='Module Signatures'; Fn='Test-TcpkLoadedModuleSignatures'; K='proc' }
    @{ T='Listening Ports';   Fn='Test-TcpkListeningPorts';         K='proc' }
    @{ T='Process Token';     Fn='Test-TcpkProcessToken';           K='proc' }
    @{ T='Mitigations';       Fn='Test-TcpkProcessMitigations';     K='proc' }
    @{ T='Process DACL';      Fn='Test-TcpkProcessDacl';            K='proc' }
    @{ T='Env Secrets';       Fn='Test-TcpkProcessEnvSecrets';      K='proc' }
    @{ T='Mem Secrets';       Fn='';                                K='mem' }
    @{ T='Child Procs';       Fn='Test-TcpkChildProcesses';         K='proc' }
    @{ T='Handles';           Fn='Test-TcpkHandleEnumeration';      K='proc' }
    @{ T='Windows';           Fn='Test-TcpkWindowEnumeration';      K='proc' }
    @{ T='GUI Inspector';     Fn='Test-TcpkGuiInspector';           K='proc' }
    @{ T='Memory Dump';       Fn='Test-TcpkMemoryDump';             K='proc' }
    @{ T='DLL Hijack Trace';  Fn='Test-TcpkDllSearchTrace';         K='trace' }
    @{ T='Named Pipes';       Fn='Test-TcpkNamedPipes';             K='sys' }
    @{ T='Pipe DACLs';        Fn='Test-TcpkNamedPipeDacl';          K='sys' }
    @{ T='ALPC / Mailslots';  Fn='Test-TcpkMailslotsAlpc';          K='sys' }
    @{ T='COM Objects';       Fn='Test-TcpkComObjects';             K='path' }
    @{ T='Named Objects';     Fn='Test-TcpkNamedObjects';           K='path' }
    @{ T='RPC Surface';       Fn='Test-TcpkRpcSurface';             K='path' }
    @{ T='Win Messages';     Fn='Test-TcpkWindowMessages';         K='proc' }
    @{ T='Shared Mem';       Fn='Test-TcpkSharedMemoryDacl';       K='proc' }
    @{ T='Memory Regions';   Fn='Test-TcpkMemoryRegions';          K='proc' }
    @{ T='Thread DACLs';     Fn='Test-TcpkThreadDacl';             K='proc' }
    @{ T='Token DACL';       Fn='Test-TcpkTokenDacl';              K='proc' }
    @{ T='Virtualization';   Fn='Test-TcpkProcessVirtualization';  K='proc' }
    @{ T='Handle DACLs';     Fn='Test-TcpkHandleDacl';             K='proc' }
    @{ T='Thread Start';     Fn='Test-TcpkThreadStart';            K='proc' }
    @{ T='Service DLL';      Fn='Test-TcpkServiceDll';             K='path' }
    @{ T='AppInit DLLs';     Fn='Test-TcpkAppInitDlls';            K='path' }
    @{ T='Load Points';      Fn='Test-TcpkRegistryLoadPoints';     K='path' }
    @{ T='Installer DLL';    Fn='Test-TcpkInstallerPlanting';      K='path' }
    @{ T='JNI Native';       Fn='Test-TcpkJavaNativeLoad';         K='path' }
    @{ T='Clipboard';        Fn='';                                K='clipboard' }
    @{ T='GUI Unlock';        Fn='';                                K='gui-unlock' }
    @{ T='Pipe Probe';        Fn='';                                K='pipe-probe' }
    @{ T='Flag-Flip';         Fn='';                                K='flag-flip' }
    @{ T='Input Fuzz...';     Fn='';                                K='input-fuzz' }
)
$rx = 10; $ry = 72; $rcol = 0
foreach ($s in $script:RtSpecs) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $s.T; $b.Size = New-Object System.Drawing.Size(140,30)
    $b.Location = New-Object System.Drawing.Point($rx,$ry)
    $b.BackColor = $rtColour[$s.K]; $b.ForeColor = [System.Drawing.Color]::White; $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80,80,85)
    $b.Add_Click([scriptblock]::Create("Invoke-RtCheck '$($s.Fn)' '$($s.K)'"))
    $rtTop.Controls.Add($b)
    $rcol++
    if ($rcol -ge 9) { $rcol = 0; $rx = 10; $ry += 36 } else { $rx += 146 }
}
$tabRt.Controls.Add($rtTop)

$txtRt = New-Object System.Windows.Forms.RichTextBox
$txtRt.Dock = 'Fill'; $txtRt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtRt.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtRt.ForeColor = [System.Drawing.Color]::White
$txtRt.ReadOnly = $true; $txtRt.WordWrap = $false
$txtRt.Text = "Runtime checks -- pick a process (Refresh), click a button.`r`nGrey = process  Amber = trace (ETW, needs admin)  Blue = system  Green = target-path  Teal = clipboard  Red = gated`r`nRun All = all non-gated/non-timed checks in sequence.  Findings stream here, severity-coloured.`r`n"
$tabRt.Controls.Add($txtRt)
$txtRt.BringToFront()
$btnRtClear.Add_Click({
    $txtRt.Clear()
    $txtRt.SelectionColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
    $txtRt.AppendText("(output cleared)`r`n")
})

# ================= TAB: Asar (unpack + browse an Electron app.asar) =================
# Self-contained: parses the app.asar layout ([u32@0=4][u32@4=headerSize][u32@8][u32@12=jsonSize]
# [json][data]) and extracts each file (data[base+offset .. +size], base = 8 + headerSize) to a
# temp folder so the operator can read the JavaScript source. Discovery-only: files are read,
# never executed. Mirrors the agentic workbench's Asar tab.
$script:AsarFiles = @(); $script:AsarLastFull = ''
function Expand-GuiAsar([string]$target) {
    if (-not $target) { return @{ error = 'set a target (install folder or app.asar) first' } }
    if (-not (Test-Path -LiteralPath $target)) { return @{ error = 'target not found' } }
    $dir = if (Test-Path -LiteralPath $target -PathType Container) { $target } else { Split-Path -Parent $target }
    $asar = Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $asar) { return @{ error = 'no .asar found under the target (not an Electron app?)' } }
    # NO SIZE CAP. Only the header must be resident; entries are read by seeking, so peak
    # memory is the largest single entry rather than the whole archive.
    $asarLen = $asar.Length
    $fsA = $null
    try {
        $fsA = [System.IO.FileStream]::new($asar.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
               ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        if ($asarLen -lt 16) { return @{ error = 'asar invalid' } }
        $hdr = New-Object byte[] 16
        if ($fsA.Read($hdr, 0, 16) -lt 16) { return @{ error = 'asar invalid' } }
        $headerObjSize = [System.BitConverter]::ToUInt32($hdr, 4)
        $jsonSize = [System.BitConverter]::ToUInt32($hdr, 12)
        if (($jsonSize + 16) -gt $asarLen) { return @{ error = 'asar header invalid' } }
        $jb = New-Object byte[] ([int]$jsonSize)
        $jr = 0
        while ($jr -lt [int]$jsonSize) {
            $rr = $fsA.Read($jb, $jr, [int]$jsonSize - $jr)
            if ($rr -le 0) { break }
            $jr += $rr
        }
        if ($jr -lt [int]$jsonSize) { return @{ error = 'asar header truncated' } }
        $tree = [System.Text.Encoding]::UTF8.GetString($jb, 0, [int]$jsonSize) | ConvertFrom-Json
        $base = 8 + $headerObjSize
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-asar-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $rootFull = [System.IO.Path]::GetFullPath($outDir)
        $files = New-Object System.Collections.Generic.List[object]
        $stack = New-Object System.Collections.Generic.Stack[object]
        $stack.Push([pscustomobject]@{ node = $tree; rel = '' })
        $total = [int64]0; $cap = [int64]200MB
        $skippedBudget = 0; $skippedLimit = 0; $skippedSlip = 0
        while ($stack.Count) {
            $cur = $stack.Pop()
            if (-not $cur.node.files) { continue }
            foreach ($prop in $cur.node.files.PSObject.Properties) {
                $child = $prop.Value
                $childRel = if ($cur.rel) { "$($cur.rel)/$($prop.Name)" } else { "$($prop.Name)" }
                if ($child.files) { $stack.Push([pscustomobject]@{ node = $child; rel = $childRel }); continue }
                if ($null -eq $child.offset) { continue }
                $sz = [int64]$child.size; $off = $base + [int64]$child.offset
                if ($sz -lt 0 -or ($off + $sz) -gt $asarLen) { continue }
                if (($total + $sz) -gt $cap) { $skippedBudget++; continue }
                if ($files.Count -ge 8000) { $skippedLimit++; continue }
                $dest = Join-Path $outDir ($childRel -replace '/', '\')
                # zip-slip guard: a malicious asar entry name ('../') must not escape the
                # extract root. Expand-TcpkAsar and the web workbench both had this; this
                # copy did not, so a crafted archive could write anywhere the user can.
                $destFull = [System.IO.Path]::GetFullPath($dest)
                if (-not $destFull.StartsWith($rootFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { $skippedSlip++; continue }
                $ddir = Split-Path -Parent $dest
                if ($ddir -and -not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                $buf = New-Object 'byte[]' $sz
                if ($sz -gt 0) {
                    $fsA.Position = $off
                    $bread = 0
                    while ($bread -lt $sz) {
                        $rr = $fsA.Read($buf, $bread, [int][Math]::Min([int]::MaxValue, $sz - $bread))
                        if ($rr -le 0) { break }
                        $bread += $rr
                    }
                    if ($bread -lt $sz) { continue }
                }
                [System.IO.File]::WriteAllBytes($dest, $buf)
                $files.Add([pscustomobject]@{ path = $childRel; size = $sz; full = $dest })
                $total += $sz
            }
        }
        $notes = @()
        if ($skippedBudget) { $notes += "$skippedBudget entr(ies) skipped (200 MB extraction budget)" }
        if ($skippedLimit)  { $notes += "$skippedLimit entr(ies) skipped (8000-file limit)" }
        if ($skippedSlip)   { $notes += "$skippedSlip entr(ies) REFUSED: path escapes the extract root (zip-slip)" }
        return @{ outDir = $outDir; bytes = $total; truncated = ($notes -join '; '); files = @($files.ToArray() | Sort-Object path) }
    } catch { return @{ error = "$($_.Exception.Message)" } }
    finally { if ($fsA) { $fsA.Dispose() } }
}
function Fill-AsarList {
    $q = $txtAsarFilter.Text.Trim().ToLower()
    $lstAsar.BeginUpdate(); $lstAsar.Items.Clear()
    $n = 0
    foreach ($f in $script:AsarFiles) {
        if ($q -and $f.path.ToLower().IndexOf($q) -lt 0) { continue }
        [void]$lstAsar.Items.Add($f); $n++
        if ($n -ge 2500) { break }
    }
    $lstAsar.EndUpdate()
}

$tabAsar = New-Object System.Windows.Forms.TabPage
$tabAsar.Text = ' Asar '
$tabAsar.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabAsar)

# Top bar built from TableLayoutPanel rows so the path box stretches and the buttons stay
# right-aligned at ANY window width (absolute positions left a dead gap when maximized).
$asarTop = New-Object System.Windows.Forms.Panel
$asarTop.Dock = 'Top'; $asarTop.Height = 70; $asarTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$asarAnchLR = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

$asarRow1 = New-Object System.Windows.Forms.TableLayoutPanel
$asarRow1.Dock = 'Top'; $asarRow1.Height = 40; $asarRow1.ColumnCount = 6; $asarRow1.RowCount = 1; $asarRow1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 164)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 100)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 108)))

$lblAsarT = New-Object System.Windows.Forms.Label
$lblAsarT.Text = "app.asar / install folder:"; $lblAsarT.Dock = 'Fill'; $lblAsarT.TextAlign = 'MiddleLeft'
$lblAsarT.ForeColor = [System.Drawing.Color]::White
$lblAsarT.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$asarRow1.Controls.Add($lblAsarT, 0, 0)

$txtAsarTarget = New-Object System.Windows.Forms.TextBox
$txtAsarTarget.Anchor = $asarAnchLR; $txtAsarTarget.Margin = New-Object System.Windows.Forms.Padding(2, 8, 6, 0)
$txtAsarTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtAsarTarget.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtAsarTarget.ForeColor = [System.Drawing.Color]::White
$asarRow1.Controls.Add($txtAsarTarget, 1, 0)

$btnAsarBrowse = New-Object System.Windows.Forms.Button
$btnAsarBrowse.Text = "Browse..."; $btnAsarBrowse.Dock = 'Fill'; $btnAsarBrowse.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$btnAsarBrowse.FlatStyle = 'Flat'; $btnAsarBrowse.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnAsarBrowse.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$asarRow1.Controls.Add($btnAsarBrowse, 2, 0)

$btnAsarExtract = New-Object System.Windows.Forms.Button
$btnAsarExtract.Text = "Extract"; $btnAsarExtract.Dock = 'Fill'; $btnAsarExtract.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$btnAsarExtract.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnAsarExtract.ForeColor = [System.Drawing.Color]::White; $btnAsarExtract.FlatStyle = 'Flat'
$btnAsarExtract.Tag = 'keep'
$asarRow1.Controls.Add($btnAsarExtract, 3, 0)

$btnAsarHex = New-Object System.Windows.Forms.Button
$btnAsarHex.Text = "Hex view"; $btnAsarHex.Dock = 'Fill'; $btnAsarHex.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$btnAsarHex.FlatStyle = 'Flat'; $btnAsarHex.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnAsarHex.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$asarRow1.Controls.Add($btnAsarHex, 4, 0)

# npm supply-chain audit of the bundled Electron packages (OSV CVEs + deprecated flags).
$btnAsarNpm = New-Object System.Windows.Forms.Button
$btnAsarNpm.Text = "npm audit"; $btnAsarNpm.Dock = 'Fill'; $btnAsarNpm.Margin = New-Object System.Windows.Forms.Padding(2, 6, 8, 6)
$btnAsarNpm.BackColor = [System.Drawing.Color]::FromArgb(23, 111, 130); $btnAsarNpm.ForeColor = [System.Drawing.Color]::White; $btnAsarNpm.FlatStyle = 'Flat'
$asarRow1.Controls.Add($btnAsarNpm, 5, 0)

$asarRow2 = New-Object System.Windows.Forms.Panel
$asarRow2.Dock = 'Top'; $asarRow2.Height = 26; $asarRow2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblAsar = New-Object System.Windows.Forms.Label
$lblAsar.Dock = 'Fill'; $lblAsar.TextAlign = 'MiddleLeft'
$lblAsar.Padding = New-Object System.Windows.Forms.Padding(10, 0, 10, 0)
$lblAsar.Text = "Pick a target, then Extract (a large app can take ~30s). Click a file to read its source; Hex view opens it in the Hex tab. npm audit checks the bundled packages for CVEs + deprecations."
$lblAsar.ForeColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
$asarRow2.Controls.Add($lblAsar)

# add row2 first, then row1, so row1 (path + buttons) docks ABOVE the hint line
$asarTop.Controls.Add($asarRow2)
$asarTop.Controls.Add($asarRow1)
$tabAsar.Controls.Add($asarTop)

# Body: left panel (filter + file list, fixed 430 wide) docked Left; source viewer fills the rest.
$asarLeft = New-Object System.Windows.Forms.Panel
$asarLeft.Dock = 'Left'; $asarLeft.Width = 430; $asarLeft.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$asarFilterRow = New-Object System.Windows.Forms.Panel
$asarFilterRow.Dock = 'Top'; $asarFilterRow.Height = 46; $asarFilterRow.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$asarPrompt = New-Object System.Windows.Forms.Label
$asarPrompt.Text = "filter files:"; $asarPrompt.Location = New-Object System.Drawing.Point(6, 5); $asarPrompt.Size = New-Object System.Drawing.Size(120, 16)
$asarPrompt.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$asarFilterRow.Controls.Add($asarPrompt)
$txtAsarFilter = New-Object System.Windows.Forms.TextBox
$txtAsarFilter.Location = New-Object System.Drawing.Point(6, 22); $txtAsarFilter.Size = New-Object System.Drawing.Size(416, 22); $txtAsarFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtAsarFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtAsarFilter.ForeColor = [System.Drawing.Color]::White; $txtAsarFilter.BorderStyle = 'FixedSingle'
# Top|Left only: the left panel is a fixed 430 wide, so a Right anchor gave no benefit and
# instead let the box stretch to a transient wider parent during layout (it ballooned to ~646px
# and spilled past the 430 panel into the source viewer). A static width stays contained.
$txtAsarFilter.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
$asarFilterRow.Controls.Add($txtAsarFilter)
$asarLeft.Controls.Add($asarFilterRow)
$lstAsar = New-Object System.Windows.Forms.ListBox
$lstAsar.Dock = 'Fill'; $lstAsar.Font = New-Object System.Drawing.Font('Consolas', 8.5); $lstAsar.DisplayMember = 'path'; $lstAsar.IntegralHeight = $false
$lstAsar.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $lstAsar.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lstAsar.BorderStyle = 'None'
$asarLeft.Controls.Add($lstAsar); $lstAsar.BringToFront()
# Nest the Left list + Fill viewer inside a Dock=Fill body panel so the Top strip above spans
# the FULL width. A Dock=Left panel placed directly on the tab steals the full height and
# pushes the top row (app.asar path + buttons) into the top-right corner.
$asarBody = New-Object System.Windows.Forms.Panel
$asarBody.Dock = 'Fill'
$asarBody.Controls.Add($asarLeft)
$txtAsarView = New-Object System.Windows.Forms.RichTextBox
$txtAsarView.Dock = 'Fill'; $txtAsarView.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtAsarView.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $txtAsarView.ForeColor = [System.Drawing.Color]::White
$txtAsarView.ReadOnly = $true; $txtAsarView.WordWrap = $false; $txtAsarView.BorderStyle = 'None'
$txtAsarView.Text = "Extract an app.asar, then click a file on the left to read its JavaScript source here."
$asarBody.Controls.Add($txtAsarView); $txtAsarView.BringToFront()
$tabAsar.Controls.Add($asarBody); $asarBody.BringToFront()

$btnAsarBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Electron archive / any (*.asar;*.*)|*.asar;*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtAsarTarget.Text = $dlg.FileName }
})
$btnAsarExtract.Add_Click({
    $t = $txtAsarTarget.Text.Trim(); if (-not $t) { $t = $txtTarget.Text.Trim() }
    $lblAsar.Text = "Extracting app.asar (a large app can take ~30s -- the window pauses)..."
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $script:AsarFiles = @(); $lstAsar.Items.Clear()
    $res = Expand-GuiAsar $t
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    if ($res.error) { $lblAsar.Text = "Error: $($res.error)"; return }
    $script:AsarFiles = @($res.files)
    $lblAsar.Text = "$(@($res.files).Count) files ($([int]($res.bytes/1KB)) KB) unpacked to $($res.outDir)"
    Fill-AsarList
})
$btnAsarNpm.Add_Click({
    $t = $txtAsarTarget.Text.Trim(); if (-not $t) { $t = $txtTarget.Text.Trim() }
    if (-not $t) { $lblAsar.Text = "Pick an app.asar or install folder first."; return }
    if (-not (Test-Path -LiteralPath $t)) { $lblAsar.Text = "Not found: $t"; return }
    $lblAsar.Text = "npm audit: scanning bundled packages, querying OSV + npm registry (the window pauses)..."
    $txtAsarView.Text = "Running npm supply-chain audit -- this queries the network and can take a moment..."
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    try {
        $mod = @(Get-Module TCPK)[0]
        $out = & $mod {
            param($p, $n)
            $r = Get-TcpkAsarNpmAudit -Path $p
            [pscustomobject]@{
                report = (Format-TcpkNpmAuditReport -Result $r -TargetName $n)
                pkgs   = [int]$r.packages
                vulns  = @($r.vulns).Count
                dep    = @($r.deprecated).Count
                blind  = "$($r.blindspot)"
                unver  = [int]$r.unverified
                ver    = [int]$r.verifiedPackages
                capped = [bool]$r.inventoryCapped
            }
        } $t (Split-Path -Leaf $t)
        $txtAsarView.Text = "$($out.report)"
        $txtAsarView.SelectionStart = 0; $txtAsarView.ScrollToCaret()
        # "0 vulnerabilities" on a bundled app means the packages were never queried, not
        # that they are clean. The status line has to say so, because it is the one line
        # a user reads before deciding the app is fine.
        $atLeast = if ($out.capped) { 'at least ' } else { '' }
        if ($out.blind) {
            # $out.ver, not $out.pkgs: pkgs includes lockfile declarations, so using it here
            # would claim more was recovered from the shipped files than actually was.
            $extra = if ($out.unver -gt 0) { " $($out.unver) more are lockfile declarations, presence not verified." } else { '' }
            $lblAsar.Text = "npm audit INCOMPLETE: only $($out.ver) package(s) recoverable from shipped files (app is bundled).$extra $($out.vulns) vulns found, but most packages were never queried -- see report."
        } elseif ($out.unver -gt 0) {
            $lblAsar.Text = "npm audit done: $atLeast$($out.pkgs) packages ($($out.unver) from lockfile, presence not verified), $($out.vulns) vulnerabilities, $($out.dep) deprecated."
        } else {
            $lblAsar.Text = "npm audit done: $atLeast$($out.pkgs) packages, $($out.vulns) vulnerabilities, $($out.dep) deprecated."
        }
    } catch {
        $txtAsarView.Text = "npm audit failed: $($_.Exception.Message)"
        $lblAsar.Text = "npm audit failed."
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})
$txtAsarFilter.Add_TextChanged({ Fill-AsarList })
$lstAsar.Add_SelectedIndexChanged({
    $f = $lstAsar.SelectedItem; if (-not $f) { return }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($f.full)
        $trunc = $false; $cap = [int]512KB
        if ($bytes.Length -gt $cap) { $b2 = New-Object 'byte[]' $cap; [System.Array]::Copy($bytes, 0, $b2, 0, $cap); $bytes = $b2; $trunc = $true }
        $txtAsarView.Text = [System.Text.Encoding]::UTF8.GetString($bytes) + $(if ($trunc) { "`r`n`r`n... [truncated at 512 KB]" } else { '' })
        $script:AsarLastFull = $f.full
    } catch { $txtAsarView.Text = "cannot read: $($_.Exception.Message)" }
})

# ================= TAB: Hex View (byte view of any file) =================
$script:HexPath = ''; $script:HexOffset = [int64]0; $script:HexSize = [int64]0; $script:HexPageSize = 4096; $script:HexHl = [int64]-1
$script:HexPeMap = $null; $script:HexPeOverlay = $false; $script:HexEntropy = $null; $script:HexDiffPath = ''
$script:HexHashes = $null; $script:HexBookmarks = New-Object System.Collections.Generic.List[object]
# ImHex-style byte colouring: precompute a byte -> colour-category index (built once).
#   1 null (dim)  2 whitespace (blue)  3 printable ASCII (green)  4 control (orange)  5 high/extended (purple)
$script:HexCatIdx = New-Object 'int[]' 256
for ($v = 0; $v -lt 256; $v++) {
    if ($v -eq 0) { $script:HexCatIdx[$v] = 1 }
    elseif ($v -eq 9 -or $v -eq 10 -or $v -eq 13) { $script:HexCatIdx[$v] = 2 }
    elseif ($v -ge 32 -and $v -le 126) { $script:HexCatIdx[$v] = 3 }
    elseif ($v -lt 32 -or $v -eq 127) { $script:HexCatIdx[$v] = 4 }
    else { $script:HexCatIdx[$v] = 5 }
}
# Colour-coded RTF for the hex page. Building RTF directly (one assignment) is far faster than
# thousands of per-byte SelectionColor calls. colortbl: 1 dim, 2 blue, 3 green, 4 orange, 5 purple,
# 6 separator-grey, 7 teal (offset gutter).
function Get-GuiHexRtf([string]$path, [int64]$offset, [int]$length) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($length -le 0 -or $length -gt 16384) { $length = 4096 }
    if ($offset -lt 0) { $offset = 0 }
    $total = [int64](Get-Item -LiteralPath $path).Length
    if ($offset -ge $total) { return @{ rtf = ''; size = $total; offset = $offset; count = 0 } }
    $count = [int][Math]::Min([int64]$length, $total - $offset)
    $buf = New-Object 'byte[]' $count
    $fsr = [System.IO.File]::OpenRead($path)
    try { [void]$fsr.Seek($offset, 'Begin'); [void]$fsr.Read($buf, 0, $count) } finally { $fsr.Dispose() }
    $sb = New-Object System.Text.StringBuilder (($count * 22) + 512)
    [void]$sb.Append('{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}')
    [void]$sb.Append('{\colortbl;\red90\green90\blue90;\red97\green175\blue239;\red152\green195\blue121;\red209\green154\blue102;\red198\green120\blue221;\red160\green160\blue160;\red78\green201\blue176;}')
    [void]$sb.Append('\f0\fs19 ')
    $cat = $script:HexCatIdx
    for ($i = 0; $i -lt $count; $i += 16) {
        $n = [Math]::Min(16, $count - $i)
        [void]$sb.Append('\cf7 ').AppendFormat('{0:x8}  ', ($offset + $i))
        $asc = New-Object System.Text.StringBuilder 128
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -lt $n) {
                $bv = $buf[$i + $j]; $ci = $cat[$bv]
                [void]$sb.Append('\cf').Append($ci).Append(' ').AppendFormat('{0:x2} ', $bv)
                if ($bv -ge 32 -and $bv -le 126) {
                    $ch = [char]$bv
                    [void]$asc.Append('\cf').Append($ci).Append(' ')
                    if ($ch -eq '\' -or $ch -eq '{' -or $ch -eq '}') { [void]$asc.Append('\') }
                    [void]$asc.Append($ch)
                } else {
                    [void]$asc.Append('\cf1 .')
                }
            } else {
                [void]$sb.Append('   ')
            }
            if ($j -eq 7) { [void]$sb.Append(' ') }
        }
        [void]$sb.Append('\cf6  |').Append($asc.ToString()).Append('\cf6 |\par ')
    }
    [void]$sb.Append('}')
    return @{ rtf = $sb.ToString(); size = $total; offset = $offset; count = $count }
}
# Data Inspector: the 16 bytes at an offset interpreted as typed values.
function Get-GuiHexInspect([string]$path, [int64]$offset) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    if ($offset -lt 0) { $offset = 0 }
    $total = [int64](Get-Item -LiteralPath $path).Length
    if ($offset -ge $total) { return @() }
    $n = [int][Math]::Min([int64]16, $total - $offset)
    $buf = New-Object 'byte[]' 16
    $fsr = [System.IO.File]::OpenRead($path)
    try { [void]$fsr.Seek($offset, 'Begin'); [void]$fsr.Read($buf, 0, $n) } finally { $fsr.Dispose() }
    $be = { param($len) $c = New-Object 'byte[]' $len; [System.Array]::Copy($buf, 0, $c, 0, $len); [System.Array]::Reverse($c); , $c }
    $o = New-Object System.Collections.Generic.List[object]
    $add = { param($k, $v) $o.Add([pscustomobject]@{ n = $k; v = "$v" }) }
    & $add 'int8'      ([sbyte]$buf[0]);           & $add 'uint8'     ($buf[0])
    & $add 'int16 LE'  ([System.BitConverter]::ToInt16($buf, 0));  & $add 'int16 BE'  ([System.BitConverter]::ToInt16((& $be 2), 0))
    & $add 'uint16 LE' ([System.BitConverter]::ToUInt16($buf, 0)); & $add 'uint16 BE' ([System.BitConverter]::ToUInt16((& $be 2), 0))
    & $add 'int32 LE'  ([System.BitConverter]::ToInt32($buf, 0));  & $add 'int32 BE'  ([System.BitConverter]::ToInt32((& $be 4), 0))
    & $add 'uint32 LE' ([System.BitConverter]::ToUInt32($buf, 0)); & $add 'uint32 BE' ([System.BitConverter]::ToUInt32((& $be 4), 0))
    & $add 'int64 LE'  ([System.BitConverter]::ToInt64($buf, 0));  & $add 'uint64 LE' ([System.BitConverter]::ToUInt64($buf, 0))
    & $add 'float LE'  ([System.BitConverter]::ToSingle($buf, 0)); & $add 'double LE' ([System.BitConverter]::ToDouble($buf, 0))
    $asc = -join (0..([Math]::Min(15, $n - 1)) | ForEach-Object { $b = $buf[$_]; if ($b -ge 32 -and $b -lt 127) { [char]$b } else { '.' } })
    & $add 'ASCII' $asc
    try { $u = [System.BitConverter]::ToUInt32($buf, 0); if ($u -gt 0 -and $u -lt 4102444800) { & $add 'u32 epoch' ([System.DateTimeOffset]::FromUnixTimeSeconds($u).UtcDateTime.ToString('u')) } } catch { }
    return $o.ToArray()
}
# Byte search: offset of the next 'hex'/'ascii' match at/after $from, or -1 (or negative code on error).
function Find-GuiHexOffset([string]$path, [string]$query, [string]$kind, [int64]$from) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return [int64]-1 }
    if (-not $query) { return [int64]-1 }
    $needle = $null
    if ($kind -eq 'hex') {
        $hx = ($query -replace '[^0-9a-fA-F]', ''); if ($hx.Length -lt 2 -or ($hx.Length % 2)) { return [int64]-3 }
        $needle = [byte[]](0..(($hx.Length / 2) - 1) | ForEach-Object { [Convert]::ToByte($hx.Substring($_ * 2, 2), 16) })
    } else { $needle = [System.Text.Encoding]::ASCII.GetBytes($query) }
    $nlen = $needle.Length; if (-not $nlen) { return [int64]-1 }
    # NO SIZE CAP (the old '-gt 300MB -> -2' refused the binaries this is most useful on)
    # and no ReadAllBytes. Sliding window with a (nlen - 1) overlap, absolute offsets.
    $flen = 0
    try { $flen = (Get-Item -LiteralPath $path -ErrorAction Stop).Length } catch { return [int64]-1 }
    $chunk = 16MB
    $ov = [Math]::Max(0, $nlen - 1)
    $pos = [int64]([Math]::Max([int64]0, $from))
    $fs = $null
    try {
        $fs = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $buf = New-Object byte[] ($chunk + $ov)
        while ($pos -lt $flen) {
            $fs.Position = $pos
            $want = [int][Math]::Min($buf.Length, $flen - $pos)
            $got = 0
            while ($got -lt $want) {
                $r = $fs.Read($buf, $got, $want - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            if ($got -le 0) { break }
            $lim = $got - $nlen
            for ($i = 0; $i -le $lim; $i++) {
                $ok = $true
                for ($j = 0; $j -lt $nlen; $j++) { if ($buf[$i + $j] -ne $needle[$j]) { $ok = $false; break } }
                if ($ok) { return [int64]($pos + $i) }
            }
            if ($got -lt $want) { break }
            $pos += $chunk
        }
    } catch {
        return [int64]-1
    } finally { if ($fs) { $fs.Dispose() } }
    return [int64]-1
}
# Extract printable ASCII + UTF-16LE ("wide") strings with their byte offsets, so a name /
# URL / path can be clicked to jump into the hex view. $filter narrows (case-insensitive
# substring) -- the "find a name" case. Regex over a Latin1 view keeps every offset exact.
function Get-GuiHexStrings([string]$path, [int]$min, [string]$filter, [string]$kind, [int]$cap) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($min -lt 2) { $min = 2 } elseif ($min -gt 200) { $min = 200 }
    if ($cap -lt 1) { $cap = 1 } elseif ($cap -gt 20000) { $cap = 20000 }
    # NO SIZE CAP. The old '-gt 300MB -> error' made the strings view unavailable on exactly
    # the binaries an analyst opens it for. Chunked with a 64 KB overlap (longer than any
    # reported string) and each match rebased to its absolute file offset, so the click-to-
    # jump target stays correct.
    $flen = 0
    try { $flen = (Get-Item -LiteralPath $path -ErrorAction Stop).Length } catch { return @{ error = 'file not readable' } }
    $lat = [System.Text.Encoding]::GetEncoding(28591)   # Latin1: 1 byte <-> 1 char
    $flt = "$filter"
    $cmp = [System.StringComparison]::OrdinalIgnoreCase
    $hits = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $total = 0
    $chunk = 16MB; $ov = 64KB
    $fs = $null
    try {
        $fs = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $buf = New-Object byte[] ($chunk + $ov)
        $pos = [int64]0
        while ($pos -lt $flen) {
            $fs.Position = $pos
            $want = [int][Math]::Min($buf.Length, $flen - $pos)
            $got = 0
            while ($got -lt $want) {
                $r = $fs.Read($buf, $got, $want - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            if ($got -le 0) { break }
            $text = $lat.GetString($buf, 0, $got)
            if ($kind -eq 'both' -or $kind -eq 'ascii') {
                foreach ($m in ([regex]::Matches($text, "[\x20-\x7E]{$min,}"))) {
                    $abs = $pos + $m.Index
                    if ($seen.ContainsKey("a$abs")) { continue }
                    $v = $m.Value
                    if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
                    $seen["a$abs"] = $true
                    $total++
                    if ($hits.Count -lt $cap) { if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }; $hits.Add([pscustomobject]@{ offset = [int64]$abs; kind = 'a'; text = $v }) }
                }
            }
            if ($kind -eq 'both' -or $kind -eq 'wide') {
                foreach ($m in ([regex]::Matches($text, "(?:[\x20-\x7E]\x00){$min,}"))) {
                    $abs = $pos + $m.Index
                    if ($seen.ContainsKey("w$abs")) { continue }
                    $v = [System.Text.Encoding]::Unicode.GetString($buf, $m.Index, $m.Length)
                    if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
                    $seen["w$abs"] = $true
                    $total++
                    if ($hits.Count -lt $cap) { if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }; $hits.Add([pscustomobject]@{ offset = [int64]$abs; kind = 'w'; text = $v }) }
                }
            }
            if ($got -lt $want) { break }
            $pos += $chunk
        }
    } catch {
    } finally { if ($fs) { $fs.Dispose() } }
    $items = @($hits | Sort-Object offset)
    return @{ items = $items; total = $total; capped = [bool]($total -gt $items.Count) }
}
function _HexStrCat([string]$v) {
    if ($v -match '(?i)https?://|ftp://') {
        return @{ cat = 'URL';      fg = [System.Drawing.Color]::FromArgb(86,  182, 194) }
    }
    if ($v -match '(?i)HKEY_|HKLM\\|HKCU\\|HKLM/|HKCU/') {
        return @{ cat = 'Registry'; fg = [System.Drawing.Color]::FromArgb(255, 200, 120) }
    }
    if ($v -match '(?i)(cmd(\.exe)?[\s/]|powershell|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin)') {
        return @{ cat = 'Exec';     fg = [System.Drawing.Color]::FromArgb(255, 140, 140) }
    }
    if ($v -match '(?i)\\.*\.pdb$|\.pdb$') {
        return @{ cat = 'PDB';      fg = [System.Drawing.Color]::FromArgb(255, 160, 220) }
    }
    if ($v -match '(?i)\b(connect|socket|recv|send|bind|listen|WSA|inet_|gethost|gethostbyname|URLDownload|WinHttp|HttpOpen|InternetOpen)\b') {
        return @{ cat = 'Network';  fg = [System.Drawing.Color]::FromArgb(100, 210, 255) }
    }
    if ($v -match '(?i)\b(AES|RSA|SHA|MD5|HMAC|encrypt|decrypt|CryptAcquire|BCrypt|NCrypt|CertOpen)\b') {
        return @{ cat = 'Crypto';   fg = [System.Drawing.Color]::FromArgb(180, 120, 255) }
    }
    if ($v -match '(?i)\b(error|failed|exception|warning|assert|fatal|critical|abort|crash)\b') {
        return @{ cat = 'Error';    fg = [System.Drawing.Color]::FromArgb(255, 110,  90) }
    }
    if ($v -match '(?i)\b(debug|trace|verbose|log(ger|ging)?|printf|OutputDebugString)\b') {
        return @{ cat = 'Debug';    fg = [System.Drawing.Color]::FromArgb(160, 160, 160) }
    }
    if ($v -match '%[sdixXuocfeEgGp]|%\d+[sdixX]') {
        return @{ cat = 'Format';   fg = [System.Drawing.Color]::FromArgb(200, 220, 140) }
    }
    if ($v -match '(?i)^[A-Za-z]:\\|^\\\\[^\\]|\.(exe|dll|sys|ocx|bat|ps1|vbs|js)$') {
        return @{ cat = 'Path/PE';  fg = [System.Drawing.Color]::FromArgb(255, 220,  80) }
    }
    if ($v -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b') {
        return @{ cat = 'IP';       fg = [System.Drawing.Color]::FromArgb(180, 230, 180) }
    }
    if ($v -match '(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP\s+TABLE|CREATE\s+TABLE)\b') {
        return @{ cat = 'SQL';      fg = [System.Drawing.Color]::FromArgb(200, 160, 220) }
    }
    if ($v -match '^\d+\.\d+\.\d+(\.\d+)?$') {
        return @{ cat = 'Version';  fg = [System.Drawing.Color]::FromArgb(140, 200, 140) }
    }
    return @{ cat = '-';            fg = [System.Drawing.Color]::FromArgb(214, 220, 228) }
}

# Button handler: scan, fill the results list, show it.
function Do-GuiHexStrings {
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHexSInfo.Text = 'load a file first'; return }
    $min = 0; [void][int]::TryParse($txtHexSMin.Text.Trim(), [ref]$min); if ($min -lt 2) { $min = 4 }
    $k = [string]$cmbHexSKind.SelectedItem; if ($k -eq 'ascii+wide') { $k = 'both' }
    $lblHexSInfo.Text = 'scanning...'; $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $r = Get-GuiHexStrings $p $min $txtHexSFilter.Text $k 2000
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    if ($r.error) { $lblHexSInfo.Text = $r.error; return }
    $pnlStrWrap.Visible = $true; $lvHexStr.BeginUpdate(); $lvHexStr.Items.Clear()
    foreach ($x in $r.items) {
        $cat = _HexStrCat $x.text
        $it = New-Object System.Windows.Forms.ListViewItem("0x$([Convert]::ToString([int64]$x.offset,16))")
        [void]$it.SubItems.Add($x.kind); [void]$it.SubItems.Add($cat.cat); [void]$it.SubItems.Add($x.text)
        $it.Tag = [int64]$x.offset; $it.ForeColor = $cat.fg
        [void]$lvHexStr.Items.Add($it)
    }
    $lvHexStr.EndUpdate()
    $lblHexSInfo.Text = "$($r.total) match$(if($r.total -eq 1){''}else{'es'})$(if($r.capped){" (showing first $($r.items.Count))"}else{''})"
}
function Load-GuiHex([int64]$off) {
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHex.Text = 'enter a file path'; return }
    if ($off -lt 0) { $off = 0 }
    $peArg = if ($script:HexPeOverlay -and $script:HexPeMap) { $script:HexPeMap } else { $null }
    $dBuf = $null
    if ($script:HexDiffPath -and (Test-Path -LiteralPath $script:HexDiffPath -PathType Leaf)) {
        $dTotal = [int64](Get-Item -LiteralPath $script:HexDiffPath).Length
        $dLen = [int][Math]::Min([int64]$script:HexPageSize, [Math]::Max(0, $dTotal - $off))
        if ($dLen -gt 0) {
            $dBuf = New-Object 'byte[]' $dLen
            $dfsr = [IO.File]::OpenRead($script:HexDiffPath)
            try { [void]$dfsr.Seek($off, 'Begin'); [void]$dfsr.Read($dBuf, 0, $dLen) } finally { $dfsr.Dispose() }
        }
    }
    if ($peArg -or $dBuf) { $r = Get-GuiHexRtfEx $p $off $script:HexPageSize $peArg $dBuf }
    else { $r = Get-GuiHexRtf $p $off $script:HexPageSize }
    if ($r.error) { $lblHex.Text = "Error: $($r.error)"; $txtHex.Text = ''; return }
    $script:HexPath = $p; $script:HexOffset = $off; $script:HexSize = $r.size
    if ($r.rtf) { $txtHex.Rtf = $r.rtf } else { $txtHex.Text = '' }
    $info = "$(Split-Path $p -Leaf) -- $($r.size) bytes, offset 0x$([Convert]::ToString($off,16)) ($($r.count) shown)"
    if ($r.diffCount) { $info += " | diff: $($r.diffCount) bytes" }
    $lblHex.Text = $info
    try { $pnlEntropy.Invalidate() } catch { }
    if ($script:HexHl -ge $off -and $script:HexHl -lt ($off + $r.count)) {
        $rowIdx = [int](($script:HexHl - $off) / 16)
        try {
            $ls = $txtHex.GetFirstCharIndexFromLine($rowIdx)
            if ($ls -ge 0) {
                $le = $txtHex.GetFirstCharIndexFromLine($rowIdx + 1)
                $len = if ($le -gt $ls) { $le - $ls - 1 } else { $txtHex.TextLength - $ls }
                $txtHex.Select($ls, [Math]::Max(0, $len)); $txtHex.SelectionBackColor = [System.Drawing.Color]::FromArgb(40, 70, 110)
                $txtHex.Select($ls, 0); $txtHex.ScrollToCaret()
            }
        } catch { }
    }
}
# Inspect an offset: fill the inspector list + highlight. Reads the offset box when $off < 0.
function Do-GuiHexInspect([int64]$off) {
    if ($off -lt 0) { try { $off = [Convert]::ToInt64(($txtHexInsIn.Text.Trim() -replace '^0x', ''), 16) } catch { $off = 0 } }
    $script:HexHl = $off; $txtHexInsIn.Text = [Convert]::ToString($off, 16); $lblHexInsOff.Text = "offset 0x$([Convert]::ToString($off,16))"
    # render the page holding the offset first (sets $script:HexPath + moves the highlight)
    if ($off -ge $script:HexOffset -and $off -lt ($script:HexOffset + $script:HexPageSize) -and $script:HexPath) { Load-GuiHex $script:HexOffset } else { $pg = [int64]([Math]::Floor($off / $script:HexPageSize) * $script:HexPageSize); Load-GuiHex $pg }
    $lvHexIns.BeginUpdate(); $lvHexIns.Items.Clear()
    foreach ($row in (Get-GuiHexInspect $script:HexPath $off)) { $it = New-Object System.Windows.Forms.ListViewItem($row.n); [void]$it.SubItems.Add($row.v); [void]$lvHexIns.Items.Add($it) }
    $lvHexIns.EndUpdate()
}
# PE section map for hex overlay. Standalone parser (module privates are not accessible).
function Get-GuiPeMap([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $fs = $null; $br = $null
    try {
        $fs = [IO.File]::OpenRead($path); $br = [IO.BinaryReader]::new($fs)
        $total = [int64]$fs.Length; if ($total -lt 0x80) { return $null }
        $fs.Position = 0; if ($br.ReadUInt16() -ne 0x5A4D) { return $null }
        $fs.Position = 0x3C; $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt ($total - 24)) { return $null }
        $fs.Position = $peOff; if ($br.ReadUInt32() -ne 0x00004550) { return $null }
        $machine = $br.ReadUInt16(); $numSec = $br.ReadUInt16()
        $ts = $br.ReadUInt32()
        $fs.Position = $peOff + 4 + 16; $optSz = $br.ReadUInt16(); $chars = $br.ReadUInt16()
        $fs.Position = $peOff + 24; $magic = $br.ReadUInt16(); $plus = ($magic -eq 0x20B)
        $fs.Position = $peOff + 24 + 70; $dllChar = $br.ReadUInt16()
        $secOff = $peOff + 4 + 20 + $optSz
        $sc = @(
            @(78,201,176), @(86,156,214), @(152,195,121), @(209,154,102),
            @(198,120,221), @(229,192,123), @(224,108,117), @(190,140,195),
            @(86,182,194), @(181,189,104)
        )
        $secs = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $numSec; $i++) {
            $b = $secOff + ($i * 40); if (($b + 40) -gt $total) { break }
            $fs.Position = $b; $nb = $br.ReadBytes(8)
            $nm = ([Text.Encoding]::ASCII.GetString($nb)).Trim([char]0).Trim()
            $vs = $br.ReadUInt32(); $va = $br.ReadUInt32()
            $rs = $br.ReadUInt32(); $rp = $br.ReadUInt32()
            $ci = [Math]::Min($i, $sc.Count - 1)
            $secs.Add([pscustomobject]@{
                Name=$nm; VA=$va; VSize=$vs; RawOff=[int64]$rp; RawSize=[int64]$rs
                Ci=$ci; R=$sc[$ci][0]; G=$sc[$ci][1]; B=$sc[$ci][2]
            })
        }
        $ddBase = if ($plus) { $peOff + 24 + 112 } else { $peOff + 24 + 96 }
        $imports = New-Object System.Collections.Generic.List[string]
        $rvaToFile = { param($rva) foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VSize)) { return $s.RawOff + ($rva - $s.VA) } }; -1 }
        if (($ddBase + 12) -le $total) {
            $fs.Position = $ddBase + 8; $impRva = $br.ReadUInt32()
            if ($impRva -ne 0) {
                $iOff = & $rvaToFile $impRva
                if ($iOff -ge 0) {
                    for ($ei = 0; $ei -lt 500; $ei++) {
                        $ds = $iOff + ($ei * 20); if (($ds + 20) -gt $total) { break }
                        $fs.Position = $ds + 12; $nRva = $br.ReadUInt32()
                        if ($nRva -eq 0) { break }
                        $nf = & $rvaToFile $nRva
                        if ($nf -lt 0 -or $nf -ge $total) { continue }
                        $fs.Position = $nf
                        $bs = New-Object System.Collections.Generic.List[byte]
                        while ($fs.Position -lt $total) { $bv = $br.ReadByte(); if ($bv -eq 0) { break }; $bs.Add($bv); if ($bs.Count -gt 200) { break } }
                        $n = [Text.Encoding]::ASCII.GetString($bs.ToArray())
                        if ($n) { $imports.Add($n) }
                    }
                }
            }
        }
        $machN = @{ 0x14C='x86'; 0x8664='x64'; 0xAA64='ARM64' }
        $mn = if ($machN.ContainsKey([int]$machine)) { $machN[[int]$machine] } else { "0x$($machine.ToString('X4'))" }
        $hdEnd = if ($secs.Count) { [int64]$secs[0].RawOff } else { [int64]$secOff + ($numSec * 40) }
        $isDll = ($chars -band 0x2000) -ne 0
        $ts2 = if ($plus) { "PE32+" } else { "PE32" }
        $ts2 += if ($isDll) { ' DLL' } else { ' EXE' }
        return [pscustomobject]@{
            IsPe=$true; Machine=$mn; TypeStr=$ts2; DllChar=$dllChar
            Timestamp=$ts; HeaderEnd=$hdEnd; PeOff=[int64]$peOff
            Sections=$secs.ToArray(); Imports=$imports.ToArray(); FileSize=$total
        }
    } catch { return $null }
    finally { if ($br) { $br.Dispose() }; if ($fs) { $fs.Dispose() } }
}
# Shannon entropy per block (0.0-8.0). Capped at 10 MB, block size auto-scaled.
function Get-GuiBlockEntropy([string]$path, [int]$blockSize) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return ,@() }
    $total = [int64](Get-Item -LiteralPath $path).Length
    if ($total -eq 0) { return ,@() }
    if ($blockSize -lt 64) { $blockSize = 256 }
    $readLen = [int][Math]::Min($total, [int64]10485760)
    $buf = New-Object 'byte[]' $readLen
    $fsr = [IO.File]::OpenRead($path)
    try { [void]$fsr.Read($buf, 0, $readLen) } finally { $fsr.Dispose() }
    $blocks = [int][Math]::Ceiling($readLen / $blockSize)
    $result = New-Object 'double[]' $blocks
    $log2 = [Math]::Log(2)
    for ($bi = 0; $bi -lt $blocks; $bi++) {
        $bs2 = $bi * $blockSize; $bl = [Math]::Min($blockSize, $readLen - $bs2)
        $freq = New-Object 'int[]' 256
        for ($i = 0; $i -lt $bl; $i++) { $freq[$buf[$bs2 + $i]]++ }
        $ent = [double]0
        for ($v = 0; $v -lt 256; $v++) {
            if ($freq[$v] -gt 0) { $p = [double]$freq[$v] / $bl; $ent -= $p * [Math]::Log($p) / $log2 }
        }
        $result[$bi] = $ent
    }
    return ,$result
}
# XOR single-byte brute-force: try 0x01-0xFF, report printable ASCII runs >= $minStr.
function Do-GuiXorScan([string]$path, [int64]$offset, [int]$length, [int]$minStr) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return ,@() }
    $total = [int64](Get-Item -LiteralPath $path).Length
    if ($length -le 0) { $length = [int][Math]::Min(65536, $total) }
    if ($minStr -lt 4) { $minStr = 6 }
    if ($offset -ge $total) { return ,@() }
    $readLen = [int][Math]::Min([int64]$length, $total - $offset)
    $buf = New-Object 'byte[]' $readLen
    $fsr = [IO.File]::OpenRead($path)
    try { [void]$fsr.Seek($offset, 'Begin'); [void]$fsr.Read($buf, 0, $readLen) } finally { $fsr.Dispose() }
    $hits = New-Object System.Collections.Generic.List[object]
    for ($key = 1; $key -lt 256; $key++) {
        $run = 0; $runStart = 0
        for ($i = 0; $i -le $readLen; $i++) {
            $ch = if ($i -lt $readLen) { $buf[$i] -bxor $key } else { 0 }
            if ($ch -ge 32 -and $ch -le 126) { if ($run -eq 0) { $runStart = $i }; $run++ }
            else {
                if ($run -ge $minStr) {
                    $xsb = New-Object System.Text.StringBuilder $run
                    for ($j = $runStart; $j -lt ($runStart + $run); $j++) { [void]$xsb.Append([char]($buf[$j] -bxor $key)) }
                    $hits.Add([pscustomobject]@{ Key=$key; KeyHex='0x'+$key.ToString('x2'); Offset=$offset+$runStart; Length=$run; Text=$xsb.ToString() })
                    if ($hits.Count -ge 100) { return ,$hits.ToArray() }
                }
                $run = 0
            }
        }
    }
    return ,$hits.ToArray()
}
function Get-GuiFileHashes([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $fs = [IO.File]::OpenRead($path)
    try {
        $md5 = [Security.Cryptography.MD5]::Create(); $h1 = [BitConverter]::ToString($md5.ComputeHash($fs)).Replace('-','').ToLower(); $md5.Dispose(); $fs.Position = 0
        $sha1 = [Security.Cryptography.SHA1]::Create(); $h2 = [BitConverter]::ToString($sha1.ComputeHash($fs)).Replace('-','').ToLower(); $sha1.Dispose(); $fs.Position = 0
        $sha256 = [Security.Cryptography.SHA256]::Create(); $h3 = [BitConverter]::ToString($sha256.ComputeHash($fs)).Replace('-','').ToLower(); $sha256.Dispose()
    } finally { $fs.Dispose() }
    [pscustomobject]@{ MD5 = $h1; SHA1 = $h2; SHA256 = $h3 }
}
function Get-GuiByteFrequency([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $counts = New-Object 'int[]' 256; $buf = New-Object 'byte[]' 65536; $total = [int64]0
    $fs = [IO.File]::OpenRead($path)
    try { while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { for ($i = 0; $i -lt $n; $i++) { $counts[$buf[$i]]++ }; $total += $n } } finally { $fs.Dispose() }
    [pscustomobject]@{ Counts = $counts; Total = $total }
}
# Extended RTF renderer with optional PE section colouring and binary diff highlights.
function Get-GuiHexRtfEx([string]$path, [int64]$offset, [int]$length, $peMap, [byte[]]$diffBuf) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($length -le 0 -or $length -gt 16384) { $length = 4096 }
    if ($offset -lt 0) { $offset = 0 }
    $total = [int64](Get-Item -LiteralPath $path).Length
    if ($offset -ge $total) { return @{ rtf = ''; size = $total; offset = $offset; count = 0 } }
    $count = [int][Math]::Min([int64]$length, $total - $offset)
    $buf = New-Object 'byte[]' $count
    $fsr = [IO.File]::OpenRead($path)
    try { [void]$fsr.Seek($offset, 'Begin'); [void]$fsr.Read($buf, 0, $count) } finally { $fsr.Dispose() }
    $cat = $script:HexCatIdx; $usePe = ($null -ne $peMap); $useDiff = ($null -ne $diffBuf)
    $esb = New-Object System.Text.StringBuilder (($count * 24) + 1024)
    [void]$esb.Append('{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}{\colortbl;')
    if ($usePe) {
        [void]$esb.Append('\red100\green180\blue180;')
        $secs = $peMap.Sections
        foreach ($s in $secs) { [void]$esb.Append("\red$($s.R)\green$($s.G)\blue$($s.B);") }
        $sepCi = $secs.Count + 2; $gutCi = $secs.Count + 3; $unmCi = $secs.Count + 4
        [void]$esb.Append('\red160\green160\blue160;\red78\green201\blue176;\red90\green90\blue90;')
        $diffCi = $secs.Count + 5
    } else {
        [void]$esb.Append('\red90\green90\blue90;\red97\green175\blue239;\red152\green195\blue121;\red209\green154\blue102;\red198\green120\blue221;\red160\green160\blue160;\red78\green201\blue176;')
        $sepCi = 6; $gutCi = 7; $diffCi = 8
    }
    if ($useDiff) { [void]$esb.Append('\red255\green60\blue60;') }
    [void]$esb.Append('}\f0\fs19 ')
    $hdEnd = if ($usePe) { $peMap.HeaderEnd } else { 0 }
    for ($i = 0; $i -lt $count; $i += 16) {
        $n = [Math]::Min(16, $count - $i)
        [void]$esb.Append("\cf$gutCi ").AppendFormat('{0:x8}  ', ($offset + $i))
        $asc = New-Object System.Text.StringBuilder 128
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -lt $n) {
                $bv = $buf[$i + $j]
                $isDiff = $useDiff -and (($i + $j) -lt $diffBuf.Length) -and ($bv -ne $diffBuf[$i + $j])
                if ($usePe) {
                    $fo = $offset + $i + $j; $ci = $unmCi
                    if ($fo -lt $hdEnd) { $ci = 1 }
                    else { foreach ($s in $secs) { if ($fo -ge $s.RawOff -and $fo -lt ($s.RawOff + $s.RawSize)) { $ci = $s.Ci + 2; break } } }
                } else { $ci = $cat[$bv] }
                if ($isDiff) { $ci = $diffCi }
                [void]$esb.Append("\cf$ci ").AppendFormat('{0:x2} ', $bv)
                if ($bv -ge 32 -and $bv -le 126) {
                    $ch = [char]$bv; [void]$asc.Append("\cf$ci ")
                    if ($ch -eq '\' -or $ch -eq '{' -or $ch -eq '}') { [void]$asc.Append('\') }
                    [void]$asc.Append($ch)
                } else {
                    $ci2 = if ($usePe) { $unmCi } else { 1 }; if ($isDiff) { $ci2 = $diffCi }
                    [void]$asc.Append("\cf$ci2 .")
                }
            } else { [void]$esb.Append('   ') }
            if ($j -eq 7) { [void]$esb.Append(' ') }
        }
        [void]$esb.Append("\cf$sepCi  |").Append($asc.ToString()).Append("\cf$sepCi |\par ")
    }
    [void]$esb.Append('}')
    $dc = 0
    if ($useDiff) { $mc = [Math]::Min($count, $diffBuf.Length); for ($i = 0; $i -lt $mc; $i++) { if ($buf[$i] -ne $diffBuf[$i]) { $dc++ } }; if ($count -gt $diffBuf.Length) { $dc += ($count - $diffBuf.Length) } }
    return @{ rtf = $esb.ToString(); size = $total; offset = $offset; count = $count; diffCount = $dc }
}

$tabHex = New-Object System.Windows.Forms.TabPage
$tabHex.Text = ' Hex '
$tabHex.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabHex)
$hexTop = New-Object System.Windows.Forms.Panel
$hexTop.Dock = 'Top'; $hexTop.Height = 90; $hexTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblHexT = New-Object System.Windows.Forms.Label
$lblHexT.Text = "File:"; $lblHexT.ForeColor = [System.Drawing.Color]::White; $lblHexT.Location = New-Object System.Drawing.Point(12, 14); $lblHexT.Size = New-Object System.Drawing.Size(46, 18)
$hexTop.Controls.Add($lblHexT)
$txtHexPath = New-Object System.Windows.Forms.TextBox
$txtHexPath.Location = New-Object System.Drawing.Point(60, 11); $txtHexPath.Size = New-Object System.Drawing.Size(594, 24); $txtHexPath.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexPath.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexPath.ForeColor = [System.Drawing.Color]::White
$hexTop.Controls.Add($txtHexPath)
$btnHexBrowse = New-Object System.Windows.Forms.Button
$btnHexBrowse.Text = "Browse..."; $btnHexBrowse.Location = New-Object System.Drawing.Point(662, 10); $btnHexBrowse.Size = New-Object System.Drawing.Size(88, 26)
$btnHexBrowse.FlatStyle = 'Flat'; $btnHexBrowse.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexBrowse.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexBrowse)
$btnHexLoad = New-Object System.Windows.Forms.Button
$btnHexLoad.Text = "Load"; $btnHexLoad.Location = New-Object System.Drawing.Point(754, 10); $btnHexLoad.Size = New-Object System.Drawing.Size(64, 26)
$btnHexLoad.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnHexLoad.ForeColor = [System.Drawing.Color]::White; $btnHexLoad.FlatStyle = 'Flat'
$hexTop.Controls.Add($btnHexLoad)
$btnHexPe = New-Object System.Windows.Forms.Button
$btnHexPe.Text = "PE"; $btnHexPe.Location = New-Object System.Drawing.Point(820, 10); $btnHexPe.Size = New-Object System.Drawing.Size(46, 26)
$btnHexPe.FlatStyle = 'Flat'; $btnHexPe.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexPe.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$btnHexPe.Font = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
$hexTop.Controls.Add($btnHexPe)
$btnHexDiff = New-Object System.Windows.Forms.Button
$btnHexDiff.Text = "Diff..."; $btnHexDiff.Location = New-Object System.Drawing.Point(872, 10); $btnHexDiff.Size = New-Object System.Drawing.Size(72, 26)
$btnHexDiff.FlatStyle = 'Flat'; $btnHexDiff.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexDiff.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexDiff)
$btnHexStrTog = New-Object System.Windows.Forms.Button
$btnHexStrTog.Text = "Strings"; $btnHexStrTog.Location = New-Object System.Drawing.Point(948, 10); $btnHexStrTog.Size = New-Object System.Drawing.Size(72, 26)
$btnHexStrTog.FlatStyle = 'Flat'; $btnHexStrTog.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexStrTog.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexStrTog)
$btnHexHash = New-Object System.Windows.Forms.Button
$btnHexHash.Text = "Hash"; $btnHexHash.Location = New-Object System.Drawing.Point(1024, 10); $btnHexHash.Size = New-Object System.Drawing.Size(52, 26)
$btnHexHash.FlatStyle = 'Flat'; $btnHexHash.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexHash.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexHash)
# Row 2 (y=42): paging + go-to + find
$btnHexPrev = New-Object System.Windows.Forms.Button
$btnHexPrev.Text = "< Prev"; $btnHexPrev.Location = New-Object System.Drawing.Point(12, 42); $btnHexPrev.Size = New-Object System.Drawing.Size(64, 26)
$btnHexPrev.FlatStyle = 'Flat'; $btnHexPrev.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexPrev.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexPrev)
$btnHexNext = New-Object System.Windows.Forms.Button
$btnHexNext.Text = "Next >"; $btnHexNext.Location = New-Object System.Drawing.Point(80, 42); $btnHexNext.Size = New-Object System.Drawing.Size(64, 26)
$btnHexNext.FlatStyle = 'Flat'; $btnHexNext.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexNext.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexNext)
$lblHexGoto = New-Object System.Windows.Forms.Label
$lblHexGoto.Text = "go to (hex):"; $lblHexGoto.ForeColor = [System.Drawing.Color]::White; $lblHexGoto.Location = New-Object System.Drawing.Point(158, 47); $lblHexGoto.Size = New-Object System.Drawing.Size(100, 18)
$hexTop.Controls.Add($lblHexGoto)
$txtHexGoto = New-Object System.Windows.Forms.TextBox
$txtHexGoto.Location = New-Object System.Drawing.Point(262, 44); $txtHexGoto.Size = New-Object System.Drawing.Size(90, 22); $txtHexGoto.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexGoto.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexGoto.ForeColor = [System.Drawing.Color]::White
$hexTop.Controls.Add($txtHexGoto)
$btnHexGo = New-Object System.Windows.Forms.Button
$btnHexGo.Text = "Go"; $btnHexGo.Location = New-Object System.Drawing.Point(358, 42); $btnHexGo.Size = New-Object System.Drawing.Size(50, 26)
$btnHexGo.FlatStyle = 'Flat'; $btnHexGo.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexGo.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexGo)
$lblHexFind = New-Object System.Windows.Forms.Label
$lblHexFind.Text = "find:"; $lblHexFind.ForeColor = [System.Drawing.Color]::White; $lblHexFind.Location = New-Object System.Drawing.Point(412, 47); $lblHexFind.Size = New-Object System.Drawing.Size(46, 18)
$hexTop.Controls.Add($lblHexFind)
$txtHexFind = New-Object System.Windows.Forms.TextBox
$txtHexFind.Location = New-Object System.Drawing.Point(462, 44); $txtHexFind.Size = New-Object System.Drawing.Size(150, 22); $txtHexFind.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexFind.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexFind.ForeColor = [System.Drawing.Color]::White
$hexTop.Controls.Add($txtHexFind)
$cmbHexKind = New-Object System.Windows.Forms.ComboBox
$cmbHexKind.Location = New-Object System.Drawing.Point(618, 44); $cmbHexKind.Size = New-Object System.Drawing.Size(70, 24); $cmbHexKind.DropDownStyle = 'DropDownList'
$cmbHexKind.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbHexKind.ForeColor = [System.Drawing.Color]::White
@('ascii', 'hex') | ForEach-Object { [void]$cmbHexKind.Items.Add($_) }; $cmbHexKind.SelectedIndex = 0
$hexTop.Controls.Add($cmbHexKind)
$btnHexFind = New-Object System.Windows.Forms.Button
$btnHexFind.Text = "Find next"; $btnHexFind.Location = New-Object System.Drawing.Point(694, 42); $btnHexFind.Size = New-Object System.Drawing.Size(86, 26)
$btnHexFind.FlatStyle = 'Flat'; $btnHexFind.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexFind.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexTop.Controls.Add($btnHexFind)
$lblHex = New-Object System.Windows.Forms.Label
$lblHex.Location = New-Object System.Drawing.Point(12, 70); $lblHex.Size = New-Object System.Drawing.Size(1060, 18)
$lblHex.Text = "Load a binary, then browse hex, overlay PE sections, diff, list strings, or inspect bytes."
$lblHex.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexTop.Controls.Add($lblHex)
$tabHex.Controls.Add($hexTop)

# Body: hex view + entropy strip + mode-switchable right panel (Inspector / PE Map / XOR Decode).
$hexBody = New-Object System.Windows.Forms.Panel
$hexBody.Dock = 'Fill'
# --- Right panel: mode-switchable analysis pane ---
$hexInsPanel = New-Object System.Windows.Forms.Panel
$hexInsPanel.Dock = 'Right'; $hexInsPanel.Width = 300; $hexInsPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$hexInsHdr = New-Object System.Windows.Forms.Panel
$hexInsHdr.Dock = 'Top'; $hexInsHdr.Height = 30; $hexInsHdr.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
$cmbHexMode = New-Object System.Windows.Forms.ComboBox
$cmbHexMode.Location = New-Object System.Drawing.Point(8, 4); $cmbHexMode.Size = New-Object System.Drawing.Size(140, 22)
$cmbHexMode.DropDownStyle = 'DropDownList'; $cmbHexMode.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$cmbHexMode.ForeColor = [System.Drawing.Color]::FromArgb(200, 205, 210); $cmbHexMode.FlatStyle = 'Flat'
@('Data Inspector', 'PE Map', 'XOR Decode', 'Byte Freq', 'Bookmarks', 'PE Detail') | ForEach-Object { [void]$cmbHexMode.Items.Add($_) }; $cmbHexMode.SelectedIndex = 0
$hexInsHdr.Controls.Add($cmbHexMode)
$hexInsPanel.Controls.Add($hexInsHdr)
# Mode A: Data Inspector (default)
$pnlInsMode = New-Object System.Windows.Forms.Panel
$pnlInsMode.Dock = 'Fill'; $pnlInsMode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$hexInsTop2 = New-Object System.Windows.Forms.Panel
$hexInsTop2.Dock = 'Top'; $hexInsTop2.Height = 54; $hexInsTop2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblHexInsOff = New-Object System.Windows.Forms.Label
$lblHexInsOff.Text = "offset 0x0"; $lblHexInsOff.Location = New-Object System.Drawing.Point(8, 6); $lblHexInsOff.Size = New-Object System.Drawing.Size(260, 16); $lblHexInsOff.ForeColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
$hexInsTop2.Controls.Add($lblHexInsOff)
$lblHexInsIn2 = New-Object System.Windows.Forms.Label
$lblHexInsIn2.Text = "offset (hex):"; $lblHexInsIn2.Location = New-Object System.Drawing.Point(8, 30); $lblHexInsIn2.Size = New-Object System.Drawing.Size(108, 16); $lblHexInsIn2.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexInsTop2.Controls.Add($lblHexInsIn2)
$txtHexInsIn = New-Object System.Windows.Forms.TextBox
$txtHexInsIn.Location = New-Object System.Drawing.Point(120, 27); $txtHexInsIn.Size = New-Object System.Drawing.Size(80, 22); $txtHexInsIn.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexInsIn.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexInsIn.ForeColor = [System.Drawing.Color]::White; $txtHexInsIn.BorderStyle = 'FixedSingle'
$hexInsTop2.Controls.Add($txtHexInsIn)
$btnHexInspect = New-Object System.Windows.Forms.Button
$btnHexInspect.Text = "Inspect"; $btnHexInspect.Location = New-Object System.Drawing.Point(204, 26); $btnHexInspect.Size = New-Object System.Drawing.Size(84, 24)
$btnHexInspect.FlatStyle = 'Flat'; $btnHexInspect.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$hexInsTop2.Controls.Add($btnHexInspect)
$pnlInsMode.Controls.Add($hexInsTop2)
$lvHexIns = New-Object System.Windows.Forms.ListView
$lvHexIns.Dock = 'Fill'; $lvHexIns.View = 'Details'; $lvHexIns.FullRowSelect = $true; $lvHexIns.GridLines = $false; $lvHexIns.HeaderStyle = 'Nonclickable'
$lvHexIns.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexIns.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexIns.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexIns.Columns.Add('Field', 110); [void]$lvHexIns.Columns.Add('Value', 168)
$pnlInsMode.Controls.Add($lvHexIns); $lvHexIns.BringToFront()
$hexInsPanel.Controls.Add($pnlInsMode); $pnlInsMode.BringToFront()
# Mode B: PE Map (sections + imports, hidden until PE toggle)
$pnlPeMode = New-Object System.Windows.Forms.Panel
$pnlPeMode.Dock = 'Fill'; $pnlPeMode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $pnlPeMode.Visible = $false
$lblPeInfo = New-Object System.Windows.Forms.Label
$lblPeInfo.Dock = 'Top'; $lblPeInfo.Height = 22; $lblPeInfo.Text = ''
$lblPeInfo.ForeColor = [System.Drawing.Color]::FromArgb(78, 201, 176); $lblPeInfo.Padding = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
$pnlPeMode.Controls.Add($lblPeInfo)
$lvHexPeImp = New-Object System.Windows.Forms.ListView
$lvHexPeImp.Dock = 'Bottom'; $lvHexPeImp.Height = 140; $lvHexPeImp.View = 'Details'; $lvHexPeImp.FullRowSelect = $true
$lvHexPeImp.GridLines = $false; $lvHexPeImp.HeaderStyle = 'Nonclickable'
$lvHexPeImp.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexPeImp.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexPeImp.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexPeImp.Columns.Add('Imports', 268)
$pnlPeMode.Controls.Add($lvHexPeImp)
$lvHexPe = New-Object System.Windows.Forms.ListView
$lvHexPe.Dock = 'Fill'; $lvHexPe.View = 'Details'; $lvHexPe.FullRowSelect = $true; $lvHexPe.GridLines = $false; $lvHexPe.HeaderStyle = 'Nonclickable'
$lvHexPe.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexPe.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexPe.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexPe.Columns.Add('Section', 70); [void]$lvHexPe.Columns.Add('Offset', 78); [void]$lvHexPe.Columns.Add('Size', 68); [void]$lvHexPe.Columns.Add('RVA', 68)
$pnlPeMode.Controls.Add($lvHexPe); $lvHexPe.BringToFront()
$hexInsPanel.Controls.Add($pnlPeMode)
# Mode C: XOR Decode (brute-force single-byte XOR)
$pnlXorMode = New-Object System.Windows.Forms.Panel
$pnlXorMode.Dock = 'Fill'; $pnlXorMode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $pnlXorMode.Visible = $false
$hexXorTop = New-Object System.Windows.Forms.Panel
$hexXorTop.Dock = 'Top'; $hexXorTop.Height = 54; $hexXorTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblXorRange = New-Object System.Windows.Forms.Label
$lblXorRange.Text = "Scans 64 KB from current offset"; $lblXorRange.Location = New-Object System.Drawing.Point(8, 6)
$lblXorRange.Size = New-Object System.Drawing.Size(260, 16); $lblXorRange.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexXorTop.Controls.Add($lblXorRange)
$btnXorScan = New-Object System.Windows.Forms.Button
$btnXorScan.Text = "Brute-force"; $btnXorScan.Location = New-Object System.Drawing.Point(8, 26); $btnXorScan.Size = New-Object System.Drawing.Size(106, 24)
$btnXorScan.FlatStyle = 'Flat'; $btnXorScan.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnXorScan.ForeColor = [System.Drawing.Color]::White
$hexXorTop.Controls.Add($btnXorScan)
$lblXorInfo = New-Object System.Windows.Forms.Label
$lblXorInfo.Text = ''; $lblXorInfo.Location = New-Object System.Drawing.Point(116, 30)
$lblXorInfo.Size = New-Object System.Drawing.Size(160, 16); $lblXorInfo.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexXorTop.Controls.Add($lblXorInfo)
$pnlXorMode.Controls.Add($hexXorTop)
$lvHexXor = New-Object System.Windows.Forms.ListView
$lvHexXor.Dock = 'Fill'; $lvHexXor.View = 'Details'; $lvHexXor.FullRowSelect = $true; $lvHexXor.GridLines = $false; $lvHexXor.HeaderStyle = 'Nonclickable'
$lvHexXor.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexXor.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexXor.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexXor.Columns.Add('Key', 48); [void]$lvHexXor.Columns.Add('Offset', 78); [void]$lvHexXor.Columns.Add('Decoded text', 148)
$pnlXorMode.Controls.Add($lvHexXor); $lvHexXor.BringToFront()
$hexInsPanel.Controls.Add($pnlXorMode)
# Mode D: Byte Frequency (byte distribution histogram)
$pnlFreqMode = New-Object System.Windows.Forms.Panel
$pnlFreqMode.Dock = 'Fill'; $pnlFreqMode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $pnlFreqMode.Visible = $false
$hexFreqTop = New-Object System.Windows.Forms.Panel
$hexFreqTop.Dock = 'Top'; $hexFreqTop.Height = 34; $hexFreqTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$btnFreqScan = New-Object System.Windows.Forms.Button
$btnFreqScan.Text = "Analyze"; $btnFreqScan.Location = New-Object System.Drawing.Point(8, 5); $btnFreqScan.Size = New-Object System.Drawing.Size(80, 24)
$btnFreqScan.FlatStyle = 'Flat'; $btnFreqScan.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnFreqScan.ForeColor = [System.Drawing.Color]::White
$hexFreqTop.Controls.Add($btnFreqScan)
$lblFreqInfo = New-Object System.Windows.Forms.Label
$lblFreqInfo.Text = ''; $lblFreqInfo.Location = New-Object System.Drawing.Point(96, 9)
$lblFreqInfo.Size = New-Object System.Drawing.Size(190, 16); $lblFreqInfo.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexFreqTop.Controls.Add($lblFreqInfo)
$pnlFreqMode.Controls.Add($hexFreqTop)
$lvHexFreq = New-Object System.Windows.Forms.ListView
$lvHexFreq.Dock = 'Fill'; $lvHexFreq.View = 'Details'; $lvHexFreq.FullRowSelect = $true; $lvHexFreq.GridLines = $false; $lvHexFreq.HeaderStyle = 'Nonclickable'
$lvHexFreq.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexFreq.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexFreq.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexFreq.Columns.Add('Byte', 52); [void]$lvHexFreq.Columns.Add('Count', 68); [void]$lvHexFreq.Columns.Add('%', 50); [void]$lvHexFreq.Columns.Add('Bar', 110)
$pnlFreqMode.Controls.Add($lvHexFreq); $lvHexFreq.BringToFront()
$hexInsPanel.Controls.Add($pnlFreqMode)
# Mode E: Bookmarks (saved offsets for quick navigation)
$pnlBmkMode = New-Object System.Windows.Forms.Panel
$pnlBmkMode.Dock = 'Fill'; $pnlBmkMode.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30); $pnlBmkMode.Visible = $false
$hexBmkTop = New-Object System.Windows.Forms.Panel
$hexBmkTop.Dock = 'Top'; $hexBmkTop.Height = 60; $hexBmkTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblBmkNote = New-Object System.Windows.Forms.Label
$lblBmkNote.Text = "note:"; $lblBmkNote.Location = New-Object System.Drawing.Point(8, 7); $lblBmkNote.Size = New-Object System.Drawing.Size(46, 16)
$lblBmkNote.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexBmkTop.Controls.Add($lblBmkNote)
$txtBmkNote = New-Object System.Windows.Forms.TextBox
$txtBmkNote.Location = New-Object System.Drawing.Point(56, 4); $txtBmkNote.Size = New-Object System.Drawing.Size(118, 22); $txtBmkNote.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtBmkNote.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtBmkNote.ForeColor = [System.Drawing.Color]::White; $txtBmkNote.BorderStyle = 'FixedSingle'
$hexBmkTop.Controls.Add($txtBmkNote)
$btnBmkAdd = New-Object System.Windows.Forms.Button
$btnBmkAdd.Text = "Add"; $btnBmkAdd.Location = New-Object System.Drawing.Point(180, 3); $btnBmkAdd.Size = New-Object System.Drawing.Size(52, 24)
$btnBmkAdd.FlatStyle = 'Flat'; $btnBmkAdd.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnBmkAdd.ForeColor = [System.Drawing.Color]::White
$hexBmkTop.Controls.Add($btnBmkAdd)
$btnBmkClear = New-Object System.Windows.Forms.Button
$btnBmkClear.Text = "Clear"; $btnBmkClear.Location = New-Object System.Drawing.Point(238, 3); $btnBmkClear.Size = New-Object System.Drawing.Size(58, 24)
$btnBmkClear.FlatStyle = 'Flat'; $btnBmkClear.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$hexBmkTop.Controls.Add($btnBmkClear)
$lblBmkInfo = New-Object System.Windows.Forms.Label
$lblBmkInfo.Text = "Bookmark the current offset"; $lblBmkInfo.Location = New-Object System.Drawing.Point(8, 34)
$lblBmkInfo.Size = New-Object System.Drawing.Size(280, 16); $lblBmkInfo.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexBmkTop.Controls.Add($lblBmkInfo)
$pnlBmkMode.Controls.Add($hexBmkTop)
$lvHexBmk = New-Object System.Windows.Forms.ListView
$lvHexBmk.Dock = 'Fill'; $lvHexBmk.View = 'Details'; $lvHexBmk.FullRowSelect = $true; $lvHexBmk.GridLines = $false; $lvHexBmk.HeaderStyle = 'Nonclickable'
$lvHexBmk.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexBmk.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexBmk.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexBmk.Columns.Add('Offset', 90); [void]$lvHexBmk.Columns.Add('Note', 190)
$pnlBmkMode.Controls.Add($lvHexBmk); $lvHexBmk.BringToFront()
$hexInsPanel.Controls.Add($pnlBmkMode)
# Mode F: PE Detail (CFF Explorer-equivalent deep analysis, widened to 440 px when active)
$piDark  = [System.Drawing.Color]::FromArgb(24, 24, 24)
$piWhite = [System.Drawing.Color]::White
$piMuted = [System.Drawing.Color]::FromArgb(180, 185, 190)
$piCyan  = [System.Drawing.Color]::FromArgb(86, 182, 194)
$piGray  = [System.Drawing.Color]::FromArgb(140, 140, 140)
$piRedBg = [System.Drawing.Color]::FromArgb(80, 30, 30);  $piRedFg = [System.Drawing.Color]::FromArgb(255, 140, 140)
$piOrgBg = [System.Drawing.Color]::FromArgb(70, 50, 20);  $piOrgFg = [System.Drawing.Color]::FromArgb(255, 200, 120)
$piYelBg = [System.Drawing.Color]::FromArgb(50, 50, 20);  $piYelFg = [System.Drawing.Color]::FromArgb(255, 220, 80)

$pnlPdMode = New-Object System.Windows.Forms.Panel
$pnlPdMode.Dock = 'Fill'; $pnlPdMode.BackColor = $piDark; $pnlPdMode.Visible = $false

$pdToolbar = New-Object System.Windows.Forms.Panel
$pdToolbar.Dock = 'Top'; $pdToolbar.Height = 28; $pdToolbar.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
$btnPdAnalyze = New-Object System.Windows.Forms.Button
$btnPdAnalyze.Text = 'Analyze'; $btnPdAnalyze.Location = New-Object System.Drawing.Point(4, 3); $btnPdAnalyze.Size = New-Object System.Drawing.Size(72, 22)
$btnPdAnalyze.FlatStyle = 'Flat'; $btnPdAnalyze.BackColor = [System.Drawing.Color]::FromArgb(0, 90, 120); $btnPdAnalyze.ForeColor = [System.Drawing.Color]::White
$pdToolbar.Controls.Add($btnPdAnalyze)
$lblPdNote = New-Object System.Windows.Forms.Label
$lblPdNote.Text = 'uses file loaded in Hex view'; $lblPdNote.Location = New-Object System.Drawing.Point(82, 7)
$lblPdNote.Size = New-Object System.Drawing.Size(220, 16); $lblPdNote.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$lblPdNote.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$pdToolbar.Controls.Add($lblPdNote)
$pnlPdMode.Controls.Add($pdToolbar)

$lblPdStatus = New-Object System.Windows.Forms.Label
$lblPdStatus.Dock = 'Top'; $lblPdStatus.Height = 18
$lblPdStatus.Text = 'Click Analyze to inspect the file loaded in the Hex view.'
$lblPdStatus.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
$lblPdStatus.Padding = New-Object System.Windows.Forms.Padding(4, 1, 0, 0)
$lblPdStatus.Font = New-Object System.Drawing.Font('Segoe UI', 7.5)
$pnlPdMode.Controls.Add($lblPdStatus)

$pdMain = New-Object System.Windows.Forms.TabControl
$pdMain.Dock = 'Fill'; $pdMain.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)

$pdTabSum = New-Object System.Windows.Forms.TabPage; $pdTabSum.Text = 'Sum'; $pdTabSum.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$pdMain.TabPages.Add($pdTabSum)
$txtPiSum = New-Object System.Windows.Forms.RichTextBox
$txtPiSum.Dock = 'Fill'; $txtPiSum.ReadOnly = $true; $txtPiSum.WordWrap = $false
$txtPiSum.Font = New-Object System.Drawing.Font('Consolas', 8.5); $txtPiSum.BackColor = $piDark; $txtPiSum.ForeColor = $piWhite
$txtPiSum.Text = 'Click Analyze.'; $pdTabSum.Controls.Add($txtPiSum)

$pdTabSec = New-Object System.Windows.Forms.TabPage; $pdTabSec.Text = 'Secs'; $pdTabSec.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$pdMain.TabPages.Add($pdTabSec)
$lvPiSec = New-Object System.Windows.Forms.ListView
$lvPiSec.Dock = 'Fill'; $lvPiSec.View = 'Details'; $lvPiSec.FullRowSelect = $true; $lvPiSec.GridLines = $true
$lvPiSec.HeaderStyle = 'Nonclickable'; $lvPiSec.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$lvPiSec.BackColor = $piDark; $lvPiSec.ForeColor = $piWhite
[void]$lvPiSec.Columns.Add('Name', 65); [void]$lvPiSec.Columns.Add('VirtAddr', 82)
[void]$lvPiSec.Columns.Add('VirtSize', 70); [void]$lvPiSec.Columns.Add('RawOff', 82)
[void]$lvPiSec.Columns.Add('RawSz', 65); [void]$lvPiSec.Columns.Add('Entropy', 58)
[void]$lvPiSec.Columns.Add('Flag', 95); [void]$lvPiSec.Columns.Add('Chars', 130)
$pdTabSec.Controls.Add($lvPiSec); $lvPiSec.BringToFront()

$pdTabExp = New-Object System.Windows.Forms.TabPage; $pdTabExp.Text = 'Exp'; $pdTabExp.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$pdMain.TabPages.Add($pdTabExp)
$lvPiExp = New-Object System.Windows.Forms.ListView
$lvPiExp.Dock = 'Fill'; $lvPiExp.View = 'Details'; $lvPiExp.FullRowSelect = $true; $lvPiExp.GridLines = $true
$lvPiExp.HeaderStyle = 'Nonclickable'; $lvPiExp.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$lvPiExp.BackColor = $piDark; $lvPiExp.ForeColor = $piWhite
[void]$lvPiExp.Columns.Add('Name', 165); [void]$lvPiExp.Columns.Add('Ord', 48)
[void]$lvPiExp.Columns.Add('RVA', 72); [void]$lvPiExp.Columns.Add('Fwd', 48)
[void]$lvPiExp.Columns.Add('Forward Target', 230)
$pdTabExp.Controls.Add($lvPiExp); $lvPiExp.BringToFront()

$pdTabRich = New-Object System.Windows.Forms.TabPage; $pdTabRich.Text = 'Rich'; $pdTabRich.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$pdMain.TabPages.Add($pdTabRich)
$pdRichHdr = New-Object System.Windows.Forms.Panel; $pdRichHdr.Dock = 'Top'; $pdRichHdr.Height = 24; $pdRichHdr.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblPiRichHint = New-Object System.Windows.Forms.Label; $lblPiRichHint.Dock = 'Fill'; $lblPiRichHint.TextAlign = 'MiddleLeft'
$lblPiRichHint.Padding = New-Object System.Windows.Forms.Padding(4, 0, 0, 0); $lblPiRichHint.ForeColor = $piMuted
$lblPiRichHint.Text = 'Compiler/linker fingerprint in the DOS stub (XOR-encoded).'
$lblPiRichHint.Font = New-Object System.Drawing.Font('Segoe UI', 7.5); $pdRichHdr.Controls.Add($lblPiRichHint)
$pdTabRich.Controls.Add($pdRichHdr)
$lvPiRich = New-Object System.Windows.Forms.ListView
$lvPiRich.Dock = 'Fill'; $lvPiRich.View = 'Details'; $lvPiRich.FullRowSelect = $true; $lvPiRich.GridLines = $true
$lvPiRich.HeaderStyle = 'Nonclickable'; $lvPiRich.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$lvPiRich.BackColor = $piDark; $lvPiRich.ForeColor = $piWhite
[void]$lvPiRich.Columns.Add('ToolId', 52); [void]$lvPiRich.Columns.Add('Tool', 135)
[void]$lvPiRich.Columns.Add('Build#', 60); [void]$lvPiRich.Columns.Add('Cnt', 52)
$pdTabRich.Controls.Add($lvPiRich); $lvPiRich.BringToFront()

$pdTabVer = New-Object System.Windows.Forms.TabPage; $pdTabVer.Text = 'Ver'; $pdTabVer.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$pdMain.TabPages.Add($pdTabVer)
$txtPiVer = New-Object System.Windows.Forms.RichTextBox
$txtPiVer.Dock = 'Fill'; $txtPiVer.ReadOnly = $true; $txtPiVer.WordWrap = $false
$txtPiVer.Font = New-Object System.Drawing.Font('Consolas', 8.5); $txtPiVer.BackColor = $piDark; $txtPiVer.ForeColor = $piWhite
$txtPiVer.Text = 'Click Analyze.'; $pdTabVer.Controls.Add($txtPiVer)

$pnlPdMode.Controls.Add($pdMain); $pdMain.BringToFront()
$hexInsPanel.Controls.Add($pnlPdMode)
$hexBody.Controls.Add($hexInsPanel)
# --- Center column: entropy strip + hex view + strings panel ---
$hexCenter = New-Object System.Windows.Forms.Panel
$hexCenter.Dock = 'Fill'
# Strings wrapper: toggle-able bottom panel with its own toolbar + results list
$pnlStrWrap = New-Object System.Windows.Forms.Panel
$pnlStrWrap.Dock = 'Bottom'; $pnlStrWrap.Height = 350; $pnlStrWrap.Visible = $false
$strBar = New-Object System.Windows.Forms.Panel
$strBar.Dock = 'Top'; $strBar.Height = 32; $strBar.BackColor = [System.Drawing.Color]::FromArgb(38, 38, 38)
$lblHexSMinL = New-Object System.Windows.Forms.Label
$lblHexSMinL.Text = "min:"; $lblHexSMinL.Location = New-Object System.Drawing.Point(8, 8); $lblHexSMinL.Size = New-Object System.Drawing.Size(38, 16)
$lblHexSMinL.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$strBar.Controls.Add($lblHexSMinL)
$txtHexSMin = New-Object System.Windows.Forms.TextBox
$txtHexSMin.Text = "4"; $txtHexSMin.Location = New-Object System.Drawing.Point(48, 5); $txtHexSMin.Size = New-Object System.Drawing.Size(36, 22); $txtHexSMin.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexSMin.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexSMin.ForeColor = [System.Drawing.Color]::White; $txtHexSMin.BorderStyle = 'FixedSingle'
$strBar.Controls.Add($txtHexSMin)
$lblHexSFilterL = New-Object System.Windows.Forms.Label
$lblHexSFilterL.Text = "filter:"; $lblHexSFilterL.Location = New-Object System.Drawing.Point(86, 8); $lblHexSFilterL.Size = New-Object System.Drawing.Size(62, 16)
$lblHexSFilterL.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$strBar.Controls.Add($lblHexSFilterL)
$txtHexSFilter = New-Object System.Windows.Forms.TextBox
$txtHexSFilter.Location = New-Object System.Drawing.Point(152, 5); $txtHexSFilter.Size = New-Object System.Drawing.Size(120, 22); $txtHexSFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtHexSFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexSFilter.ForeColor = [System.Drawing.Color]::White; $txtHexSFilter.BorderStyle = 'FixedSingle'
$strBar.Controls.Add($txtHexSFilter)
$cmbHexSKind = New-Object System.Windows.Forms.ComboBox
$cmbHexSKind.Location = New-Object System.Drawing.Point(276, 5); $cmbHexSKind.Size = New-Object System.Drawing.Size(96, 22); $cmbHexSKind.DropDownStyle = 'DropDownList'
$cmbHexSKind.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbHexSKind.ForeColor = [System.Drawing.Color]::FromArgb(200, 205, 210); $cmbHexSKind.FlatStyle = 'Flat'
@('ascii+wide', 'ascii', 'wide') | ForEach-Object { [void]$cmbHexSKind.Items.Add($_) }; $cmbHexSKind.SelectedIndex = 0
$strBar.Controls.Add($cmbHexSKind)
$btnHexStrings = New-Object System.Windows.Forms.Button
$btnHexStrings.Text = "Search"; $btnHexStrings.Location = New-Object System.Drawing.Point(376, 4); $btnHexStrings.Size = New-Object System.Drawing.Size(68, 24)
$btnHexStrings.FlatStyle = 'Flat'; $btnHexStrings.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnHexStrings.ForeColor = [System.Drawing.Color]::White
$strBar.Controls.Add($btnHexStrings)
$lblHexSInfo = New-Object System.Windows.Forms.Label
$lblHexSInfo.Location = New-Object System.Drawing.Point(452, 8); $lblHexSInfo.Size = New-Object System.Drawing.Size(300, 16); $lblHexSInfo.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$strBar.Controls.Add($lblHexSInfo)
$pnlStrWrap.Controls.Add($strBar)
$lvHexStr = New-Object System.Windows.Forms.ListView
$lvHexStr.Dock = 'Fill'
$lvHexStr.View = 'Details'; $lvHexStr.FullRowSelect = $true; $lvHexStr.GridLines = $false; $lvHexStr.HeaderStyle = 'Nonclickable'; $lvHexStr.MultiSelect = $false
$lvHexStr.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexStr.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexStr.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexStr.Columns.Add('Offset', 90); [void]$lvHexStr.Columns.Add('K', 34)
[void]$lvHexStr.Columns.Add('Category', 100); [void]$lvHexStr.Columns.Add('String (click to jump)', 1060)
$pnlStrWrap.Controls.Add($lvHexStr); $lvHexStr.BringToFront()
$hexCenter.Controls.Add($pnlStrWrap)
$splStrWrap = New-Object System.Windows.Forms.Splitter
$splStrWrap.Dock = 'Bottom'; $splStrWrap.Height = 5
$splStrWrap.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
$hexCenter.Controls.Add($splStrWrap)
# Entropy heatmap strip (whole-file minimap, click to jump)
$pnlEntropy = New-Object System.Windows.Forms.Panel
$pnlEntropy.Dock = 'Left'; $pnlEntropy.Width = 20; $pnlEntropy.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
$pnlEntropy.Add_Paint({
    $ent = $script:HexEntropy; if (-not $ent -or $ent.Count -eq 0) { return }
    $gr = $_.Graphics; $w = $pnlEntropy.Width; $h = $pnlEntropy.Height; if ($h -le 0) { return }
    $nc = $ent.Count
    for ($py = 0; $py -lt $h; $py++) {
        $bi = [int]([Math]::Floor($py * $nc / $h)); if ($bi -ge $nc) { $bi = $nc - 1 }
        $e = $ent[$bi]
        if ($e -lt 2) { $cr = 30; $cg = 40; $cb = [int](60 + $e * 60) }
        elseif ($e -lt 5) { $t2 = ($e - 2) / 3; $cr = [int](30 + $t2 * 80); $cg = [int](120 + $t2 * 60); $cb = [int](120 - $t2 * 80) }
        elseif ($e -lt 7) { $t2 = ($e - 5) / 2; $cr = [int](180 + $t2 * 75); $cg = [int](180 - $t2 * 100); $cb = 30 }
        else { $cr = 255; $cg = [int]([Math]::Max(0, 80 - ($e - 7) * 80)); $cb = 30 }
        $ebr = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb([Math]::Min(255,$cr), [Math]::Min(255,$cg), [Math]::Min(255,$cb)))
        $gr.FillRectangle($ebr, 0, $py, $w, 1); $ebr.Dispose()
    }
    if ($script:HexSize -gt 0) {
        $my = [int]([Math]::Floor($script:HexOffset * $h / $script:HexSize))
        $mh = [int][Math]::Max(2, [Math]::Ceiling($script:HexPageSize * $h / $script:HexSize))
        $epen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 1)
        $gr.DrawRectangle($epen, 0, [Math]::Min($my, $h - 1), $w - 1, [Math]::Min($mh, $h - $my - 1)); $epen.Dispose()
    }
})
$pnlEntropy.Add_MouseClick({
    if (-not $script:HexSize -or $script:HexSize -le 0 -or $pnlEntropy.Height -le 0) { return }
    $joff = [int64]([Math]::Floor($_.Y * $script:HexSize / $pnlEntropy.Height))
    $joff = [int64]([Math]::Floor($joff / 16) * 16)
    Load-GuiHex $joff
})
$hexCenter.Controls.Add($pnlEntropy)
$txtHex = New-Object System.Windows.Forms.RichTextBox
$txtHex.Dock = 'Fill'; $txtHex.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtHex.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18); $txtHex.ForeColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
$txtHex.ReadOnly = $true; $txtHex.WordWrap = $false; $txtHex.BorderStyle = 'None'; $txtHex.HideSelection = $false
$hexCtxMenu = New-Object System.Windows.Forms.ContextMenuStrip
$hexCtxCopyHex = $hexCtxMenu.Items.Add('Copy page as hex string')
$hexCtxCopyC = $hexCtxMenu.Items.Add('Copy page as C array')
$hexCtxCopyPy = $hexCtxMenu.Items.Add('Copy page as Python bytes')
$hexCtxCopyPs = $hexCtxMenu.Items.Add('Copy page as PS byte[]')
$hexCtxMenu.Items.Add('-')
$hexCtxBmk = $hexCtxMenu.Items.Add('Bookmark this offset')
$txtHex.ContextMenuStrip = $hexCtxMenu
$hexCenter.Controls.Add($txtHex); $txtHex.BringToFront()
$hexBody.Controls.Add($hexCenter); $hexCenter.BringToFront()
$tabHex.Controls.Add($hexBody); $hexBody.BringToFront()
# --- Event handlers ---
$btnHexBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtHexPath.Text = $dlg.FileName }
})
$btnHexLoad.Add_Click({
    $script:HexHl = [int64]-1; $script:HexPeMap = $null; $script:HexPeOverlay = $false; $script:HexHashes = $null
    $script:HexDiffPath = ''; $btnHexDiff.Text = 'Diff...'; $btnHexDiff.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $btnHexPe.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnHexHash.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $btnHexStrTog.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $pnlStrWrap.Visible = $false
    Load-GuiHex 0
    $lp = $txtHexPath.Text.Trim()
    if ($lp -and (Test-Path -LiteralPath $lp -PathType Leaf)) {
        $ebs = [int][Math]::Max(256, [int][Math]::Ceiling([int64](Get-Item -LiteralPath $lp).Length / 2000))
        $script:HexEntropy = Get-GuiBlockEntropy $lp $ebs
        $pnlEntropy.Invalidate()
        $script:HexHashes = Get-GuiFileHashes $lp
    }
})
$btnHexPrev.Add_Click({ Load-GuiHex ($script:HexOffset - $script:HexPageSize) })
$btnHexNext.Add_Click({ if (-not $script:HexSize -or ($script:HexOffset + $script:HexPageSize) -lt $script:HexSize) { Load-GuiHex ($script:HexOffset + $script:HexPageSize) } })
$btnHexInspect.Add_Click({ Do-GuiHexInspect ([int64]-1) })
$btnHexGo.Add_Click({ try { $o = [Convert]::ToInt64(($txtHexGoto.Text.Trim() -replace '^0x', ''), 16) } catch { $lblHex.Text = 'bad hex offset'; return }; Do-GuiHexInspect $o })
$btnHexFind.Add_Click({
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHex.Text = 'load a file first'; return }
    $q = $txtHexFind.Text; if (-not $q) { $lblHex.Text = 'enter a search'; return }
    $from = if ($script:HexHl -ge 0) { $script:HexHl + 1 } else { [int64]0 }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $o = Find-GuiHexOffset $p $q ([string]$cmbHexKind.SelectedItem) $from
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    # -2 ('file too large to search') is gone: Find-GuiHexOffset streams now and has no
    # size limit, so there is no longer a size at which the search declines to run.
    if ($o -eq [int64]-3) { $lblHex.Text = 'hex needs an even number of hex digits' }
    elseif ($o -lt 0) { $lblHex.Text = "no match from 0x$([Convert]::ToString($from,16))" }
    else { Do-GuiHexInspect $o; $lblHex.Text = "match at 0x$([Convert]::ToString($o,16))" }
})
$txtHex.Add_MouseUp({
    if (-not $script:HexPath) { return }
    try { $ci2 = $txtHex.GetCharIndexFromPosition($_.Location); $line = $txtHex.GetLineFromCharIndex($ci2); $off = $script:HexOffset + ($line * 16); Do-GuiHexInspect $off } catch { }
})
$btnHexStrings.Add_Click({ Do-GuiHexStrings })
$lvHexStr.Add_Click({ if ($lvHexStr.SelectedItems.Count -and $null -ne $lvHexStr.SelectedItems[0].Tag) { Do-GuiHexInspect ([int64]$lvHexStr.SelectedItems[0].Tag) } })
# Right-panel mode switching
$cmbHexMode.Add_SelectedIndexChanged({
    $mi = $cmbHexMode.SelectedIndex
    $pnlInsMode.Visible = ($mi -eq 0); $pnlPeMode.Visible = ($mi -eq 1); $pnlXorMode.Visible = ($mi -eq 2)
    $pnlFreqMode.Visible = ($mi -eq 3); $pnlBmkMode.Visible = ($mi -eq 4); $pnlPdMode.Visible = ($mi -eq 5)
    $modePnls = @($pnlInsMode, $pnlPeMode, $pnlXorMode, $pnlFreqMode, $pnlBmkMode, $pnlPdMode)
    if ($mi -ge 0 -and $mi -lt $modePnls.Count) { $modePnls[$mi].BringToFront() }
    # PE Detail needs more horizontal space for its multi-column ListViews
    $hexInsPanel.Width = if ($mi -eq 5) { 440 } else { 300 }
})
$btnPdAnalyze.Add_Click({
    $p = "$($txtHexPath.Text)".Trim()
    if (-not $p) { $lblPdStatus.Text = 'Load a file in the Hex view first, then click Analyze.'; return }
    Load-PeInfo $p
})
# PE overlay toggle
$btnHexPe.Add_Click({
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHex.Text = 'load a file first'; return }
    # Toggle off: return to plain hex view
    if ($script:HexPeOverlay) {
        $script:HexPeOverlay = $false; $script:HexPeMap = $null
        $btnHexPe.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        $cmbHexMode.SelectedIndex = 0; Load-GuiHex $script:HexOffset; return
    }
    # Load PE section map for hex color overlay
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $pm = Get-GuiPeMap $p
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    if (-not $pm) { $lblHex.Text = 'not a valid PE file'; return }
    $script:HexPeMap = $pm; $script:HexPeOverlay = $true
    $btnHexPe.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
    # Fill PE Map list (used by PE Map mode)
    $lvHexPe.BeginUpdate(); $lvHexPe.Items.Clear()
    $hit = New-Object System.Windows.Forms.ListViewItem('Headers')
    [void]$hit.SubItems.Add('0x0'); [void]$hit.SubItems.Add("0x$($pm.HeaderEnd.ToString('x'))"); [void]$hit.SubItems.Add('0x0')
    $hit.ForeColor = [System.Drawing.Color]::FromArgb(100, 180, 180); $hit.Tag = [int64]0; [void]$lvHexPe.Items.Add($hit)
    foreach ($s in $pm.Sections) {
        $sit = New-Object System.Windows.Forms.ListViewItem($s.Name)
        [void]$sit.SubItems.Add("0x$($s.RawOff.ToString('x'))"); [void]$sit.SubItems.Add("0x$($s.RawSize.ToString('x'))"); [void]$sit.SubItems.Add("0x$($s.VA.ToString('x'))")
        $sit.ForeColor = [System.Drawing.Color]::FromArgb($s.R, $s.G, $s.B); $sit.Tag = $s.RawOff; [void]$lvHexPe.Items.Add($sit)
    }
    $lvHexPe.EndUpdate()
    $lblPeInfo.Text = "$($pm.TypeStr) | $($pm.Machine)"
    $lvHexPeImp.BeginUpdate(); $lvHexPeImp.Items.Clear()
    foreach ($imp in $pm.Imports) { [void]$lvHexPeImp.Items.Add($imp) }
    $lvHexPeImp.EndUpdate()
    # Switch to PE Detail mode and run full analysis
    $cmbHexMode.SelectedIndex = 5
    Load-GuiHex $script:HexOffset
    Load-PeInfo $p
})
# PE section click -> jump to that file offset
$lvHexPe.Add_Click({
    if ($lvHexPe.SelectedItems.Count -and $null -ne $lvHexPe.SelectedItems[0].Tag) {
        Do-GuiHexInspect ([int64]$lvHexPe.SelectedItems[0].Tag)
    }
})
# Binary diff toggle
$btnHexDiff.Add_Click({
    if ($script:HexDiffPath) {
        $script:HexDiffPath = ''; $btnHexDiff.Text = 'Diff...'
        $btnHexDiff.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
        Load-GuiHex $script:HexOffset; return
    }
    $ddlg = New-Object System.Windows.Forms.OpenFileDialog; $ddlg.Filter = "All files (*.*)|*.*"; $ddlg.Title = "Select comparison file"
    if ($ddlg.ShowDialog() -ne 'OK') { return }
    $script:HexDiffPath = $ddlg.FileName
    $btnHexDiff.Text = 'X Diff'; $btnHexDiff.BackColor = [System.Drawing.Color]::FromArgb(192, 57, 43)
    Load-GuiHex $script:HexOffset
})
# XOR brute-force scan
$btnXorScan.Add_Click({
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblXorInfo.Text = 'load a file first'; return }
    $lblXorInfo.Text = 'scanning...'; $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $xhits = Do-GuiXorScan $p $script:HexOffset 65536 6
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $lvHexXor.BeginUpdate(); $lvHexXor.Items.Clear()
    foreach ($xh in $xhits) {
        $xit = New-Object System.Windows.Forms.ListViewItem($xh.KeyHex)
        [void]$xit.SubItems.Add("0x$($xh.Offset.ToString('x'))"); [void]$xit.SubItems.Add($xh.Text)
        $xit.Tag = [int64]$xh.Offset; [void]$lvHexXor.Items.Add($xit)
    }
    $lvHexXor.EndUpdate()
    $lblXorInfo.Text = "$($xhits.Count) hit$(if($xhits.Count -ne 1){'s'})"
})
# XOR result click -> jump to offset
$lvHexXor.Add_Click({
    if ($lvHexXor.SelectedItems.Count -and $null -ne $lvHexXor.SelectedItems[0].Tag) {
        Do-GuiHexInspect ([int64]$lvHexXor.SelectedItems[0].Tag)
    }
})
# Strings panel toggle
$btnHexStrTog.Add_Click({
    if ($pnlStrWrap.Visible) {
        $pnlStrWrap.Visible = $false; $btnHexStrTog.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    } else {
        $pnlStrWrap.Visible = $true; $btnHexStrTog.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
        Do-GuiHexStrings
    }
})
# Hash button: compute + copy to clipboard
$btnHexHash.Add_Click({
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHex.Text = 'load a file first'; return }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $lblHex.Text = 'file not found'; return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $script:HexHashes = Get-GuiFileHashes $p
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    if (-not $script:HexHashes) { $lblHex.Text = 'hash failed'; return }
    $h = $script:HexHashes
    $clip = "MD5:    $($h.MD5)`r`nSHA1:   $($h.SHA1)`r`nSHA256: $($h.SHA256)"
    [System.Windows.Forms.Clipboard]::SetText($clip)
    $lblHex.Text = "MD5: $($h.MD5.Substring(0,16))... SHA256: $($h.SHA256.Substring(0,16))... (copied)"
    $btnHexHash.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
})
# Byte frequency analysis
$btnFreqScan.Add_Click({
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblFreqInfo.Text = 'load a file first'; return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents()
    $bf = Get-GuiByteFrequency $p
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    if (-not $bf -or $bf.Total -eq 0) { $lblFreqInfo.Text = 'empty file'; return }
    $mx = 0; for ($v = 0; $v -lt 256; $v++) { if ($bf.Counts[$v] -gt $mx) { $mx = $bf.Counts[$v] } }
    $sorted = 0..255 | Sort-Object { -$bf.Counts[$_] }
    $nonzero = 0; for ($v = 0; $v -lt 256; $v++) { if ($bf.Counts[$v] -gt 0) { $nonzero++ } }
    $lvHexFreq.BeginUpdate(); $lvHexFreq.Items.Clear()
    foreach ($v in $sorted) {
        $c = $bf.Counts[$v]; if ($c -eq 0) { continue }
        $pct = [Math]::Round($c * 100.0 / $bf.Total, 2)
        $barLen = if ($mx -gt 0) { [int][Math]::Round($c * 16.0 / $mx) } else { 0 }
        $bar = New-Object string '#', $barLen
        $it = New-Object System.Windows.Forms.ListViewItem("0x$($v.ToString('x2'))")
        [void]$it.SubItems.Add($c.ToString('N0')); [void]$it.SubItems.Add("$pct"); [void]$it.SubItems.Add($bar)
        if ($c -eq $mx) { $it.ForeColor = [System.Drawing.Color]::FromArgb(78, 201, 176) }
        [void]$lvHexFreq.Items.Add($it)
    }
    $lvHexFreq.EndUpdate()
    $lblFreqInfo.Text = "$nonzero/256 distinct bytes"
})
# Bookmark add
$btnBmkAdd.Add_Click({
    $off = $script:HexHl; if ($off -lt 0) { $off = $script:HexOffset }
    $note = $txtBmkNote.Text.Trim(); if (-not $note) { $note = "offset 0x$([Convert]::ToString($off, 16))" }
    $script:HexBookmarks.Add([pscustomobject]@{ Offset = $off; Note = $note })
    $it = New-Object System.Windows.Forms.ListViewItem("0x$([Convert]::ToString($off, 16))")
    [void]$it.SubItems.Add($note); $it.Tag = $off; [void]$lvHexBmk.Items.Add($it)
    $txtBmkNote.Text = ''
    $lblBmkInfo.Text = "$($script:HexBookmarks.Count) bookmark$(if($script:HexBookmarks.Count -ne 1){'s'})"
})
# Bookmark clear
$btnBmkClear.Add_Click({
    $script:HexBookmarks.Clear(); $lvHexBmk.Items.Clear()
    $lblBmkInfo.Text = 'Bookmark the current offset'
})
# Bookmark click -> jump
$lvHexBmk.Add_Click({
    if ($lvHexBmk.SelectedItems.Count -and $null -ne $lvHexBmk.SelectedItems[0].Tag) {
        Do-GuiHexInspect ([int64]$lvHexBmk.SelectedItems[0].Tag)
    }
})
# Context menu: copy as hex string
$hexCtxCopyHex.Add_Click({
    $p = $script:HexPath; if (-not $p) { return }
    $buf = New-Object 'byte[]' $script:HexPageSize
    $fs = [IO.File]::OpenRead($p); try { [void]$fs.Seek($script:HexOffset, 'Begin'); $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    $sb = New-Object System.Text.StringBuilder ($n * 2)
    for ($i = 0; $i -lt $n; $i++) { [void]$sb.AppendFormat('{0:x2}', $buf[$i]) }
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString()); $lblHex.Text = "$n bytes copied as hex string"
})
# Context menu: copy as C array
$hexCtxCopyC.Add_Click({
    $p = $script:HexPath; if (-not $p) { return }
    $buf = New-Object 'byte[]' $script:HexPageSize
    $fs = [IO.File]::OpenRead($p); try { [void]$fs.Seek($script:HexOffset, 'Begin'); $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    $sb = New-Object System.Text.StringBuilder; [void]$sb.Append("unsigned char buf[$n] = {`r`n    ")
    for ($i = 0; $i -lt $n; $i++) {
        [void]$sb.AppendFormat('0x{0:x2}', $buf[$i])
        if ($i -lt $n - 1) { [void]$sb.Append(', ') }
        if (($i + 1) % 16 -eq 0 -and $i -lt $n - 1) { [void]$sb.Append("`r`n    ") }
    }
    [void]$sb.Append("`r`n};")
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString()); $lblHex.Text = "$n bytes copied as C array"
})
# Context menu: copy as Python bytes
$hexCtxCopyPy.Add_Click({
    $p = $script:HexPath; if (-not $p) { return }
    $buf = New-Object 'byte[]' $script:HexPageSize
    $fs = [IO.File]::OpenRead($p); try { [void]$fs.Seek($script:HexOffset, 'Begin'); $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    $sb = New-Object System.Text.StringBuilder; [void]$sb.Append("buf = b'")
    for ($i = 0; $i -lt $n; $i++) { [void]$sb.AppendFormat('\x{0:x2}', $buf[$i]) }
    [void]$sb.Append("'")
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString()); $lblHex.Text = "$n bytes copied as Python bytes"
})
# Context menu: copy as PS byte[]
$hexCtxCopyPs.Add_Click({
    $p = $script:HexPath; if (-not $p) { return }
    $buf = New-Object 'byte[]' $script:HexPageSize
    $fs = [IO.File]::OpenRead($p); try { [void]$fs.Seek($script:HexOffset, 'Begin'); $n = $fs.Read($buf, 0, $buf.Length) } finally { $fs.Dispose() }
    $sb = New-Object System.Text.StringBuilder; [void]$sb.Append('[byte[]]@(')
    for ($i = 0; $i -lt $n; $i++) {
        [void]$sb.AppendFormat('0x{0:x2}', $buf[$i])
        if ($i -lt $n - 1) { [void]$sb.Append(',') }
        if (($i + 1) % 20 -eq 0 -and $i -lt $n - 1) { [void]$sb.Append("`r`n") }
    }
    [void]$sb.Append(')')
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString()); $lblHex.Text = "$n bytes copied as PS byte[]"
})
# Context menu: bookmark current offset
$hexCtxBmk.Add_Click({
    $off = $script:HexHl; if ($off -lt 0) { $off = $script:HexOffset }
    $script:HexBookmarks.Add([pscustomobject]@{ Offset = $off; Note = "0x$([Convert]::ToString($off, 16))" })
    $it = New-Object System.Windows.Forms.ListViewItem("0x$([Convert]::ToString($off, 16))")
    [void]$it.SubItems.Add("0x$([Convert]::ToString($off, 16))"); $it.Tag = $off; [void]$lvHexBmk.Items.Add($it)
    $lblHex.Text = "Bookmarked offset 0x$([Convert]::ToString($off, 16))"
})

# Wire the Asar "Hex view" button (created in the Asar top row) now that the Hex tab exists.
$btnAsarHex.Add_Click({
    if (-not $script:AsarLastFull) { $lblAsar.Text = "Select a file first, then Hex view."; return }
    $txtHexPath.Text = $script:AsarLastFull; $tabs.SelectedTab = $tabHex; Load-GuiHex 0
})

# ================= TAB: DLL Decompiler (.NET assembly browser) =================
# Browse a .NET assembly's types + methods and view IL (always, via the bundled
# Mono.Cecil) or decompiled C# (via ilspycmd if installed; byte-context fallback).
# The GUI reads the assembly InMemory (no file lock) so it never collides with an
# in-flight audit that also parses the same DLL.
$tabDec = New-Object System.Windows.Forms.TabPage
$tabDec.Text = ' Decompiler '
$tabDec.BackColor = [System.Drawing.Color]::FromArgb(13, 16, 22)
[void]$tabs.TabPages.Add($tabDec)

$script:DecAsm     = $null    # GUI-owned Mono.Cecil AssemblyDefinition (InMemory)
$script:DecTypes   = $null    # all TypeDefinitions of the loaded module
$script:DecDllPath = $null    # path of the loaded assembly
$script:DecCurMethod = $null  # currently selected MethodDefinition

# --- toolbar (Top): two TableLayoutPanel rows so it stays aligned at ANY window width
# (absolute positions + Right-anchor broke when the window was maximized). ---
$decBar = New-Object System.Windows.Forms.Panel
$decBar.Dock = 'Top'; $decBar.Height = 80
$tabDec.Controls.Add($decBar)

$anchLR = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$mkFillLabel = {
    param($text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text; $l.Dock = 'Fill'; $l.TextAlign = 'MiddleLeft'; $l.Margin = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)
    $l
}

# Row 1: Assembly: | combo (stretch) | Browse | Scan target | Load
$decRow1 = New-Object System.Windows.Forms.TableLayoutPanel
$decRow1.Dock = 'Top'; $decRow1.Height = 42; $decRow1.ColumnCount = 5; $decRow1.RowCount = 1
[void]$decRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 84)))
[void]$decRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$decRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$decRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 116)))
[void]$decRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 88)))

$lblDecAsm = & $mkFillLabel 'Assembly:'
$decRow1.Controls.Add($lblDecAsm, 0, 0)

$cmbDecDll = New-Object System.Windows.Forms.ComboBox
$cmbDecDll.DropDownStyle = 'DropDown'; $cmbDecDll.Anchor = $anchLR; $cmbDecDll.Margin = New-Object System.Windows.Forms.Padding(2, 8, 6, 0)
$decRow1.Controls.Add($cmbDecDll, 1, 0)

$btnDecBrowse = New-Object System.Windows.Forms.Button
$btnDecBrowse.Text = 'Browse...'; $btnDecBrowse.Dock = 'Fill'; $btnDecBrowse.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$decRow1.Controls.Add($btnDecBrowse, 2, 0)

$btnDecScan = New-Object System.Windows.Forms.Button
$btnDecScan.Text = 'Scan target'; $btnDecScan.Dock = 'Fill'; $btnDecScan.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$decRow1.Controls.Add($btnDecScan, 3, 0)

$btnDecLoad = New-Object System.Windows.Forms.Button
$btnDecLoad.Text = 'Load'; $btnDecLoad.Dock = 'Fill'; $btnDecLoad.Margin = New-Object System.Windows.Forms.Padding(2, 6, 6, 6)
$decRow1.Controls.Add($btnDecLoad, 4, 0)

# Row 2: Filter types: | filter box | status (stretch)
$decRow2 = New-Object System.Windows.Forms.TableLayoutPanel
$decRow2.Dock = 'Top'; $decRow2.Height = 34; $decRow2.ColumnCount = 3; $decRow2.RowCount = 1
[void]$decRow2.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 84)))
[void]$decRow2.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 290)))
[void]$decRow2.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

$lblDecFilter = & $mkFillLabel 'Filter types:'
$decRow2.Controls.Add($lblDecFilter, 0, 0)

$txtDecFilter = New-Object System.Windows.Forms.TextBox
$txtDecFilter.Anchor = $anchLR; $txtDecFilter.Margin = New-Object System.Windows.Forms.Padding(2, 6, 6, 0)
$decRow2.Controls.Add($txtDecFilter, 1, 0)

$lblDecStatus = & $mkFillLabel 'Load a .NET assembly (Browse, or Scan target) to browse its types + methods.'
$decRow2.Controls.Add($lblDecStatus, 2, 0)

# add row2 first, then row1, so row1 (Assembly) docks ABOVE row2 (Filter)
$decBar.Controls.Add($decRow2)
$decBar.Controls.Add($decRow1)

# --- main area (Fill): Types | Methods | Code ---
$decMain = New-Object System.Windows.Forms.TableLayoutPanel
$decMain.Dock = 'Fill'; $decMain.ColumnCount = 3; $decMain.RowCount = 1
$decMain.BackColor = [System.Drawing.Color]::FromArgb(13, 16, 22)
[void]$decMain.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 24)))
[void]$decMain.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 26)))
[void]$decMain.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$decMain.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$tabDec.Controls.Add($decMain)
# Fill body must be front-most so the Top toolbar carves its strip first (same pattern
# as $asarBody / $hexBody / $txtPmon); otherwise decBar overlaps the top of decMain.
$decMain.BringToFront()

# column helper: a Panel with a Top title label + a Fill body control
$decTypesBox = New-Object System.Windows.Forms.Panel; $decTypesBox.Dock = 'Fill'; $decTypesBox.Margin = New-Object System.Windows.Forms.Padding(6, 4, 3, 6)
$lblDecTypes = New-Object System.Windows.Forms.Label; $lblDecTypes.Text = 'Types'; $lblDecTypes.Dock = 'Top'; $lblDecTypes.Height = 22; $lblDecTypes.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5, [System.Drawing.FontStyle]::Bold)
$lstDecTypes = New-Object System.Windows.Forms.ListBox; $lstDecTypes.Dock = 'Fill'; $lstDecTypes.Font = New-Object System.Drawing.Font('Consolas', 9); $lstDecTypes.IntegralHeight = $false; $lstDecTypes.HorizontalScrollbar = $true
$decTypesBox.Controls.Add($lstDecTypes); $decTypesBox.Controls.Add($lblDecTypes)
$decMain.Controls.Add($decTypesBox, 0, 0)

$decMethodsBox = New-Object System.Windows.Forms.Panel; $decMethodsBox.Dock = 'Fill'; $decMethodsBox.Margin = New-Object System.Windows.Forms.Padding(3, 4, 3, 6)
$lblDecMethods = New-Object System.Windows.Forms.Label; $lblDecMethods.Text = 'Methods'; $lblDecMethods.Dock = 'Top'; $lblDecMethods.Height = 22; $lblDecMethods.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5, [System.Drawing.FontStyle]::Bold)
$lstDecMethods = New-Object System.Windows.Forms.ListBox; $lstDecMethods.Dock = 'Fill'; $lstDecMethods.Font = New-Object System.Drawing.Font('Consolas', 9); $lstDecMethods.IntegralHeight = $false; $lstDecMethods.HorizontalScrollbar = $true
$decMethodsBox.Controls.Add($lstDecMethods); $decMethodsBox.Controls.Add($lblDecMethods)
$decMain.Controls.Add($decMethodsBox, 1, 0)

$decCodeBox = New-Object System.Windows.Forms.Panel; $decCodeBox.Dock = 'Fill'; $decCodeBox.Margin = New-Object System.Windows.Forms.Padding(3, 4, 6, 6)
$decCodeBar = New-Object System.Windows.Forms.Panel; $decCodeBar.Dock = 'Top'; $decCodeBar.Height = 30
$btnDecIl = New-Object System.Windows.Forms.Button; $btnDecIl.Text = 'IL'; $btnDecIl.Location = New-Object System.Drawing.Point(0, 2); $btnDecIl.Size = New-Object System.Drawing.Size(60, 24)
$btnDecCs = New-Object System.Windows.Forms.Button; $btnDecCs.Text = 'Decompile C#'; $btnDecCs.Location = New-Object System.Drawing.Point(66, 2); $btnDecCs.Size = New-Object System.Drawing.Size(120, 24)
$btnDecHex = New-Object System.Windows.Forms.Button; $btnDecHex.Text = 'Open in Hex'; $btnDecHex.Location = New-Object System.Drawing.Point(192, 2); $btnDecHex.Size = New-Object System.Drawing.Size(104, 24); $btnDecHex.Enabled = $false
$chkDecWrap = New-Object System.Windows.Forms.CheckBox; $chkDecWrap.Text = 'Wrap'; $chkDecWrap.Checked = $true; $chkDecWrap.Location = New-Object System.Drawing.Point(304, 5); $chkDecWrap.Size = New-Object System.Drawing.Size(60, 20)
$lblDecCodeHint = New-Object System.Windows.Forms.Label; $lblDecCodeHint.Text = 'IL via Mono.Cecil (always); C# needs ilspycmd on PATH. Native PE shows analysis, not IL.'; $lblDecCodeHint.Location = New-Object System.Drawing.Point(372, 2); $lblDecCodeHint.Size = New-Object System.Drawing.Size(700, 24); $lblDecCodeHint.TextAlign = 'MiddleLeft'
$decCodeBar.Controls.Add($btnDecIl); $decCodeBar.Controls.Add($btnDecCs); $decCodeBar.Controls.Add($btnDecHex); $decCodeBar.Controls.Add($chkDecWrap); $decCodeBar.Controls.Add($lblDecCodeHint)
# Staged by Load-DecAssembly when the selection turns out to be native, so the operator can
# go straight to the bytes instead of retyping the path into the Hex tab.
$btnDecHex.Add_Click({
    $t = $script:DecNativePath
    if (-not $t) { $t = $script:DecDllPath }
    if (-not $t -or -not (Test-Path -LiteralPath $t)) { $lblDecStatus.Text = 'No file selected to open in Hex.'; return }
    $txtHexPath.Text = $t
    $tabs.SelectedTab = $tabHex
    Load-GuiHex 0
})
$txtDecCode = New-Object System.Windows.Forms.RichTextBox; $txtDecCode.Dock = 'Fill'; $txtDecCode.ReadOnly = $true; $txtDecCode.Font = New-Object System.Drawing.Font('Consolas', 9.5); $txtDecCode.WordWrap = $true
$txtDecCode.Text = "Select a type on the left, then a method, to disassemble its IL here." + [Environment]::NewLine + "Click 'Decompile C#' to reconstruct C# for the selected method (requires ilspycmd)."
$decCodeBox.Controls.Add($txtDecCode); $decCodeBox.Controls.Add($decCodeBar)
$decMain.Controls.Add($decCodeBox, 2, 0)
# Wrap toggle: long IL operand lines (fully-qualified type names) overflow otherwise.
$chkDecWrap.Add_CheckedChanged({ $txtDecCode.WordWrap = $chkDecWrap.Checked; $txtDecCode.Refresh() })
# Hover tooltips so cut-off Type / Method names are still fully readable.
$decTip = New-Object System.Windows.Forms.ToolTip
$decTip.AutoPopDelay = 12000; $decTip.InitialDelay = 350; $decTip.ReshowDelay = 80
foreach ($lst in @($lstDecTypes, $lstDecMethods)) {
    $lst | Add-Member -NotePropertyName _TipIdx -NotePropertyValue -1 -Force
    $lst.Add_MouseMove({
        param($s, $e)
        $idx = $s.IndexFromPoint($e.Location)
        if ($idx -ne $s._TipIdx) {
            $s._TipIdx = $idx
            $txt = if ($idx -ge 0 -and $idx -lt $s.Items.Count) { "$($s.Items[$idx])" } else { '' }
            $decTip.SetToolTip($s, $txt)
        }
    })
}

# --- Decompiler logic ---
function Ensure-DecCecil {
    if ('Mono.Cecil.AssemblyDefinition' -as [type]) { return $true }
    $m = @(Get-Module TCPK)
    if ($m.Count) { try { [void](& $m[0] { Test-TcpkCecilAvailable }) } catch { } }
    return (('Mono.Cecil.AssemblyDefinition' -as [type]) -ne $null)
}

function Populate-DecTypes {
    $lstDecTypes.BeginUpdate(); $lstDecTypes.Items.Clear()
    $flt = "$($txtDecFilter.Text)".Trim()
    if ($script:DecTypes) {
        foreach ($ty in $script:DecTypes) {
            if ($flt -and ($ty.FullName -notmatch [regex]::Escape($flt))) { continue }
            [void]$lstDecTypes.Items.Add($ty)
        }
    }
    $lstDecTypes.EndUpdate()
    $lstDecMethods.Items.Clear()
}

# Fast managed-PE test: read the COM descriptor data directory (index 14). A NATIVE PE
# (d3dcompiler_47.dll, vcruntime, Qt, Go, Rust, Chromium) has RVA 0 there, and handing one
# to Mono.Cecil's ReadAssembly throws "Format of the executable (.exe) or library (.dll) is
# invalid". Native binaries must therefore never reach the decompiler list in the first
# place. Same directory the module's _PeReader uses; done inline so the GUI needs no
# private-module call, and it is far cheaper than attempting a Cecil load per file.
function Test-DecIsManagedPe([string]$Path) {
    $fs = $null; $br = $null
    try {
        $fs = [IO.File]::OpenRead($Path)
        if ($fs.Length -lt 0x80) { return $false }
        $br = [IO.BinaryReader]::new($fs)
        $fs.Position = 0x3C
        $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt ($fs.Length - 24)) { return $false }
        $fs.Position = $peOff
        if ($br.ReadUInt32() -ne 0x00004550) { return $false }          # 'PE\0\0'
        $fs.Position = $peOff + 24
        $magic = $br.ReadUInt16()                                        # 0x10B PE32 / 0x20B PE32+
        $ddStart = $peOff + 24 + 96
        if ($magic -eq 0x20B) { $ddStart = $peOff + 24 + 112 }
        $comOff = $ddStart + (14 * 8)                                    # data directory 14
        if (($comOff + 4) -gt $fs.Length) { return $false }
        $fs.Position = $comOff
        return ($br.ReadUInt32() -ne 0)
    } catch { return $false }
    finally {
        if ($br) { $br.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

# Native PE analysis panel. Selecting a native DLL used to be a dead end that told you to
# go to another tab; a target like a device configurator is mostly native, so that made the
# tab useless exactly where it was most needed. Everything shown here reuses public cmdlets
# (Get-TcpkPeHardening) and the shared PE reader, so it agrees with the Mitigations tab.
function Show-DecNativePe([string]$path) {
    $leaf = Split-Path $path -Leaf
    $lblDecStatus.Text = "$leaf is a NATIVE binary -- no IL to decompile. Showing PE analysis instead."
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// $leaf")
    [void]$sb.AppendLine("// NATIVE PE (no .NET metadata) -- compiled machine code, so there is no IL to")
    [void]$sb.AppendLine("// reconstruct. Recovering source shape needs a disassembler (Ghidra / IDA).")
    [void]$sb.AppendLine("// What CAN be determined about it is below.")
    [void]$sb.AppendLine('')

    $mod = @(Get-Module TCPK)
    $info = $null
    if ($mod.Count) { try { $info = & $mod[0] { param($p) Read-TcpkPe -Path $p } $path } catch { } }

    if (-not $info) {
        [void]$sb.AppendLine('  PE header could not be parsed (truncated or malformed file).')
        $txtDecCode.Text = $sb.ToString(); return
    }

    $arch = 'x86'
    if ($info.IsPE32Plus) { $arch = 'x64' }
    if ($info.Machine -eq 0x01c4 -or $info.Machine -eq 0xAA64) { $arch = 'ARM' }
    [void]$sb.AppendLine("FILE        $leaf")
    [void]$sb.AppendLine(("FORMAT      {0}  (machine 0x{1:X4}, {2})" -f $(if ($info.IsPE32Plus) { 'PE32+' } else { 'PE32' }), $info.Machine, $arch))
    [void]$sb.AppendLine(("SIZE        {0:N0} bytes, SizeOfCode {1:N0}" -f (Get-Item -LiteralPath $path).Length, $info.SizeOfCode))
    [void]$sb.AppendLine('')

    # Hardening via the public cmdlet, so this panel and the Mitigations tab cannot disagree.
    $h = $null
    try { $h = @(Get-TcpkPeHardening -Path $path)[0] } catch { }
    if ($h) {
        [void]$sb.AppendLine("HARDENING   $($h.Status)" + $(if ($h.Missing) { "   (missing: $($h.Missing))" } else { '' }))
        # These fields are STRINGS ('YES'/'NO'), not booleans. Print the value directly:
        # testing them with if() would be wrong, because the string 'NO' is truthy in
        # PowerShell and every mitigation would report as enabled.
        foreach ($n in @('ASLR', 'DEP', 'CFG', 'HighEntropyVA', 'ForceIntegrity', 'SafeSEH', 'GS')) {
            $v = '?'
            try { if ($null -ne $h.$n -and "$($h.$n)" -ne '') { $v = "$($h.$n)" } } catch { }
            [void]$sb.AppendLine(("   {0,-16} {1}" -f $n, $v))
        }
        [void]$sb.AppendLine(("   {0,-16} {1}" -f 'DllCharacteristics', $h.DllCharacteristics))
    } else {
        # Fall back to the raw reader if the hardening cmdlet skipped it (resource-only PE).
        [void]$sb.AppendLine('HARDENING   not available (resource-only PE, or SizeOfCode = 0)')
        [void]$sb.AppendLine(("   {0,-16} {1}" -f 'SafeSEH', $info.SafeSeh))
        [void]$sb.AppendLine(("   {0,-16} {1}" -f 'StackCookie (/GS)', $info.StackCookie))
    }
    [void]$sb.AppendLine('')

    $sigTxt = 'not checked'
    try {
        $sg = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $sigTxt = "$($sg.Status)"
        if ($sg.SignerCertificate) { $sigTxt = "$sigTxt  --  $($sg.SignerCertificate.Subject)" }
    } catch { }
    [void]$sb.AppendLine("SIGNING     $sigTxt")
    [void]$sb.AppendLine('')

    $imps = @($info.Imports)
    $dimps = @($info.DelayImports)
    [void]$sb.AppendLine("IMPORTS     $($imps.Count) module(s)" + $(if ($dimps.Count) { " + $($dimps.Count) delay-loaded" } else { '' }))
    foreach ($i in ($imps | Select-Object -First 25)) { [void]$sb.AppendLine("   $i") }
    if ($imps.Count -gt 25) { [void]$sb.AppendLine("   ... +$($imps.Count - 25) more") }
    foreach ($i in ($dimps | Select-Object -First 10)) { [void]$sb.AppendLine("   $i  [delay-load]") }
    [void]$sb.AppendLine('')

    $exps = @($info.Exports)
    [void]$sb.AppendLine("EXPORTS     $($exps.Count) named" + $(if ($exps.Count -ge 100) { ' (reader caps the list at 100)' } else { '' }))
    foreach ($e in ($exps | Select-Object -First 20)) { [void]$sb.AppendLine("   $e") }
    if ($exps.Count -gt 20) { [void]$sb.AppendLine("   ... +$($exps.Count - 20) more") }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine("SECTIONS    $((@($info.SectionNames)) -join ', ')")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('NEXT        "Open in Hex" (button above) for the raw bytes and strings.')
    [void]$sb.AppendLine('            The Mitigations and Signing tabs show this file alongside every')
    [void]$sb.AppendLine('            other binary in the target after an audit run.')

    $txtDecCode.Text = $sb.ToString()
    $txtDecCode.Select(0, 0); $txtDecCode.SelectionStart = 0; $txtDecCode.ScrollToCaret()
}

function Load-DecAssembly([string]$path) {
    if (-not (Ensure-DecCecil)) { $lblDecStatus.Text = 'Mono.Cecil not available (tools\ILSpy\Mono.Cecil.dll missing).'; return }
    $path = "$path".Trim('"').Trim()
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { $lblDecStatus.Text = "File not found: $path"; return }
    # A native binary has no IL, so instead of a dead end give the analysis that DOES
    # apply to it -- PE posture, hardening, imports, exports -- right here in the same
    # pane, and leave the file staged for the Hex tab one click away.
    if (-not (Test-DecIsManagedPe $path)) {
        $lstDecTypes.Items.Clear(); $lstDecMethods.Items.Clear()
        $script:DecNativePath = $path
        Show-DecNativePe $path
        $btnDecHex.Enabled = $true
        return
    }
    $script:DecNativePath = $null
    $btnDecHex.Enabled = $false
    if ($script:DecAsm) { try { $script:DecAsm.Dispose() } catch { } ; $script:DecAsm = $null }
    $script:DecCurMethod = $null    # drop any method held from the previous assembly
    $lstDecTypes.Items.Clear(); $lstDecMethods.Items.Clear(); $txtDecCode.Clear()
    $lblDecStatus.Text = 'Reading assembly...'; [System.Windows.Forms.Application]::DoEvents()
    $rp = New-Object Mono.Cecil.ReaderParameters; $rp.InMemory = $true
    $asm = $null
    try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($path, $rp) }
    catch { $lblDecStatus.Text = "Not a .NET assembly / unreadable: $($_.Exception.Message)"; return }
    $script:DecAsm = $asm; $script:DecDllPath = $path
    $types = New-Object System.Collections.Generic.List[object]
    try { foreach ($ty in $asm.MainModule.GetTypes()) { if ($ty.Name -ne '<Module>') { $types.Add($ty) } } } catch { }
    $script:DecTypes = $types
    Populate-DecTypes
    $lblDecStatus.Text = ("{0}  --  {1} types  ({2})" -f (Split-Path $path -Leaf), $types.Count, $asm.MainModule.Runtime)
}

# --- sink awareness -----------------------------------------------------------------
# The point of showing IL in a security tool is finding the dangerous call, not reading
# opcodes. These reuse the SHARED callsite sink map, so what the Decompiler tab highlights
# is exactly what the IL verifier proves -- the two can never drift apart.
function Get-DecSinkSpecs {
    if ($script:DecSinkSpecs) { return $script:DecSinkSpecs }
    $list = New-Object 'System.Collections.Generic.List[object]'
    $mod = @(Get-Module TCPK)
    if ($mod.Count) {
        try {
            $map = & $mod[0] { Get-TcpkCallsiteSinkMap }
            foreach ($kv in $map.GetEnumerator()) {
                foreach ($s in $kv.Value.Sinks) {
                    $list.Add([pscustomobject]@{ T = "$($s.T)"; M = "$($s.M)"; Mo = [bool]$s.Mo })
                }
            }
        } catch { }
    }
    # Deserialization types live in their own detector rather than the callsite map, so
    # add them explicitly. Same set the workbench uses.
    foreach ($t in @(
        'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter',
        'System.Runtime.Serialization.NetDataContractSerializer',
        'System.Web.UI.LosFormatter', 'System.Web.UI.ObjectStateFormatter',
        'System.Messaging.BinaryMessageFormatter', 'SoapFormatter',
        'System.Xml.Serialization.XmlSerializer', 'System.Runtime.Serialization.DataContractSerializer'
    )) { $list.Add([pscustomobject]@{ T = $t; M = ''; Mo = $false }) }
    $script:DecSinkSpecs = $list
    return $list
}

# Returns a short label ("Process.Start") when a called method matches a sink spec, else $null.
# Honours M (exact method on a type) / Mo (P/Invoke method name) / bare-T (any member of the
# type) so it does not over-flag: Environment::get_NewLine is not the GetEnvironmentVariable sink.
function Get-DecSinkHit($Mref) {
    if (-not $Mref) { return $null }
    $declFull = ''; $declLeaf = ''; $name = ''
    try {
        $declFull = "$($Mref.DeclaringType.FullName)"
        $declLeaf = "$($Mref.DeclaringType.Name)"
        $name     = "$($Mref.Name)"
    } catch { return $null }
    foreach ($s in (Get-DecSinkSpecs)) {
        if ($s.Mo) {
            if ($name -like "*$($s.T)*") { return $name }
        } elseif ($s.M) {
            if ($declFull -like "*$($s.T)*" -and $name -eq $s.M) { return "$declLeaf.$name" }
        } else {
            if ($declFull -like "*$($s.T)*") { return "$declLeaf.$name" }
        }
    }
    return $null
}

# Distinct sink labels called by a method. Used both to mark the method list and to
# summarise at the top of the IL view.
function Get-DecMethodSinks($Method) {
    $hits = New-Object 'System.Collections.Generic.List[string]'
    try {
        if (-not $Method.HasBody) { return $hits }
        foreach ($ins in $Method.Body.Instructions) {
            if ("$($ins.OpCode.Name)" -notlike 'call*' -and "$($ins.OpCode.Name)" -ne 'newobj') { continue }
            $h = Get-DecSinkHit $ins.Operand
            if ($h -and -not $hits.Contains($h)) { $hits.Add($h) }
        }
    } catch { }
    return $hits
}

function Show-DecIl {
    $sel = $lstDecMethods.SelectedItem
    if (-not $sel) { return }
    # The list holds display wrappers so sink-bearing methods can be marked; unwrap.
    $m = $sel
    if ($sel.PSObject.Properties['Method']) { $m = $sel.Method }
    if (-not $m) { return }
    $script:DecCurMethod = $m

    $sinkLines = New-Object 'System.Collections.Generic.List[int]'
    $sb = New-Object System.Text.StringBuilder
    # _decLine tracks the 0-based output line so sink call sites can be coloured after
    # the text is set; RichTextBox needs line indices, not stream offsets.
    $script:_decLine = 0
    [void]$sb.AppendLine("// $($m.DeclaringType.FullName)::$($m.Name)"); $script:_decLine++
    [void]$sb.AppendLine("// returns $($m.ReturnType.FullName)"); $script:_decLine++

    $sinks = Get-DecMethodSinks $m
    if ($sinks.Count) {
        [void]$sb.AppendLine("// SINKS REACHED: $($sinks -join ', ')"); $script:_decLine++
    }

    if (-not $m.HasBody) {
        [void]$sb.AppendLine('// (no managed body -- abstract / extern / P-Invoke / interface)'); $script:_decLine++
    } else {
        [void]$sb.AppendLine("// $($m.Body.Instructions.Count) IL instructions, $($m.Body.Variables.Count) locals"); $script:_decLine++
        [void]$sb.AppendLine(''); $script:_decLine++
        foreach ($ins in $m.Body.Instructions) {
            $op  = $ins.OpCode.Name
            $arg = ''
            if ($null -ne $ins.Operand) { $arg = " $($ins.Operand)" }
            $hit = $null
            if ($op -like 'call*' -or $op -eq 'newobj') { $hit = Get-DecSinkHit $ins.Operand }
            $mark = '  '
            if ($hit) { $mark = '>>'; $sinkLines.Add($script:_decLine) }
            [void]$sb.AppendLine(("{0}IL_{1:X4}: {2,-11}{3}" -f $mark, $ins.Offset, $op, $arg))
            $script:_decLine++
            if ($sb.Length -gt 200000) { [void]$sb.AppendLine('  ... (truncated)'); break }
        }
    }

    $txtDecCode.Text = $sb.ToString()

    # Colour the sink call sites. RichTextBox keeps SelectionColor until .Text is reset,
    # so this survives until the next method is shown.
    if ($sinks.Count) {
        try {
            $txtDecCode.Select(0, $txtDecCode.Lines[0].Length + $txtDecCode.Lines[1].Length + 2)
            $s2 = $txtDecCode.GetFirstCharIndexFromLine(2)
            if ($s2 -ge 0 -and $txtDecCode.Lines.Count -gt 2) {
                $txtDecCode.Select($s2, $txtDecCode.Lines[2].Length)
                $txtDecCode.SelectionColor = [System.Drawing.Color]::FromArgb(255, 160, 90)
            }
        } catch { }
    }
    foreach ($ln in $sinkLines) {
        try {
            if ($ln -ge $txtDecCode.Lines.Count) { continue }
            $st = $txtDecCode.GetFirstCharIndexFromLine($ln)
            if ($st -lt 0) { continue }
            $txtDecCode.Select($st, $txtDecCode.Lines[$ln].Length)
            $txtDecCode.SelectionColor = [System.Drawing.Color]::FromArgb(255, 110, 110)
        } catch { }
    }
    $txtDecCode.Select(0, 0); $txtDecCode.SelectionStart = 0; $txtDecCode.ScrollToCaret()
}

# --- wire events ---
$btnDecBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = '.NET assemblies (*.dll;*.exe)|*.dll;*.exe|All files (*.*)|*.*'
    $seed = "$($txtTarget.Text)"
    if ($seed -and (Test-Path -LiteralPath $seed)) { $ofd.InitialDirectory = if (Test-Path -LiteralPath $seed -PathType Leaf) { Split-Path -LiteralPath $seed -Parent } else { $seed } }
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $cmbDecDll.Text = $ofd.FileName; Load-DecAssembly $ofd.FileName }
})
$btnDecScan.Add_Click({
    $base = "$($txtTarget.Text)"
    if (-not $base) { $lblDecStatus.Text = 'Set a target at the top first.'; return }
    if (Test-Path -LiteralPath $base -PathType Leaf) { $base = Split-Path -LiteralPath $base -Parent }
    if (-not (Test-Path -LiteralPath $base)) { $lblDecStatus.Text = "Target path not found: $base"; return }
    $lblDecStatus.Text = 'Scanning for assemblies...'; [System.Windows.Forms.Application]::DoEvents()
    $found = @(Get-ChildItem -LiteralPath $base -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.dll' -or $_.Extension -eq '.exe' } | Sort-Object FullName | Select-Object -First 800)
    $cmbDecDll.Items.Clear()
    # Only MANAGED assemblies belong in the decompiler list. A target directory is usually
    # mostly native (Chromium, DirectX, VC runtime, Qt), and listing those meant selecting
    # one produced a raw Cecil "Format of the executable is invalid" error with no
    # explanation. Native binaries are counted and reported, not offered.
    $managed = 0; $native = 0
    foreach ($f in $found) {
        if (Test-DecIsManagedPe $f.FullName) { [void]$cmbDecDll.Items.Add($f.FullName); $managed++ }
        else { $native++ }
    }
    if ($managed -gt 0) { $cmbDecDll.SelectedIndex = 0 }

    $capNote = ''
    if ($found.Count -ge 800) { $capNote = ' (scan capped at 800 files)' }
    if ($managed -eq 0) {
        $lblDecStatus.Text = ("No .NET assemblies under {0} -- all {1} binaries are native. This looks like a native or Electron app; use Mitigations / Signing for PE posture, or the Asar tab if it ships app.asar.{2}" -f $base, $native, $capNote)
    } else {
        $lblDecStatus.Text = ("{0} .NET assembly(ies) under {1}  ({2} native binaries skipped -- not decompilable){3}" -f $managed, $base, $native, $capNote)
    }
})
$btnDecLoad.Add_Click({ Load-DecAssembly $cmbDecDll.Text })
$cmbDecDll.Add_SelectedIndexChanged({ if ($cmbDecDll.SelectedItem) { Load-DecAssembly "$($cmbDecDll.SelectedItem)" } })
$txtDecFilter.Add_TextChanged({ Populate-DecTypes })
$lstDecTypes.Add_SelectedIndexChanged({
    $ty = $lstDecTypes.SelectedItem
    if (-not $ty) { return }
    $lstDecMethods.BeginUpdate(); $lstDecMethods.Items.Clear()
    # Mark methods that reach a known sink and sort them to the top. A real assembly type
    # can hold hundreds of methods, and hunting for the one dangerous call by hand is the
    # slow part of the job. Wrapped in a display object with a ToString override so the
    # ListBox shows the marker while Show-DecIl still gets the MethodDefinition.
    $sinkCount = 0
    try {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($mm in $ty.Methods) {
            $hits = Get-DecMethodSinks $mm
            $label = "$mm"
            $rank = 1
            if ($hits.Count) {
                $label = ">> $mm    [$($hits -join ', ')]"
                $rank = 0
                $sinkCount++
            }
            $row = [pscustomobject]@{ Method = $mm; Label = $label; Rank = $rank }
            $row | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Label } -Force
            $rows.Add($row)
        }
        foreach ($r in ($rows | Sort-Object Rank)) { [void]$lstDecMethods.Items.Add($r) }
    } catch {
        # Fall back to the plain list rather than showing nothing if sink scanning fails.
        try { foreach ($mm in $ty.Methods) { [void]$lstDecMethods.Items.Add($mm) } } catch { }
    }
    $lstDecMethods.EndUpdate()
    if ($sinkCount -gt 0) {
        $lblDecMethods.Text = ("Methods ({0})   >> {1} reach a sink" -f $lstDecMethods.Items.Count, $sinkCount)
    } else {
        $lblDecMethods.Text = ("Methods ({0})" -f $lstDecMethods.Items.Count)
    }
})
$lstDecMethods.Add_SelectedIndexChanged({ Show-DecIl })
$btnDecIl.Add_Click({ Show-DecIl })
$btnDecCs.Add_Click({
    # Use the CURRENT method selection (belongs to the loaded assembly); fall back to the
    # last-shown method only if it matches the current selection state.
    $m = $lstDecMethods.SelectedItem; if (-not $m) { $m = $script:DecCurMethod }
    # The method list holds display wrappers so sink-bearing methods can be marked; unwrap
    # before touching .Name, or this reads the wrapper instead of the MethodDefinition.
    if ($m -and $m.PSObject.Properties['Method']) { $m = $m.Method }
    if (-not $m -or -not $script:DecDllPath) { $lblDecStatus.Text = 'Select a method first.'; return }
    $lblDecStatus.Text = "Decompiling $($m.Name) (this can take a while on large assemblies)..."
    $txtDecCode.Text = 'Running ilspycmd (or byte-context fallback)...'; [System.Windows.Forms.Application]::DoEvents()
    try {
        $res = Invoke-TcpkDecompile -Dll $script:DecDllPath -Search $m.Name -Context 10 3>$null
        if (-not $res -or -not "$res".Trim()) { $res = "(no C# match for '$($m.Name)'. If ilspycmd is not installed, only IL is available.)" }
        $txtDecCode.Text = "$res"; $txtDecCode.SelectionStart = 0; $txtDecCode.ScrollToCaret()
        $lblDecStatus.Text = "Decompiled $($m.Name)."
    } catch { $txtDecCode.Text = "Decompile failed: $($_.Exception.Message)"; $lblDecStatus.Text = 'Decompile failed.' }
})

# ================= TAB: Process Monitor (live watch + activity capture) =================
# One tab, two clickable modes sharing a target picker + console:
#   Live watch       -- re-render a target's live state (path, memory, handles, threads,
#                       modules, TCP connections, child processes) every N seconds.
#   Activity capture -- baseline the target, then poll for N seconds and LOG new module loads,
#                       new TCP connections, and new child processes with timestamps. Poll-based
#                       and driver-free (not a kernel Procmon), but shows what the app does live.
$tabPmon = New-Object System.Windows.Forms.TabPage
$tabPmon.Text = ' ProcMon '
$tabPmon.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabPmon)

$script:PmonMode = 'live'
$script:PmonRunning = $false
$script:PmonPid = 0
$script:PmonSeenMod = $null; $script:PmonSeenConn = $null; $script:PmonSeenChild = $null
$script:PmonSeenPipe = $null; $script:PmonSeenListen = $null
$script:PmonCaptureEnd = $null
$script:PmonDllJob = $null
$script:PmonTimer = New-Object System.Windows.Forms.Timer
$script:PmonTimer.Interval = 2000

$pmGreen  = [System.Drawing.Color]::FromArgb(166, 226, 46)
$pmCyan   = [System.Drawing.Color]::FromArgb(102, 217, 239)
$pmYellow = [System.Drawing.Color]::FromArgb(214, 137, 16)
$pmGrey   = [System.Drawing.Color]::FromArgb(150, 150, 150)
$pmRed    = [System.Drawing.Color]::FromArgb(224, 108, 117)

$pmonTop = New-Object System.Windows.Forms.Panel
$pmonTop.Dock = 'Top'; $pmonTop.Height = 112; $pmonTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
# Row 1: mode buttons + process picker
$btnPmLive = New-Object System.Windows.Forms.Button
$btnPmLive.Text = "Live watch"; $btnPmLive.Location = New-Object System.Drawing.Point(12, 10); $btnPmLive.Size = New-Object System.Drawing.Size(110, 28); $btnPmLive.FlatStyle = 'Flat'
$btnPmLive.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnPmLive.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$pmonTop.Controls.Add($btnPmLive)
$btnPmCap = New-Object System.Windows.Forms.Button
$btnPmCap.Text = "Activity capture"; $btnPmCap.Location = New-Object System.Drawing.Point(126, 10); $btnPmCap.Size = New-Object System.Drawing.Size(142, 28); $btnPmCap.FlatStyle = 'Flat'
$btnPmCap.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnPmCap.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$pmonTop.Controls.Add($btnPmCap)
$lblPmProc = New-Object System.Windows.Forms.Label
$lblPmProc.Text = "Process:"; $lblPmProc.ForeColor = [System.Drawing.Color]::White; $lblPmProc.Location = New-Object System.Drawing.Point(284, 16); $lblPmProc.Size = New-Object System.Drawing.Size(68, 18)
$pmonTop.Controls.Add($lblPmProc)
$cmbPmProc = New-Object System.Windows.Forms.ComboBox
$cmbPmProc.Location = New-Object System.Drawing.Point(356, 12); $cmbPmProc.Size = New-Object System.Drawing.Size(244, 24); $cmbPmProc.DropDownStyle = 'DropDown'
$cmbPmProc.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbPmProc.ForeColor = [System.Drawing.Color]::White
$pmonTop.Controls.Add($cmbPmProc)
$btnPmRefresh = New-Object System.Windows.Forms.Button
$btnPmRefresh.Text = "Refresh"; $btnPmRefresh.Location = New-Object System.Drawing.Point(606, 11); $btnPmRefresh.Size = New-Object System.Drawing.Size(74, 26)
$btnPmRefresh.FlatStyle = 'Flat'; $btnPmRefresh.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnPmRefresh.ForeColor = [System.Drawing.Color]::White
$pmonTop.Controls.Add($btnPmRefresh)
$lblPmFilter = New-Object System.Windows.Forms.Label
$lblPmFilter.Text = "Module filter:"; $lblPmFilter.ForeColor = [System.Drawing.Color]::White; $lblPmFilter.Location = New-Object System.Drawing.Point(694, 16); $lblPmFilter.Size = New-Object System.Drawing.Size(116, 18)
$pmonTop.Controls.Add($lblPmFilter)
$txtPmonFilter = New-Object System.Windows.Forms.TextBox
$txtPmonFilter.Location = New-Object System.Drawing.Point(814, 12); $txtPmonFilter.Size = New-Object System.Drawing.Size(164, 24); $txtPmonFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtPmonFilter.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtPmonFilter.ForeColor = [System.Drawing.Color]::White
$pmonTop.Controls.Add($txtPmonFilter)
# Row 2: interval / duration + start + stop + status
$lblPmNum = New-Object System.Windows.Forms.Label
$lblPmNum.Text = "Refresh interval (s):"; $lblPmNum.ForeColor = [System.Drawing.Color]::White; $lblPmNum.Location = New-Object System.Drawing.Point(12, 51); $lblPmNum.Size = New-Object System.Drawing.Size(210, 18)
$pmonTop.Controls.Add($lblPmNum)
$numPmNum = New-Object System.Windows.Forms.NumericUpDown
$numPmNum.Location = New-Object System.Drawing.Point(226, 48); $numPmNum.Size = New-Object System.Drawing.Size(60, 24); $numPmNum.Minimum = 0; $numPmNum.Maximum = 3600; $numPmNum.Value = 2
$numPmNum.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $numPmNum.ForeColor = [System.Drawing.Color]::White
$pmonTop.Controls.Add($numPmNum)
$btnPmStart = New-Object System.Windows.Forms.Button
$btnPmStart.Text = "Start"; $btnPmStart.Location = New-Object System.Drawing.Point(296, 47); $btnPmStart.Size = New-Object System.Drawing.Size(80, 28)
$btnPmStart.BackColor = [System.Drawing.Color]::FromArgb(39, 121, 78); $btnPmStart.ForeColor = [System.Drawing.Color]::White; $btnPmStart.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmStart)
$btnPmStop = New-Object System.Windows.Forms.Button
$btnPmStop.Text = "Stop"; $btnPmStop.Location = New-Object System.Drawing.Point(382, 47); $btnPmStop.Size = New-Object System.Drawing.Size(80, 28); $btnPmStop.Enabled = $false; $btnPmStop.FlatStyle = 'Flat'
$btnPmStop.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnPmStop.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$pmonTop.Controls.Add($btnPmStop)
$btnPmSave = New-Object System.Windows.Forms.Button
$btnPmSave.Text = "Save output..."; $btnPmSave.Location = New-Object System.Drawing.Point(470, 47); $btnPmSave.Size = New-Object System.Drawing.Size(126, 28); $btnPmSave.FlatStyle = 'Flat'
$btnPmSave.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnPmSave.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$pmonTop.Controls.Add($btnPmSave)
$lblPmStatus = New-Object System.Windows.Forms.Label
$lblPmStatus.Location = New-Object System.Drawing.Point(600, 52); $lblPmStatus.Size = New-Object System.Drawing.Size(580, 18); $lblPmStatus.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$lblPmStatus.Text = "Pick a mode, choose a process (Refresh), set the interval / duration, then Start."
$pmonTop.Controls.Add($lblPmStatus)
# Row 3: capture extras -- DLL trace option (ETW, admin) and what the enhanced capture now tracks.
# The checkbox is only meaningful in capture mode; Set-PmonMode shows/hides it accordingly.
$chkPmDllTrace = New-Object System.Windows.Forms.CheckBox
$chkPmDllTrace.Text = 'DLL search trace during capture (requires admin -- shows every phantom-DLL probe in real time)'
$chkPmDllTrace.Location = New-Object System.Drawing.Point(12, 88)
$chkPmDllTrace.Size = New-Object System.Drawing.Size(748, 18)
$chkPmDllTrace.ForeColor = [System.Drawing.Color]::FromArgb(214, 137, 16)
$chkPmDllTrace.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$chkPmDllTrace.FlatStyle = 'Flat'
$chkPmDllTrace.Visible = $false
$pmonTop.Controls.Add($chkPmDllTrace)
$lblPmCapExtras = New-Object System.Windows.Forms.Label
$lblPmCapExtras.Text = 'Capture now also tracks: named pipes / new listening ports / unsigned module loads'
$lblPmCapExtras.Location = New-Object System.Drawing.Point(12, 88)
$lblPmCapExtras.Size = New-Object System.Drawing.Size(700, 18)
$lblPmCapExtras.ForeColor = [System.Drawing.Color]::FromArgb(100, 120, 100)
$lblPmCapExtras.Visible = $false
$pmonTop.Controls.Add($lblPmCapExtras)
$tabPmon.Controls.Add($pmonTop)

$txtPmon = New-Object System.Windows.Forms.RichTextBox
$txtPmon.Dock = 'Fill'; $txtPmon.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtPmon.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18); $txtPmon.ForeColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
$txtPmon.ReadOnly = $true; $txtPmon.WordWrap = $false
$txtPmon.Text = "Process Monitor.`r`n`r`n  Live watch      -- continuously re-renders one process's state (path, memory, handles, threads, modules, TCP connections, child processes).`r`n  Activity capture -- baselines the process, then logs NEW module loads / TCP connections / child processes over N seconds (exercise the app during the window).`r`n`r`nRead-only. Pick a mode above, choose a process, then Start. Some fields need admin for protected processes."
$tabPmon.Controls.Add($txtPmon); $txtPmon.BringToFront()

function Set-PmonMode([string]$m) {
    if ($script:PmonRunning) { return }
    $script:PmonMode = $m
    if ($m -eq 'live') {
        $btnPmLive.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnPmLive.ForeColor = [System.Drawing.Color]::White
        $btnPmCap.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230); $btnPmCap.ForeColor = [System.Drawing.Color]::Black
        $lblPmNum.Text = "Refresh interval (s):"; $numPmNum.Value = 2
        $chkPmDllTrace.Visible = $false; $lblPmCapExtras.Visible = $false
    } else {
        $btnPmCap.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnPmCap.ForeColor = [System.Drawing.Color]::White
        $btnPmLive.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230); $btnPmLive.ForeColor = [System.Drawing.Color]::Black
        $lblPmNum.Text = "Capture duration (s, 0=until Stop):"; $numPmNum.Value = 20
        $chkPmDllTrace.Visible = $true; $lblPmCapExtras.Visible = $true
    }
}
function Resolve-PmonTarget {
    $t = $cmbPmProc.Text.Trim(); if (-not $t) { return $null }
    if ($t -match '\(pid\s+(\d+)\)') { try { return Get-Process -Id ([int]$Matches[1]) -ErrorAction Stop } catch { return $null } }
    $nm = $t -replace '\.exe$', ''
    try { return (Get-Process -Name $nm -ErrorAction Stop | Select-Object -First 1) } catch { return $null }
}
function Stop-Pmon {
    try { $script:PmonTimer.Stop() } catch {}
    if ($script:PmonDllJob) {
        try { Stop-Job -Job $script:PmonDllJob -ErrorAction SilentlyContinue } catch {}
        try { Remove-Job -Job $script:PmonDllJob -Force -ErrorAction SilentlyContinue } catch {}
        $script:PmonDllJob = $null
    }
    $script:PmonRunning = $false
    $btnPmStart.Enabled = $true; $btnPmStop.Enabled = $false; $btnPmLive.Enabled = $true; $btnPmCap.Enabled = $true
}
# RTF-escape a value for the coloured Process Monitor output.
function Get-PmonRtfText([string]$s) {
    if (-not $s) { return '' }
    $o = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq '\') { [void]$o.Append('\\') }
        elseif ($ch -eq '{') { [void]$o.Append('\{') }
        elseif ($ch -eq '}') { [void]$o.Append('\}') }
        elseif ($code -ge 32 -and $code -le 126) { [void]$o.Append($ch) }
        elseif ($code -gt 126) { }
        else { [void]$o.Append(' ') }
    }
    return $o.ToString()
}
# Append a "  label   value" row to the RTF (label grey, value colour = $vc).
function Add-PmonRow($sb, [string]$lbl, [string]$val, [int]$vc = 3) {
    [void]$sb.Append('\cf2   ' + $lbl.PadRight(13) + '\cf' + $vc + ' ' + (Get-PmonRtfText $val) + '\par ')
}
function Render-PmonLive {
    try { $p = Get-Process -Id $script:PmonPid -ErrorAction Stop } catch { Write-IcptLine $txtPmon "`r`nProcess exited.`r`n" $pmGrey; Stop-Pmon; $lblPmStatus.Text = "Process exited."; return }
    $path = '(access denied)'; try { $path = $p.MainModule.FileName } catch {}
    $desc = ''; $comp = ''; $prod = ''; $fver = ''
    try { $fvi = $p.MainModule.FileVersionInfo; $desc = "$($fvi.FileDescription)"; $comp = "$($fvi.CompanyName)"; $prod = "$($fvi.ProductName)"; $fver = "$($fvi.FileVersion)" } catch {}
    $ci = $null; try { $ci = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:PmonPid)" -OperationTimeoutSec 5 -ErrorAction SilentlyContinue } catch {}
    $ppid = ''; $cmd = ''; if ($ci) { $ppid = "$($ci.ParentProcessId)"; $cmd = "$($ci.CommandLine)" }
    $owner = ''; try { if ($ci) { $ow = $ci | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue; if ($ow -and $ow.User) { $owner = "$($ow.Domain)\$($ow.User)" } } } catch {}
    $started = '(n/a)'; try { $started = $p.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}
    $prio = '(n/a)'; try { $prio = "$($p.PriorityClass)" } catch {}
    $sess = '?'; try { $sess = "$($p.SessionId)" } catch {}
    $wsMB = [Math]::Round($p.WorkingSet64 / 1MB, 1); $prvMB = [Math]::Round($p.PrivateMemorySize64 / 1MB, 1)
    $peakMB = [Math]::Round($p.PeakWorkingSet64 / 1MB, 1); $vmMB = [Math]::Round($p.VirtualMemorySize64 / 1MB, 1)
    $cpu = 0; try { $cpu = [Math]::Round($p.CPU, 1) } catch {}
    $mods = @(); try { $mods = @($p.Modules) } catch {}
    $conns  = @(); try { $conns  = @(Get-NetTCPConnection -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue) } catch {}
    $udp    = @(); try { $udp    = @(Get-NetUDPEndpoint   -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue) } catch {}
    $kids   = @(); try { $kids   = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($script:PmonPid)" -OperationTimeoutSec 5 -ErrorAction SilentlyContinue) } catch {}
    $pipeRx = ''; try { $pipeRx = [regex]::Escape($p.ProcessName) } catch {}
    $pipes  = @(); try { $allPipes = @([System.IO.Directory]::GetFiles('\\.\pipe\', '*')); $pipes = @($allPipes | Where-Object { -not $pipeRx -or $_ -match "(?i)$pipeRx" } | Select-Object -First 50) } catch {}
    $estab  = @($conns | Where-Object { "$($_.State)" -ne 'Listen' })
    $listen = @($conns | Where-Object { "$($_.State)" -eq 'Listen' })

    # colortbl: 1 cyan(headers) 2 label 3 value 4 green(path/module/established) 5 dim(paths/sep) 6 yellow(user/child) 7 orange(remote) 8 red
    $r = New-Object System.Text.StringBuilder
    [void]$r.Append('{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}')
    [void]$r.Append('{\colortbl;\red102\green217\blue239;\red130\green150\blue170;\red225\green225\blue225;\red152\green195\blue121;\red120\green120\blue120;\red214\green180\blue90;\red209\green154\blue102;\red224\green108\blue117;}')
    [void]$r.Append('\f0\fs19 ')
    [void]$r.Append('\cf5 monitoring -- ' + (Get-Date).ToString('HH:mm:ss') + '\par ')
    [void]$r.Append('\par\cf1\b PROCESS\b0\par ')
    Add-PmonRow $r 'Name / PID' ("$($p.ProcessName)  ($($p.Id))" + $(if ($ppid) { "    parent $ppid" } else { '' }))
    Add-PmonRow $r 'Path' $path 4
    if ($desc) { Add-PmonRow $r 'Description' $desc }
    if ($comp) { Add-PmonRow $r 'Company' $comp }
    if ($prod -or $fver) { Add-PmonRow $r 'Product' ($prod + $(if ($fver) { "  (v$fver)" } else { '' })) }
    if ($owner) { Add-PmonRow $r 'User' $owner 6 }
    Add-PmonRow $r 'Started' $started
    Add-PmonRow $r 'Priority' ("$prio    session $sess")
    if ($cmd) { Add-PmonRow $r 'Command' $cmd 5 }
    [void]$r.Append('\par\cf1\b MEMORY\b0\par ')
    Add-PmonRow $r 'Working set' ("$wsMB MB")
    Add-PmonRow $r 'Private' ("$prvMB MB")
    Add-PmonRow $r 'Peak WS' ("$peakMB MB")
    Add-PmonRow $r 'Virtual' ("$vmMB MB")
    Add-PmonRow $r 'Handles' ("$($p.HandleCount)    threads $($p.Threads.Count)    cpu ${cpu}s")
    # Optional module filter (name or path substring, case-insensitive).
    $modsAll = $mods
    # Modules loaded from user-writable locations are DLL hijack or injection suspects.
    $wpathRx = '(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\[^\\]+\\Downloads\\)'
    $wPathMods = @($modsAll | Where-Object { $mf2 = ''; try { $mf2 = "$($_.FileName)" } catch {}; $mf2 -match $wpathRx })
    $mflt = ''; try { $mflt = $txtPmonFilter.Text.Trim() } catch {}
    if ($mflt) {
        $fl = $mflt.ToLower()
        $mods = @($mods | Where-Object { $s = ''; try { $s = "$($_.ModuleName) $($_.FileName)".ToLower() } catch { try { $s = "$($_.ModuleName)".ToLower() } catch {} }; $s.Contains($fl) })
    }
    $modHdr = if ($mflt) { "$($mods.Count) of $($modsAll.Count), filter: $mflt" } else { "$($mods.Count)" }
    if ($wPathMods.Count) { $modHdr += "  !! $($wPathMods.Count) WRITABLE PATH" }
    # Show ALL modules (a real .NET app has a few hundred). A high safety cap only guards
    # against a pathological runaway -- normal processes never hit it.
    $modCap = 5000
    [void]$r.Append('\par\cf1\b MODULES (' + (Get-PmonRtfText $modHdr) + ')\b0\par ')
    foreach ($m in ($mods | Select-Object -First $modCap)) {
        $mn = ''; $mf = ''; try { $mn = "$($m.ModuleName)" } catch {}; try { $mf = "$($m.FileName)" } catch {}
        $isWp = $mf -match $wpathRx
        if ($isWp) {
            # Loaded from a user-writable path -- red, prefixed with !! to stand out.
            [void]$r.Append('\cf8 !! ' + (Get-PmonRtfText $mn).PadRight(36) + '  \cf8 ' + (Get-PmonRtfText $mf) + '\par ')
        } else {
            # Normal: name in green, path dimmed.  Always keep a 2-space gap so a long name
            # does not run directly into the path.  The trailing "  " is inside cf4 (invisible).
            [void]$r.Append('\cf4     ' + (Get-PmonRtfText $mn).PadRight(38) + '  \cf5 ' + (Get-PmonRtfText $mf) + '\par ')
        }
    }
    if ($mods.Count -gt $modCap) { [void]$r.Append('\cf5     ... ' + ($mods.Count - $modCap) + ' more\par ') }
    [void]$r.Append('\par\cf1\b NETWORK -- TCP ESTABLISHED (' + $estab.Count + ')\b0\par ')
    foreach ($c in ($estab | Select-Object -First 500)) {
        $stc = if ("$($c.State)" -eq 'Established') { 4 } else { 2 }
        [void]$r.Append('\cf3     ' + (Get-PmonRtfText "$($c.LocalAddress):$($c.LocalPort)") + '\cf5  -> \cf7 ' + (Get-PmonRtfText "$($c.RemoteAddress):$($c.RemotePort)") + '\cf' + $stc + '    ' + (Get-PmonRtfText "$($c.State)") + '\par ')
    }
    if (-not $estab.Count) { [void]$r.Append('\cf5     (none)\par ') }
    [void]$r.Append('\par\cf1\b LISTENING TCP (' + $listen.Count + ')\b0\par ')
    foreach ($c in ($listen | Select-Object -First 100)) {
        [void]$r.Append('\cf6     ' + (Get-PmonRtfText "$($c.LocalAddress):$($c.LocalPort)") + '\par ')
    }
    if (-not $listen.Count) { [void]$r.Append('\cf5     (none)\par ') }
    [void]$r.Append('\par\cf1\b UDP ENDPOINTS (' + $udp.Count + ')\b0\par ')
    foreach ($u in ($udp | Select-Object -First 100)) {
        [void]$r.Append('\cf6     ' + (Get-PmonRtfText "$($u.LocalAddress):$($u.LocalPort)") + '\par ')
    }
    if (-not $udp.Count) { [void]$r.Append('\cf5     (none)\par ') }
    [void]$r.Append('\par\cf1\b NAMED PIPES -- process match (' + $pipes.Count + ')\b0\par ')
    foreach ($pp in $pipes) { [void]$r.Append('\cf6     ' + (Get-PmonRtfText "$pp") + '\par ') }
    if (-not $pipes.Count) { [void]$r.Append('\cf5     (none matching process name)\par ') }
    [void]$r.Append('\par\cf1\b CHILD PROCESSES (' + $kids.Count + ')\b0\par ')
    foreach ($k in ($kids | Select-Object -First 500)) { [void]$r.Append('\cf6     ' + (Get-PmonRtfText "$($k.Name)") + '\cf5  (pid ' + $k.ProcessId + ')\par ') }
    if (-not $kids.Count) { [void]$r.Append('\cf5     (none)\par ') }
    [void]$r.Append('}')
    # Preserve the scroll position across refreshes so a long module list stays readable.
    $top = -1; try { $top = $txtPmon.GetCharIndexFromPosition((New-Object System.Drawing.Point(2, 2))) } catch {}
    $txtPmon.Rtf = $r.ToString()
    if ($top -ge 0 -and $top -lt $txtPmon.TextLength) { try { $txtPmon.SelectionStart = $top; $txtPmon.SelectionLength = 0; $txtPmon.ScrollToCaret() } catch {} }
}
function Poll-PmonCapture {
    if ($script:PmonCaptureEnd -and (Get-Date) -ge $script:PmonCaptureEnd) { Write-IcptLine $txtPmon "`r`n-- capture complete --`r`n" $pmCyan; Stop-Pmon; $lblPmStatus.Text = "Capture complete."; return }
    try { $p = Get-Process -Id $script:PmonPid -ErrorAction Stop } catch { Write-IcptLine $txtPmon "`r`nProcess exited.`r`n" $pmGrey; Stop-Pmon; return }
    $ts = (Get-Date).ToString('HH:mm:ss')

    # --- Module loads (enhanced: check signature and load-path writability for new loads) ---
    $newMods = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($m in $p.Modules) {
            $k = "$($m.FileName)"
            if ($k -and -not $script:PmonSeenMod.Contains($k)) {
                [void]$script:PmonSeenMod.Add($k)
                [void]$newMods.Add($k)
            }
        }
    } catch {}
    $sigChecked = 0
    foreach ($modPath in $newMods) {
        Write-IcptLine $txtPmon ("[{0}] MODULE  {1}`r`n" -f $ts, $modPath) $pmGreen
        # Skip OS paths for signature/writability -- they are always signed and never writable.
        if ($modPath -match '(?i)\\(System32|SysWOW64|WinSxS|Windows\\)') { continue }
        # Limit per-tick signature calls: these touch disk; too many at once stalls the UI tick.
        if ($sigChecked -ge 8) { continue }
        $sigChecked++
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $modPath -ErrorAction Stop
            if ($sig.Status -ne 'Valid') {
                Write-IcptLine $txtPmon ("  !! UNSIGNED  {0}  (Authenticode status: {1})`r`n" -f $modPath, $sig.Status) $pmRed
            }
        } catch {}
        # Flag load from a user-writable directory (runtime DLL hijack confirmation).
        $dir = Split-Path -Parent $modPath
        if ($dir -and $dir -notmatch '(?i)\\Program Files') {
            $isUserWritable = $false
            try {
                $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
                $isUserWritable = $null -ne ($acl.Access | Where-Object {
                    $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b' -and
                    $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $_.AccessControlType -eq 'Allow'
                })
            } catch {}
            if ($isUserWritable) {
                Write-IcptLine $txtPmon ("  !! WRITABLE PATH  loaded from user-writable dir: {0}`r`n" -f $dir) $pmRed
            }
        }
    }

    # --- TCP connections ---
    try { foreach ($c in (Get-NetTCPConnection -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue)) { $k = "$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)"; if (-not $script:PmonSeenConn.Contains($k)) { [void]$script:PmonSeenConn.Add($k); Write-IcptLine $txtPmon ("[{0}] TCP     {1}:{2} -> {3}:{4} [{5}]`r`n" -f $ts, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State) $pmCyan } } } catch {}

    # --- New listening ports (new IPC / server surface the app opens during exercise) ---
    try {
        foreach ($l in (Get-NetTCPConnection -State Listen -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue)) {
            $k = "L:$($l.LocalAddress):$($l.LocalPort)"
            if (-not $script:PmonSeenListen.Contains($k)) {
                [void]$script:PmonSeenListen.Add($k)
                Write-IcptLine $txtPmon ("[{0}] LISTEN  TCP $($l.LocalAddress):$($l.LocalPort) (new listening port opened)`r`n" -f $ts) $pmYellow
            }
        }
        foreach ($u in (Get-NetUDPEndpoint -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue)) {
            $k = "U:$($u.LocalAddress):$($u.LocalPort)"
            if (-not $script:PmonSeenListen.Contains($k)) {
                [void]$script:PmonSeenListen.Add($k)
                Write-IcptLine $txtPmon ("[{0}] LISTEN  UDP $($u.LocalAddress):$($u.LocalPort) (new UDP endpoint)`r`n" -f $ts) $pmYellow
            }
        }
    } catch {}

    # --- Named pipes (new pipes created during exercise -- IPC surface and squatting candidates) ---
    try {
        foreach ($pp in (Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue)) {
            $k = $pp.Name
            if ($k -and -not $script:PmonSeenPipe.Contains($k)) {
                [void]$script:PmonSeenPipe.Add($k)
                Write-IcptLine $txtPmon ("[{0}] PIPE    \\.\pipe\$k`r`n" -f $ts) $pmYellow
            }
        }
    } catch {}

    # --- Child processes ---
    try { foreach ($ch in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($script:PmonPid)" -OperationTimeoutSec 5 -ErrorAction SilentlyContinue)) { $k = "$($ch.ProcessId)"; if (-not $script:PmonSeenChild.Contains($k)) { [void]$script:PmonSeenChild.Add($k); Write-IcptLine $txtPmon ("[{0}] CHILD   {1} (pid {2})`r`n" -f $ts, $ch.Name, $ch.ProcessId) $pmYellow } } } catch {}

    # --- DLL trace job (ETW phantom-DLL stream, if the operator started it) ---
    if ($script:PmonDllJob) {
        try {
            $lines = Receive-Job -Job $script:PmonDllJob -Keep:$false -ErrorAction SilentlyContinue
            foreach ($l in $lines) {
                if ($l -match '^PHANTOM\t(.+)$') {
                    Write-IcptLine $txtPmon ("[{0}] PHANTOM {1}`r`n" -f $ts, $matches[1]) $pmRed
                }
            }
            if ($script:PmonDllJob.State -ne 'Running') {
                Write-IcptLine $txtPmon "`r`n-- DLL trace complete --`r`n" $pmCyan
                try { Remove-Job -Job $script:PmonDllJob -Force -ErrorAction SilentlyContinue } catch {}
                $script:PmonDllJob = $null
            }
        } catch { $script:PmonDllJob = $null }
    }
}
$btnPmRefresh.Add_Click({
    $sel = $cmbPmProc.Text
    $cmbPmProc.Items.Clear()
    try { Get-Process -ErrorAction SilentlyContinue | Sort-Object ProcessName | ForEach-Object { [void]$cmbPmProc.Items.Add(("{0}  (pid {1})" -f $_.ProcessName, $_.Id)) } } catch {}
    if ($sel) { $cmbPmProc.Text = $sel }
})
$btnPmLive.Add_Click({ Set-PmonMode 'live' })
$btnPmCap.Add_Click({ Set-PmonMode 'capture' })
$script:PmonTimer.Add_Tick({ if ($script:PmonMode -eq 'live') { Render-PmonLive } else { Poll-PmonCapture } })
$btnPmStart.Add_Click({
    if ($script:PmonRunning) { return }
    $p = Resolve-PmonTarget
    if (-not $p) { $lblPmStatus.Text = "Process not found -- Refresh and pick one, or type a name / PID."; return }
    $script:PmonPid = $p.Id
    $n = [int]$numPmNum.Value
    $txtPmon.Clear()
    $script:PmonRunning = $true
    $btnPmStart.Enabled = $false; $btnPmStop.Enabled = $true; $btnPmLive.Enabled = $false; $btnPmCap.Enabled = $false
    if ($script:PmonMode -eq 'live') {
        $script:PmonTimer.Interval = [Math]::Max(1, $n) * 1000
        $lblPmStatus.Text = "Live watch: $($p.ProcessName) (pid $($p.Id)) every ${n}s -- Stop to end."
        Render-PmonLive
    } else {
        $script:PmonSeenMod    = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenConn   = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenChild  = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenPipe   = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenListen = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonDllJob = $null
        # Baseline: record what already exists so only CHANGES appear in the log.
        try { foreach ($m in $p.Modules) { [void]$script:PmonSeenMod.Add("$($m.FileName)") } } catch {}
        try { foreach ($c in (Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenConn.Add("$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)") } } catch {}
        try { foreach ($l in (Get-NetTCPConnection -State Listen -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenListen.Add("L:$($l.LocalAddress):$($l.LocalPort)") } } catch {}
        try { foreach ($u in (Get-NetUDPEndpoint -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenListen.Add("U:$($u.LocalAddress):$($u.LocalPort)") } } catch {}
        try { foreach ($pp in (Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenPipe.Add($pp.Name) } } catch {}
        try { foreach ($ch in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -OperationTimeoutSec 5 -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenChild.Add("$($ch.ProcessId)") } } catch {}
        $script:PmonTimer.Interval = 1000
        if ($n -le 0) {
            $script:PmonCaptureEnd = $null
            $lblPmStatus.Text = "Activity capture: $($p.ProcessName) (pid $($p.Id)) -- running until you Stop (or it exits)."
            Write-IcptLine $txtPmon ("== Activity capture: {0} (pid {1}) -- until Stop (or exit) ==`r`n" -f $p.ProcessName, $p.Id) $pmCyan
        } else {
            $script:PmonCaptureEnd = (Get-Date).AddSeconds($n)
            $lblPmStatus.Text = "Activity capture: $($p.ProcessName) (pid $($p.Id)) for ${n}s -- exercise the app now."
            Write-IcptLine $txtPmon ("== Activity capture: {0} (pid {1}) for {2}s ==`r`n" -f $p.ProcessName, $p.Id, $n) $pmCyan
        }
        $extras = 'modules / TCP connections / listening ports / named pipes / child processes'
        Write-IcptLine $txtPmon ("(baseline taken; logging NEW {0})`r`n" -f $extras) $pmGrey
        # If DLL trace is requested, start an ETW job in the background.
        # The job streams PHANTOM<TAB><path> lines for each phantom-DLL probe found.
        # Poll-PmonCapture picks these up on every timer tick and logs them in red.
        if ($chkPmDllTrace.Checked) {
            $procName2 = $p.ProcessName; $secs2 = if ($n -gt 0) { $n } else { 300 }
            $psd1Ref = $tcpkPsd1
            $script:PmonDllJob = Start-Job -ScriptBlock {
                param($modulePath, $procName, $secs)
                Import-Module $modulePath -Force -ErrorAction Stop
                & (Get-Module TCPK) {
                    param($pn, $s)
                    # Test-TcpkDllSearchTrace writes findings as TcpkFinding objects to the output stream.
                    foreach ($f in @(Test-TcpkDllSearchTrace -ProcessName $pn -Seconds $s)) {
                        if ($f -and $f.File) { "PHANTOM`t$($f.File)" }
                        elseif ($f -and $f.Title) { "PHANTOM`t$($f.Title)" }
                    }
                } -ArgumentList $procName, $secs
            } -ArgumentList $psd1Ref, $procName2, $secs2
            Write-IcptLine $txtPmon "(DLL search trace started -- phantom-DLL probes will appear in red)`r`n" $pmYellow
        }
        Write-IcptLine $txtPmon "" $pmGrey
    }
    $script:PmonTimer.Start()
})
$btnPmStop.Add_Click({ Stop-Pmon; Write-IcptLine $txtPmon "`r`n(stopped)`r`n" $pmGrey; $lblPmStatus.Text = "Stopped." })
# Live watch: apply the module filter immediately (only re-renders while running in live mode).
$txtPmonFilter.Add_TextChanged({ if ($script:PmonRunning -and $script:PmonMode -eq 'live') { Render-PmonLive } })
# Save the current console (live snapshot or activity log) to a timestamped text file.
$btnPmSave.Add_Click({
    if (-not $txtPmon.Text.Trim()) { $lblPmStatus.Text = "Nothing to save yet."; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Text file (*.txt)|*.txt|All files (*.*)|*.*"
    $dlg.FileName = "tcpk-procmon-$((Get-Date).ToString('yyyyMMdd-HHmmss')).txt"
    if ($dlg.ShowDialog() -eq 'OK') {
        try { [System.IO.File]::WriteAllText($dlg.FileName, $txtPmon.Text); $lblPmStatus.Text = "Saved: $($dlg.FileName)" }
        catch { $lblPmStatus.Text = "Save failed: $($_.Exception.Message)" }
    }
})
$form.Add_FormClosing({
    try { $script:PmonTimer.Stop() } catch {}
    if ($script:PmonDllJob) { try { Stop-Job -Job $script:PmonDllJob -ErrorAction SilentlyContinue; Remove-Job -Job $script:PmonDllJob -Force -ErrorAction SilentlyContinue } catch {} }
})
Set-PmonMode 'live'

# ================= TAB: Attack-Path Graph =================
# Correlates audit findings into end-to-end attack paths (entry -> primitive -> goal) via
# Get-TcpkAttackGraph. Shows reachable goals + the Mermaid flowchart source to paste into
# any renderer. Read-only, offline, reasons over the completed audit's findings.json only.
$tabGraph = New-Object System.Windows.Forms.TabPage
$tabGraph.Text = ' Graph '
$tabGraph.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabGraph)

$graphTop = New-Object System.Windows.Forms.Panel
$graphTop.Dock = 'Top'; $graphTop.Height = 70; $graphTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblGraphInfo = New-Object System.Windows.Forms.Label
$lblGraphInfo.Text = "Attack-path graph -- correlate audit findings into entry -> primitive -> goal paths. Run an audit first, then click Build Graph."
$lblGraphInfo.ForeColor = [System.Drawing.Color]::White; $lblGraphInfo.Location = New-Object System.Drawing.Point(12, 8); $lblGraphInfo.Size = New-Object System.Drawing.Size(1140, 18)
$graphTop.Controls.Add($lblGraphInfo)
$btnGraphBuild = New-Object System.Windows.Forms.Button
$btnGraphBuild.Text = "Build Graph"; $btnGraphBuild.Location = New-Object System.Drawing.Point(12, 34); $btnGraphBuild.Size = New-Object System.Drawing.Size(120, 28)
$btnGraphBuild.BackColor = [System.Drawing.Color]::FromArgb(0, 90, 120); $btnGraphBuild.ForeColor = [System.Drawing.Color]::White; $btnGraphBuild.FlatStyle = 'Flat'
$graphTop.Controls.Add($btnGraphBuild)
$btnGraphCopy = New-Object System.Windows.Forms.Button
$btnGraphCopy.Text = "Copy Mermaid"; $btnGraphCopy.Location = New-Object System.Drawing.Point(140, 34); $btnGraphCopy.Size = New-Object System.Drawing.Size(120, 28)
$btnGraphCopy.FlatStyle = 'Flat'; $btnGraphCopy.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnGraphCopy.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$btnGraphCopy.Enabled = $false
$graphTop.Controls.Add($btnGraphCopy)
$lblGraphStatus = New-Object System.Windows.Forms.Label
$lblGraphStatus.Text = ""; $lblGraphStatus.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
$lblGraphStatus.Location = New-Object System.Drawing.Point(270, 40); $lblGraphStatus.Size = New-Object System.Drawing.Size(700, 18)
$graphTop.Controls.Add($lblGraphStatus)
$tabGraph.Controls.Add($graphTop)

$splitGraph = New-Object System.Windows.Forms.SplitContainer
$splitGraph.Dock = 'Fill'; $splitGraph.Orientation = 'Horizontal'; $splitGraph.SplitterDistance = 200
$splitGraph.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$splitGraph.Panel1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$splitGraph.Panel2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$lblGoalsHdr = New-Object System.Windows.Forms.Label
$lblGoalsHdr.Text = "REACHABLE GOALS"; $lblGoalsHdr.ForeColor = [System.Drawing.Color]::White; $lblGoalsHdr.Dock = 'Top'; $lblGoalsHdr.Height = 22
$lblGoalsHdr.Padding = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
$splitGraph.Panel1.Controls.Add($lblGoalsHdr)
$lvGoals = New-Object System.Windows.Forms.ListView
$lvGoals.Dock = 'Fill'; $lvGoals.View = 'Details'; $lvGoals.FullRowSelect = $true; $lvGoals.GridLines = $true
$lvGoals.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lvGoals.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvGoals.ForeColor = [System.Drawing.Color]::White
[void]$lvGoals.Columns.Add('Severity', 80)
[void]$lvGoals.Columns.Add('Goal', 360)
[void]$lvGoals.Columns.Add('Via', 500)
$splitGraph.Panel1.Controls.Add($lvGoals)
$lvGoals.BringToFront()

$lblMermaidHdr = New-Object System.Windows.Forms.Label
$lblMermaidHdr.Text = "MERMAID SOURCE (paste into mermaid.live or any Mermaid renderer)"; $lblMermaidHdr.ForeColor = [System.Drawing.Color]::White; $lblMermaidHdr.Dock = 'Top'; $lblMermaidHdr.Height = 22
$lblMermaidHdr.Padding = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
$splitGraph.Panel2.Controls.Add($lblMermaidHdr)
$txtMermaid = New-Object System.Windows.Forms.RichTextBox
$txtMermaid.Dock = 'Fill'; $txtMermaid.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtMermaid.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $txtMermaid.ForeColor = [System.Drawing.Color]::White
$txtMermaid.ReadOnly = $true; $txtMermaid.WordWrap = $false
$txtMermaid.Text = "Run an audit (Audit tab), then click Build Graph to correlate findings into attack paths.`r`n`r`nThe graph output is a Mermaid flowchart -- copy it and paste into mermaid.live (or any Mermaid renderer) to visualize the attack paths."
$splitGraph.Panel2.Controls.Add($txtMermaid)
$txtMermaid.BringToFront()
$tabGraph.Controls.Add($splitGraph)
$splitGraph.BringToFront()



# --- PE Info logic ---
function Load-PeInfo([string]$filePath) {
    if (-not $filePath -or -not [IO.File]::Exists($filePath)) {
        $lblPdStatus.Text = "File not found: $filePath"; return
    }
    $lblPdStatus.Text = "Analyzing $([IO.Path]::GetFileName($filePath)) ..."
    [System.Windows.Forms.Application]::DoEvents()
    $pi = $null
    try {
        $mod = @(Get-Module TCPK)[0]
        if (-not $mod) { $lblPdStatus.Text = 'TCPK module not loaded.'; return }
        $pi = & $mod { param($p) Get-TcpkPeInfo -Path $p } $filePath
    } catch { $lblPdStatus.Text = "Error: $($_.Exception.Message)"; return }
    if (-not $pi) { $lblPdStatus.Text = 'Not a valid PE or no data returned.'; return }

    # Summary
    $txtPiSum.Clear()
    function _PiLine($lbl, $val) {
        $txtPiSum.SelectionColor = $piGray; $txtPiSum.AppendText(("{0,-22}" -f $lbl))
        $txtPiSum.SelectionColor = $piWhite; $txtPiSum.AppendText("$val`r`n")
    }
    $txtPiSum.SelectionColor = $piCyan; $txtPiSum.AppendText("$($pi.Name)`r`n")
    $txtPiSum.SelectionColor = $piGray; $txtPiSum.AppendText(("-" * 64 + "`r`n"))
    _PiLine 'Path:'             $pi.FullPath
    _PiLine 'File size:'        ("{0:N0} bytes" -f $pi.FileSize)
    _PiLine 'Arch:'             $pi.Arch
    _PiLine 'Subsystem:'        $pi.Subsystem
    _PiLine 'Compiler:'         $pi.Compiler
    _PiLine 'Compiled at:'      $pi.CompiledAt
    _PiLine 'Linker version:'   $pi.LinkerVersion
    _PiLine 'Image base:'       $pi.ImageBase
    _PiLine 'Image size:'       ("{0:N0} bytes" -f $pi.SizeOfImage)
    _PiLine 'OEP:'              "$($pi.OEP)  (in $($pi.OEPSection))"
    _PiLine 'Sections:'         $pi.NumberOfSections
    _PiLine 'Exports:'          $pi.ExportCount
    _PiLine 'Managed (.NET):'   $pi.IsManaged
    _PiLine 'DLL chars:'        $pi.DllCharacteristics
    _PiLine 'Characteristics:'  $pi.Characteristics
    _PiLine 'Exec level:'       $(if ($pi.ExecutionLevel) { $pi.ExecutionLevel } else { '(no manifest)' })
    if ($pi.OverlaySize -gt 0) {
        $txtPiSum.SelectionColor = $piOrgFg; $txtPiSum.AppendText(("{0,-22}" -f 'Overlay:'))
        $txtPiSum.SelectionColor = $piWhite; $txtPiSum.AppendText("$($pi.OverlayOffset)  ($($pi.OverlaySize) bytes)`r`n")
    }
    if ($pi.HighEntropySecs.Count -gt 0) {
        $txtPiSum.SelectionColor = $piRedFg; $txtPiSum.AppendText(("{0,-22}" -f 'High entropy secs:'))
        $txtPiSum.SelectionColor = $piWhite; $txtPiSum.AppendText(($pi.HighEntropySecs -join ', ') + "`r`n")
    }
    $txtPiSum.SelectionStart = 0; $txtPiSum.ScrollToCaret()

    # Sections
    $lvPiSec.BeginUpdate(); $lvPiSec.Items.Clear()
    foreach ($sec in $pi.Sections) {
        $li = New-Object System.Windows.Forms.ListViewItem($sec.Name)
        [void]$li.SubItems.Add($sec.VirtualAddress); [void]$li.SubItems.Add("$($sec.VirtualSize)")
        [void]$li.SubItems.Add($sec.RawOffset);       [void]$li.SubItems.Add("$($sec.RawSize)")
        [void]$li.SubItems.Add("$($sec.Entropy)");    [void]$li.SubItems.Add($sec.EntropyFlag)
        [void]$li.SubItems.Add($sec.Characteristics)
        if ($sec.Entropy -gt 7.0)     { $li.BackColor = $piRedBg; $li.ForeColor = $piRedFg }
        elseif ($sec.Entropy -gt 6.0) { $li.BackColor = $piOrgBg; $li.ForeColor = $piOrgFg }
        [void]$lvPiSec.Items.Add($li)
    }
    $lvPiSec.EndUpdate()

    # Exports
    $lvPiExp.BeginUpdate(); $lvPiExp.Items.Clear()
    foreach ($exp in $pi.Exports) {
        $li = New-Object System.Windows.Forms.ListViewItem($exp.Name)
        [void]$li.SubItems.Add("$($exp.Ordinal)"); [void]$li.SubItems.Add($exp.RVA)
        [void]$li.SubItems.Add($(if ($exp.IsForwarded) { 'YES' } else { '' }))
        [void]$li.SubItems.Add($exp.ForwardTarget)
        if ($exp.IsForwarded) { $li.BackColor = $piYelBg; $li.ForeColor = $piYelFg }
        [void]$lvPiExp.Items.Add($li)
    }
    $lvPiExp.EndUpdate()

    # Rich Header
    $lvPiRich.BeginUpdate(); $lvPiRich.Items.Clear()
    $rh = $pi.RichHeader
    $lblPiRichHint.Text = if ($rh.Present) {
        "Rich Header present.  XOR key: $($rh.XorKey)  |  Compiler hint: $(if ($rh.VsHint) { $rh.VsHint } else { '(unknown build)' })"
    } else { 'Rich Header: NOT PRESENT (binary stripped its header, or built with a non-MSVC toolchain).' }
    if ($rh.Present) {
        foreach ($e in $rh.Entries) {
            $li = New-Object System.Windows.Forms.ListViewItem($e.ToolId)
            [void]$li.SubItems.Add($e.ToolName); [void]$li.SubItems.Add("$($e.BuildNumber)"); [void]$li.SubItems.Add("$($e.UseCount)")
            [void]$lvPiRich.Items.Add($li)
        }
    }
    $lvPiRich.EndUpdate()

    # Version Info
    $txtPiVer.Clear()
    function _VerLine($lbl, $val) {
        $txtPiVer.SelectionColor = $piGray; $txtPiVer.AppendText(("{0,-22}" -f $lbl))
        $txtPiVer.SelectionColor = $piWhite; $txtPiVer.AppendText($(if ($val) { $val } else { '(not set)' }) + "`r`n")
    }
    $txtPiVer.SelectionColor = $piCyan; $txtPiVer.AppendText("VS_VERSIONINFO`r`n")
    $txtPiVer.SelectionColor = $piGray; $txtPiVer.AppendText(("-" * 52 + "`r`n"))
    _VerLine 'FileVersion:'      $pi.FileVersion
    _VerLine 'ProductVersion:'   $pi.ProductVersion
    _VerLine 'CompanyName:'      $pi.CompanyName
    _VerLine 'ProductName:'      $pi.ProductName
    _VerLine 'FileDescription:'  $pi.FileDescription
    _VerLine 'OriginalFilename:' $pi.OriginalFilename
    _VerLine 'InternalName:'     $pi.InternalName
    _VerLine 'LegalCopyright:'   $pi.LegalCopyright
    $txtPiVer.AppendText("`r`n")
    $txtPiVer.SelectionColor = $piCyan; $txtPiVer.AppendText("Manifest`r`n")
    $txtPiVer.SelectionColor = $piGray; $txtPiVer.AppendText(("-" * 52 + "`r`n"))
    _VerLine 'ExecutionLevel:'   $(if ($pi.ExecutionLevel) { $pi.ExecutionLevel } else { '(not found)' })
    $txtPiVer.SelectionStart = 0; $txtPiVer.ScrollToCaret()

    $lblPdStatus.Text = "Loaded: $($pi.Name)  |  $($pi.Arch)  |  $($pi.Compiler)  |  $($pi.NumberOfSections) sections  |  $($pi.ExportCount) exports  |  overlay: $($pi.OverlaySize) bytes"
}


# ================= TAB: Dependencies (Dependency Walker equivalent) =================
$tabDep = New-Object System.Windows.Forms.TabPage
$tabDep.Text = ' Dependencies '
$tabDep.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabDep)

$depBar = New-Object System.Windows.Forms.Panel
$depBar.Dock = 'Top'; $depBar.Height = 74; $depBar.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$tabDep.Controls.Add($depBar)

$depRow1 = New-Object System.Windows.Forms.TableLayoutPanel
$depRow1.Dock = 'Top'; $depRow1.Height = 38; $depRow1.ColumnCount = 6; $depRow1.RowCount = 1
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 90)))
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 110)))
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 106)))
[void]$depRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
$lblDepFile = New-Object System.Windows.Forms.Label
$lblDepFile.Text = 'File:'; $lblDepFile.Dock = 'Fill'; $lblDepFile.TextAlign = 'MiddleLeft'
$lblDepFile.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0); $lblDepFile.ForeColor = [System.Drawing.Color]::White
$depRow1.Controls.Add($lblDepFile, 0, 0)
$cmbDepFile = New-Object System.Windows.Forms.ComboBox
$cmbDepFile.DropDownStyle = 'DropDown'; $cmbDepFile.Anchor = $anchLR; $cmbDepFile.Margin = New-Object System.Windows.Forms.Padding(2, 8, 6, 0)
$cmbDepFile.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $cmbDepFile.ForeColor = [System.Drawing.Color]::White
$depRow1.Controls.Add($cmbDepFile, 1, 0)
$btnDepBrowse = New-Object System.Windows.Forms.Button
$btnDepBrowse.Text = 'Browse...'; $btnDepBrowse.Dock = 'Fill'; $btnDepBrowse.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$depRow1.Controls.Add($btnDepBrowse, 2, 0)
$btnDepScan = New-Object System.Windows.Forms.Button
$btnDepScan.Text = 'Scan target'; $btnDepScan.Dock = 'Fill'; $btnDepScan.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$depRow1.Controls.Add($btnDepScan, 3, 0)
$numDepDepth = New-Object System.Windows.Forms.NumericUpDown
$numDepDepth.Minimum = 1; $numDepDepth.Maximum = 6; $numDepDepth.Value = 3; $numDepDepth.Dock = 'Fill'; $numDepDepth.Margin = New-Object System.Windows.Forms.Padding(2, 7, 2, 7)
$numDepDepth.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $numDepDepth.ForeColor = [System.Drawing.Color]::White
$depRow1.Controls.Add($numDepDepth, 4, 0)
$btnDepBuild = New-Object System.Windows.Forms.Button
$btnDepBuild.Text = 'Build Tree'; $btnDepBuild.Dock = 'Fill'; $btnDepBuild.Margin = New-Object System.Windows.Forms.Padding(2, 6, 6, 6)
$btnDepBuild.BackColor = [System.Drawing.Color]::FromArgb(0, 90, 120); $btnDepBuild.ForeColor = [System.Drawing.Color]::White; $btnDepBuild.FlatStyle = 'Flat'
$depRow1.Controls.Add($btnDepBuild, 5, 0)

$depRow2 = New-Object System.Windows.Forms.Panel
$depRow2.Dock = 'Top'; $depRow2.Height = 32
$lblDepStatus = New-Object System.Windows.Forms.Label
$lblDepStatus.Dock = 'Fill'; $lblDepStatus.TextAlign = 'MiddleLeft'; $lblDepStatus.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$lblDepStatus.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
$lblDepStatus.Text = 'Browse or type an EXE/DLL, set recursion depth, then click Build Tree.  RED = HIGH risk (MISSING or writable AppDir).  YELLOW = MEDIUM (PATH-resolved).'
$depRow2.Controls.Add($lblDepStatus)
$depBar.Controls.Add($depRow2)
$depBar.Controls.Add($depRow1)

# Filter + summary bar at bottom
$depBottom = New-Object System.Windows.Forms.Panel
$depBottom.Dock = 'Bottom'; $depBottom.Height = 30; $depBottom.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
$tabDep.Controls.Add($depBottom)
$btnDepShowAll = New-Object System.Windows.Forms.Button
$btnDepShowAll.Text = 'Show All'; $btnDepShowAll.Location = New-Object System.Drawing.Point(8, 3); $btnDepShowAll.Size = New-Object System.Drawing.Size(84, 24)
$btnDepShowAll.FlatStyle = 'Flat'; $btnDepShowAll.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnDepShowAll.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$depBottom.Controls.Add($btnDepShowAll)
$btnDepRiskOnly = New-Object System.Windows.Forms.Button
$btnDepRiskOnly.Text = 'Hijack Risk Only'; $btnDepRiskOnly.Location = New-Object System.Drawing.Point(98, 3); $btnDepRiskOnly.Size = New-Object System.Drawing.Size(142, 24)
$btnDepRiskOnly.FlatStyle = 'Flat'; $btnDepRiskOnly.BackColor = [System.Drawing.Color]::FromArgb(80, 20, 20); $btnDepRiskOnly.ForeColor = [System.Drawing.Color]::FromArgb(255, 140, 140)
$depBottom.Controls.Add($btnDepRiskOnly)
$lblDepSummary = New-Object System.Windows.Forms.Label
$lblDepSummary.Location = New-Object System.Drawing.Point(244, 6); $lblDepSummary.Size = New-Object System.Drawing.Size(894, 20)
$lblDepSummary.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
$depBottom.Controls.Add($lblDepSummary)

# Main grid
$lvDep = New-Object System.Windows.Forms.ListView
$lvDep.Dock = 'Fill'; $lvDep.View = 'Details'; $lvDep.FullRowSelect = $true; $lvDep.GridLines = $true
$lvDep.HeaderStyle = 'Nonclickable'; $lvDep.Font = New-Object System.Drawing.Font('Consolas', 9)
$lvDep.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvDep.ForeColor = [System.Drawing.Color]::White
[void]$lvDep.Columns.Add('DLL', 195); [void]$lvDep.Columns.Add('Parent', 155)
[void]$lvDep.Columns.Add('Depth', 50); [void]$lvDep.Columns.Add('Status', 130)
[void]$lvDep.Columns.Add('HijackRisk', 88); [void]$lvDep.Columns.Add('Delay', 48)
[void]$lvDep.Columns.Add('Resolved Path', 400)
$tabDep.Controls.Add($lvDep); $lvDep.BringToFront()

$script:DepItems      = @()
$script:DepRiskFilter = $false
$depHighBg = [System.Drawing.Color]::FromArgb(80, 20, 20); $depHighFg = [System.Drawing.Color]::FromArgb(255, 140, 140)
$depMedBg  = [System.Drawing.Color]::FromArgb(70, 60, 10); $depMedFg  = [System.Drawing.Color]::FromArgb(255, 220, 80)

function Refresh-DepGrid {
    $lvDep.BeginUpdate(); $lvDep.Items.Clear()
    foreach ($it in $script:DepItems) {
        if ($script:DepRiskFilter -and $it.Tag -ne 'HIGH' -and $it.Tag -ne 'MEDIUM') { continue }
        [void]$lvDep.Items.Add($it)
    }
    $lvDep.EndUpdate()
}

function Build-DepTree {
    $path  = "$($cmbDepFile.Text)".Trim()
    $depth = [int]$numDepDepth.Value
    if (-not $path -or -not [IO.File]::Exists($path)) { $lblDepStatus.Text = "File not found: $path"; return }
    $lblDepStatus.Text = "Building dependency tree for $([IO.Path]::GetFileName($path)) (depth=$depth) ..."
    [System.Windows.Forms.Application]::DoEvents()
    $nodes = @()
    try {
        $mod = @(Get-Module TCPK)[0]
        if (-not $mod) { $lblDepStatus.Text = 'TCPK module not loaded.'; return }
        $nodes = @(& $mod { param($p,$d) Get-TcpkDependencyTree -Path $p -MaxDepth $d } $path $depth)
    } catch { $lblDepStatus.Text = "Error: $($_.Exception.Message)"; return }

    $indent = '  '
    $script:DepItems = foreach ($n in $nodes) {
        $pfx = $indent * ([Math]::Max(0, $n.Depth - 1))
        $li  = New-Object System.Windows.Forms.ListViewItem("$pfx$($n.DllName)")
        [void]$li.SubItems.Add($n.ParentDll); [void]$li.SubItems.Add("$($n.Depth)")
        [void]$li.SubItems.Add($n.Status);    [void]$li.SubItems.Add($n.HijackRisk)
        [void]$li.SubItems.Add($(if ($n.IsDelayLoad) { 'YES' } else { '' }))
        [void]$li.SubItems.Add($n.ResolvedPath)
        $li.Tag = $n.HijackRisk
        if ($n.HijackRisk -eq 'HIGH')   { $li.BackColor = $depHighBg; $li.ForeColor = $depHighFg }
        elseif ($n.HijackRisk -eq 'MEDIUM') { $li.BackColor = $depMedBg; $li.ForeColor = $depMedFg }
        $li
    }
    $cH = @($nodes | Where-Object { $_.HijackRisk -eq 'HIGH' }).Count
    $cM = @($nodes | Where-Object { $_.HijackRisk -eq 'MEDIUM' }).Count
    $cX = @($nodes | Where-Object { $_.Status -eq 'MISSING' }).Count
    $lblDepSummary.Text = "Total: $($nodes.Count) DLLs  |  MISSING: $cX  |  HIGH risk: $cH  |  MEDIUM risk: $cM"
    $lblDepStatus.Text  = "Done: $([IO.Path]::GetFileName($path))  --  $($nodes.Count) DLLs at depth $depth"
    $script:DepRiskFilter = $false; Refresh-DepGrid
}

$btnDepBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'PE Files (*.exe;*.dll;*.sys;*.ocx)|*.exe;*.dll;*.sys;*.ocx|All files (*.*)|*.*'
    $ofd.Title = 'Select a PE to trace dependencies'
    if ($ofd.ShowDialog() -eq 'OK') {
        if ($cmbDepFile.Items -notcontains $ofd.FileName) { [void]$cmbDepFile.Items.Add($ofd.FileName) }
        $cmbDepFile.Text = $ofd.FileName
    }
    $ofd.Dispose()
})
$btnDepScan.Add_Click({
    $base = "$($txtTarget.Text)".Trim()
    if (-not $base) { $lblDepStatus.Text = 'Set an audit target first (top toolbar).'; return }
    $exes = @(Get-ChildItem -Path $base -Recurse -Include '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 50)
    $cmbDepFile.BeginUpdate(); $cmbDepFile.Items.Clear()
    foreach ($f in $exes) { [void]$cmbDepFile.Items.Add($f.FullName) }
    $cmbDepFile.EndUpdate()
    if ($cmbDepFile.Items.Count -gt 0) { $cmbDepFile.SelectedIndex = 0; $lblDepStatus.Text = "$($cmbDepFile.Items.Count) EXEs found. Select one and click Build Tree." }
    else { $lblDepStatus.Text = 'No EXE files found in the target directory.' }
})
$btnDepBuild.Add_Click({ Build-DepTree })
$btnDepShowAll.Add_Click({ $script:DepRiskFilter = $false; Refresh-DepGrid })
$btnDepRiskOnly.Add_Click({ $script:DepRiskFilter = $true; Refresh-DepGrid })
$cmbDepFile.Add_KeyDown({ param($s,$e); if ($e.KeyCode -eq 'Return') { Build-DepTree } })

# ---- Tab 21: Live Edit (real-time intercept + buffer modification) ----
$tabLiveEdit = New-Object System.Windows.Forms.TabPage
$tabLiveEdit.Text = ' Live Edit '
$tabLiveEdit.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
[void]$tabs.TabPages.Add($tabLiveEdit)

# Toolbar
$leBar  = New-Object System.Windows.Forms.Panel; $leBar.Dock = 'Top'; $leBar.Height = 74
$leBar.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)

$leRow1 = New-Object System.Windows.Forms.TableLayoutPanel
$leRow1.Dock = 'Top'; $leRow1.Height = 37; $leRow1.ColumnCount = 4; $leRow1.RowCount = 1
[void]$leRow1.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('AutoSize'))
[void]$leRow1.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('AutoSize'))
[void]$leRow1.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('AutoSize'))
[void]$leRow1.ColumnStyles.Add([System.Windows.Forms.ColumnStyle]::new('Percent', 100))

$lblLeTitle = New-Object System.Windows.Forms.Label
$lblLeTitle.Text = 'Intercept Mode  (pipe: \\.\pipe\tcpk_intercept)'; $lblLeTitle.ForeColor = [System.Drawing.Color]::Silver
$lblLeTitle.AutoSize = $true; $lblLeTitle.Margin = [System.Windows.Forms.Padding]::new(8, 10, 8, 0)

$btnLeStart = New-Object System.Windows.Forms.Button
$btnLeStart.Text = 'Start Server'; $btnLeStart.Width = 100; $btnLeStart.Height = 26
$btnLeStart.BackColor = [System.Drawing.Color]::FromArgb(0, 110, 55); $btnLeStart.ForeColor = [System.Drawing.Color]::White
$btnLeStart.FlatStyle = 'Flat'; $btnLeStart.Margin = [System.Windows.Forms.Padding]::new(0, 5, 6, 5)

$btnLeStop = New-Object System.Windows.Forms.Button
$btnLeStop.Text = 'Stop Server'; $btnLeStop.Width = 100; $btnLeStop.Height = 26; $btnLeStop.Enabled = $false
$btnLeStop.BackColor = [System.Drawing.Color]::FromArgb(90, 25, 25); $btnLeStop.ForeColor = [System.Drawing.Color]::White
$btnLeStop.FlatStyle = 'Flat'; $btnLeStop.Margin = [System.Windows.Forms.Padding]::new(0, 5, 6, 5)

$leRow1.Controls.Add($lblLeTitle, 0, 0); $leRow1.Controls.Add($btnLeStart, 1, 0); $leRow1.Controls.Add($btnLeStop, 2, 0)

$leRow2 = New-Object System.Windows.Forms.Panel; $leRow2.Dock = 'Top'; $leRow2.Height = 28
$leRow2.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
$lblLeStatus = New-Object System.Windows.Forms.Label
$lblLeStatus.Text = 'Pipe server not running. Click Start Server, then attach frida with tcpk_hook.js to the target process.'
$lblLeStatus.ForeColor = [System.Drawing.Color]::Gray; $lblLeStatus.Dock = 'Fill'
$lblLeStatus.TextAlign = 'MiddleLeft'; $lblLeStatus.Padding = [System.Windows.Forms.Padding]::new(8, 0, 0, 0)
$leRow2.Controls.Add($lblLeStatus)

$leBar.Controls.Add($leRow2); $leBar.Controls.Add($leRow1)
$tabLiveEdit.Controls.Add($leBar)

# Split: editor (top) + action bar (bottom)
$leSplit = New-Object System.Windows.Forms.SplitContainer
$leSplit.Dock = 'Fill'; $leSplit.Orientation = 'Horizontal'; $leSplit.SplitterDistance = 300
$leSplit.Panel1MinSize = 80; $leSplit.Panel2MinSize = 44
$leSplit.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$leEdLabel = New-Object System.Windows.Forms.Label
$leEdLabel.Text = 'Intercepted buffer (edit before forwarding):'; $leEdLabel.ForeColor = [System.Drawing.Color]::Gray
$leEdLabel.Dock = 'Top'; $leEdLabel.Height = 20; $leEdLabel.Padding = [System.Windows.Forms.Padding]::new(6, 2, 0, 0)

$txtLeEdit = New-Object System.Windows.Forms.RichTextBox
$txtLeEdit.Dock = 'Fill'; $txtLeEdit.WordWrap = $false
$txtLeEdit.Font = [System.Drawing.Font]::new('Consolas', 9.5)
$txtLeEdit.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 18); $txtLeEdit.ForeColor = [System.Drawing.Color]::FromArgb(200, 220, 200)
$txtLeEdit.BorderStyle = 'None'; $txtLeEdit.Text = '(no packet intercepted yet)'

$leSplit.Panel1.Controls.Add($txtLeEdit); $leSplit.Panel1.Controls.Add($leEdLabel)

# Action bar
$leActBar = New-Object System.Windows.Forms.FlowLayoutPanel
$leActBar.Dock = 'Fill'; $leActBar.FlowDirection = 'LeftToRight'
$leActBar.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
$leActBar.Padding = [System.Windows.Forms.Padding]::new(6, 6, 0, 6)

$btnLeForward = New-Object System.Windows.Forms.Button
$btnLeForward.Text = 'Forward (modified)'; $btnLeForward.Width = 148; $btnLeForward.Height = 28; $btnLeForward.Enabled = $false
$btnLeForward.BackColor = [System.Drawing.Color]::FromArgb(0, 90, 190); $btnLeForward.ForeColor = [System.Drawing.Color]::White
$btnLeForward.FlatStyle = 'Flat'; $btnLeForward.Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)

$btnLePass = New-Object System.Windows.Forms.Button
$btnLePass.Text = 'Pass Through'; $btnLePass.Width = 110; $btnLePass.Height = 28; $btnLePass.Enabled = $false
$btnLePass.BackColor = [System.Drawing.Color]::FromArgb(50, 70, 50); $btnLePass.ForeColor = [System.Drawing.Color]::White
$btnLePass.FlatStyle = 'Flat'; $btnLePass.Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)

$btnLeDrop = New-Object System.Windows.Forms.Button
$btnLeDrop.Text = 'Drop'; $btnLeDrop.Width = 80; $btnLeDrop.Height = 28; $btnLeDrop.Enabled = $false
$btnLeDrop.BackColor = [System.Drawing.Color]::FromArgb(110, 25, 25); $btnLeDrop.ForeColor = [System.Drawing.Color]::White
$btnLeDrop.FlatStyle = 'Flat'; $btnLeDrop.Margin = [System.Windows.Forms.Padding]::new(0, 0, 8, 0)

[void]$leActBar.Controls.Add($btnLeForward)
[void]$leActBar.Controls.Add($btnLePass)
[void]$leActBar.Controls.Add($btnLeDrop)
$leSplit.Panel2.Controls.Add($leActBar)

$tabLiveEdit.Controls.Add($leSplit); $leSplit.BringToFront()

# Shared state
$script:LeHandle  = $null   # pscustomobject returned by Start-TcpkInterceptPipe
$script:LePending = $false  # $true when a packet is waiting for a decision

# Poll timer: checks for incoming packets from the background pipe server
$tmrLe = New-Object System.Windows.Forms.Timer; $tmrLe.Interval = 100

$tmrLe.Add_Tick({
    if ($null -eq $script:LeHandle) { return }
    $st = $script:LeHandle.State
    if (-not $script:LePending -and "$($st.Decision)" -eq 'PENDING') {
        $script:LePending = $true
        $raw = $st.PacketBytes
        if ($null -ne $raw) {
            $txtLeEdit.Text = [System.Text.Encoding]::Latin1.GetString($raw)
            $lblLeStatus.Text = "PACKET INTERCEPTED -- $($raw.Length) bytes. Edit and click Forward, Pass Through, or Drop."
            $lblLeStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 200, 60)
        }
        $btnLeForward.Enabled = $true; $btnLePass.Enabled = $true; $btnLeDrop.Enabled = $true
    }
    # Show connection status
    if (-not $script:LePending -and $st.Connected -and "$($st.Decision)" -eq 'IDLE') {
        if ($lblLeStatus.ForeColor.G -lt 150) {
            $lblLeStatus.Text = 'Hook connected. Waiting for outbound traffic...'; $lblLeStatus.ForeColor = [System.Drawing.Color]::Silver
        }
    }
})

function _LeDecide {
    param([string]$Decision, [byte[]]$ReplyBytes = $null)
    if ($null -eq $script:LeHandle) { return }
    $st = $script:LeHandle.State
    $st.ReplyBytes  = $ReplyBytes
    $st.Decision    = $Decision
    $script:LePending = $false
    $btnLeForward.Enabled = $false; $btnLePass.Enabled = $false; $btnLeDrop.Enabled = $false
}

$btnLeForward.Add_Click({
    $bytes = [System.Text.Encoding]::Latin1.GetBytes($txtLeEdit.Text)
    _LeDecide -Decision 'FORWARD' -ReplyBytes $bytes
    $lblLeStatus.Text = "Forwarded modified ($($bytes.Length) bytes)"; $lblLeStatus.ForeColor = [System.Drawing.Color]::FromArgb(80, 200, 100)
})

$btnLePass.Add_Click({
    _LeDecide -Decision 'PASSTHRU'
    $lblLeStatus.Text = 'Passed through (original unchanged)'; $lblLeStatus.ForeColor = [System.Drawing.Color]::Silver
})

$btnLeDrop.Add_Click({
    _LeDecide -Decision 'DROP'
    $lblLeStatus.Text = 'Dropped (hook sends 0 bytes)'; $lblLeStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 90, 90)
})

$btnLeStart.Add_Click({
    if ($null -ne $script:LeHandle) { return }
    $mod = @(Get-Module TCPK)[0]
    if (-not $mod) { $lblLeStatus.Text = 'TCPK module not loaded.'; return }
    try {
        $script:LeHandle = & $mod { Start-TcpkInterceptPipe }
        $btnLeStart.Enabled = $false; $btnLeStop.Enabled = $true
        $tmrLe.Start()
        $lblLeStatus.Text = 'Pipe server running. Attach frida to the target process with tcpk_hook.js.'
        $lblLeStatus.ForeColor = [System.Drawing.Color]::FromArgb(80, 200, 100)
    } catch {
        $lblLeStatus.Text = "Failed to start pipe server: $($_.Exception.Message)"; $lblLeStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 90, 90)
    }
})

$btnLeStop.Add_Click({
    if ($null -eq $script:LeHandle) { return }
    $tmrLe.Stop()
    $h = $script:LeHandle; $script:LeHandle = $null; $script:LePending = $false
    $mod = @(Get-Module TCPK)[0]
    if ($mod) { try { & $mod { param($hh) Stop-TcpkInterceptPipe -Handle $hh } $h } catch { } }
    $btnLeStart.Enabled = $true; $btnLeStop.Enabled = $false
    $btnLeForward.Enabled = $false; $btnLePass.Enabled = $false; $btnLeDrop.Enabled = $false
    $lblLeStatus.Text = 'Pipe server stopped.'; $lblLeStatus.ForeColor = [System.Drawing.Color]::Gray
})

$btnGraphBuild.Add_Click({
    if (-not $script:CurrentOutDir) { $lblGraphStatus.Text = "No audit output -- run an audit first (Audit tab)."; return }
    $jsonPath = Join-Path $script:CurrentOutDir 'findings.json'
    if (-not (Test-Path -LiteralPath $jsonPath)) { $lblGraphStatus.Text = "findings.json not found -- run an audit first."; return }
    $lblGraphStatus.Text = "Building graph..."
    [System.Windows.Forms.Application]::DoEvents()
    # MUST run inside the module. New-TcpkFinding lives in Private/ and Export-ModuleMember
    # only publishes Public/*.ps1, so it does not exist in GUI scope -- and [TcpkFinding],
    # the type Get-TcpkAttackGraph demands, is a module-scoped class that a caller cannot
    # construct without `using module` either. Calling them from here threw
    # "not recognized", the catch below turned it into "Graph failed: ...", and the tab
    # looked broken after every completed audit. Same `& $mod { }` pattern the asar and
    # decompiler tabs already use.
    $graphFindings = @()
    $findingCount  = 0
    try {
        $mod = @(Get-Module TCPK)[0]
        if (-not $mod) { throw 'TCPK module is not loaded in this session.' }
        $res = & $mod {
            param($p)
            $raw = @(Read-TcpkFindingsJson -Path $p)
            $findings = @(ConvertTo-TcpkFindingObject -Raw $raw)
            [pscustomobject]@{
                Count   = $findings.Count
                Dropped = ($raw.Count - $findings.Count)
                Graph   = @($findings | Get-TcpkAttackGraph)
            }
        } $jsonPath
        $findingCount  = [int]$res.Count
        $graphFindings = @($res.Graph)
        if ([int]$res.Dropped -gt 0) {
            Write-LogLine "Graph: skipped $($res.Dropped) malformed finding(s) in findings.json" ([System.Drawing.Color]::FromArgb(241,196,15))
        }
    } catch {
        $lblGraphStatus.Text = "Graph failed: $($_.Exception.Message)"
        return
    }
    if (-not $graphFindings.Count) {
        $lblGraphStatus.Text = "Graph produced nothing from $findingCount finding(s) -- no correlation rules matched."
        $txtMermaid.Text = "(no diagram)"
        $btnGraphCopy.Enabled = $false
        return
    }
    $goals = @($graphFindings | Where-Object { $_.RuleId -eq 'attackgraph.reachable-goal' })
    $render = $graphFindings | Where-Object { $_.RuleId -eq 'attackgraph.render' } | Select-Object -First 1
    $noPath = $graphFindings | Where-Object { $_.RuleId -eq 'attackgraph.no-path' } | Select-Object -First 1
    $lvGoals.Items.Clear()
    if ($noPath) {
        $lblGraphStatus.Text = "No end-to-end attack path correlated from $findingCount findings."
        $txtMermaid.Text = "(no attack paths found -- individual findings may still matter)"
        $btnGraphCopy.Enabled = $false
        return
    }
    foreach ($g in $goals) {
        $item = New-Object System.Windows.Forms.ListViewItem("$($g.Severity)")
        if ($script:SevColour.ContainsKey("$($g.Severity)")) { $item.ForeColor = $script:SevColour["$($g.Severity)"] }
        [void]$item.SubItems.Add("$($g.Title)")
        [void]$item.SubItems.Add("$($g.Evidence)")
        [void]$lvGoals.Items.Add($item)
    }
    $mermaid = ''
    if ($render) {
        $desc = "$($render.Description)"
        $m = [regex]::Match($desc, '(?s)```mermaid\r?\n(.+?)\r?\n```')
        if ($m.Success) { $mermaid = $m.Groups[1].Value }
    }
    $txtMermaid.Text = if ($mermaid) { $mermaid } else { "(no diagram)" }
    $btnGraphCopy.Enabled = [bool]$mermaid
    $lblGraphStatus.Text = "$($goals.Count) reachable goal(s) from $findingCount findings. $($render.Evidence -replace '\s+', ' ')"
})
$btnGraphCopy.Add_Click({
    $src = $txtMermaid.Text
    if ($src -and $src -ne '(no diagram)' -and $src -ne '(no attack paths found -- individual findings may still matter)') {
        [System.Windows.Forms.Clipboard]::SetText($src)
        $lblGraphStatus.Text = "Mermaid source copied to clipboard."
    }
})

$form.Controls.Add($tabs)
$tabs.BringToFront()

# Live log (left)
$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = "Live progress (each check fires as it runs)"
$logLabel.Dock = 'Top'
$logLabel.Height = 22
$logLabel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40); $logLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$logLabel.Padding = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
$split.Panel1.Controls.Add($logLabel)

$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Dock = 'Fill'
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLog.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtLog.ForeColor = [System.Drawing.Color]::White
$txtLog.ReadOnly = $true
$txtLog.WordWrap = $false
$split.Panel1.Controls.Add($txtLog)
$txtLog.BringToFront()

# Scan worker resource readout. CPU% and RAM for the active scan job worker,
# sampled every 2 seconds so a pegged or stalled scan is visible at a glance
# without an external monitor. The worker is a real separate process (Start-Job),
# so $PID inside the job is the process to measure.
#
# CPU% is delta of Process.CPU over wall seconds. That is summed across cores, so
# on a multi-threaded process it could exceed 100 -- but the audit worker is a
# single-threaded PS 5.1 process, so pegged reads ~100 and stalled reads ~0, which
# is exactly the signal wanted. Clamped for safety.
#
# LAYOUT. Directly below Run Audit, left-aligned with it (x 820), in the only band
# at that x that is actually free. The header is fully packed; measured occupancy in
# the x 820-1006 column is:
#     y   6- 32  btnBrowse / btnAutoDetect
#     y  38- 70  btnRun / btnPause
#     y  78- 96  lblAiStatus   (x 820-1180)
#     y 136-156  lblIdent      (x 14-1006)
# leaving y 98-134. An earlier attempt at (980, 8) landed on top of btnAutoDetect and
# clipped its caption. picLogo owns x 1008-1176, so the panel stops at 1006, flush
# with the right edge of btnPause.
#
# Z-ORDER matters as much as position: Controls.Add appends and index 0 is the FRONT,
# so a control added this late in the script is drawn BEHIND everything added earlier.
# Once the theme pass gives every Label an opaque BackColor, behind means invisible.
# Hence BringToFront().
#
# AutoSize is OFF deliberately -- it overrides Size on a FlowLayoutPanel, and the
# labels carry Margin 0 so the two of them fit the fixed width exactly.
# Tag 'keep' exempts them from Set-CtlThemeRecursive, which repaints every Label with
# the palette foreground and would erase the colour coding.
$script:IcptClearNext     = $false
$script:RtInRunAll        = $false
$script:ScanWorkerPid     = 0
$script:ScanWorkerLastCpu = 0.0
$script:ScanWorkerLastAt  = [DateTime]::Now

# Two meters, each a fixed track panel with a coloured fill panel inside it. The fill's
# WIDTH is the value, so there is no Paint handler and nothing custom-drawn -- an exception
# inside a WinForms Paint override is ugly and hard to contain, and this needs none.
#
# Colour is the point. "CPU 78%" as text needs reading; a bar that turns amber then red is
# read at a glance from across a room, which is the difference between noticing a pegged
# scan and not. Thresholds: green under 50, amber 50-84, red 85+.
$pnlRes = New-Object System.Windows.Forms.Panel
$pnlRes.Tag      = 'keep'
$pnlRes.Size     = New-Object System.Drawing.Size(186, 34)
$pnlRes.Location = New-Object System.Drawing.Point(820, 96)
$pnlRes.Anchor   = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($pnlRes)

# --- CPU row ---
$lblCpuPct = New-Object System.Windows.Forms.Label
$lblCpuPct.Text      = 'CPU   --'
$lblCpuPct.Tag       = 'keep'
$lblCpuPct.AutoSize  = $false
$lblCpuPct.Location  = New-Object System.Drawing.Point(0, 0)
$lblCpuPct.Size      = New-Object System.Drawing.Size(96, 15)
$lblCpuPct.TextAlign = 'MiddleLeft'
$lblCpuPct.Font      = New-Object System.Drawing.Font('Consolas', 8, [System.Drawing.FontStyle]::Bold)
$lblCpuPct.ForeColor = [System.Drawing.Color]::FromArgb(166, 226, 46)
$pnlRes.Controls.Add($lblCpuPct)

$script:CpuTrack = New-Object System.Windows.Forms.Panel
$script:CpuTrack.Tag       = 'keep'
$script:CpuTrack.Location  = New-Object System.Drawing.Point(98, 3)
$script:CpuTrack.Size      = New-Object System.Drawing.Size(86, 9)
$script:CpuTrack.BackColor = [System.Drawing.Color]::FromArgb(38, 42, 50)
$pnlRes.Controls.Add($script:CpuTrack)

$script:CpuFill = New-Object System.Windows.Forms.Panel
$script:CpuFill.Tag       = 'keep'
$script:CpuFill.Location  = New-Object System.Drawing.Point(0, 0)
$script:CpuFill.Size      = New-Object System.Drawing.Size(0, 9)
$script:CpuFill.BackColor = [System.Drawing.Color]::FromArgb(166, 226, 46)
$script:CpuTrack.Controls.Add($script:CpuFill)

# --- RAM row ---
$lblRamMb = New-Object System.Windows.Forms.Label
$lblRamMb.Text      = 'RAM   --'
$lblRamMb.Tag       = 'keep'
$lblRamMb.AutoSize  = $false
$lblRamMb.Location  = New-Object System.Drawing.Point(0, 17)
$lblRamMb.Size      = New-Object System.Drawing.Size(96, 15)
$lblRamMb.TextAlign = 'MiddleLeft'
$lblRamMb.Font      = New-Object System.Drawing.Font('Consolas', 8, [System.Drawing.FontStyle]::Bold)
$lblRamMb.ForeColor = [System.Drawing.Color]::FromArgb(102, 217, 239)
$pnlRes.Controls.Add($lblRamMb)

$script:RamTrack = New-Object System.Windows.Forms.Panel
$script:RamTrack.Tag       = 'keep'
$script:RamTrack.Location  = New-Object System.Drawing.Point(98, 20)
$script:RamTrack.Size      = New-Object System.Drawing.Size(86, 9)
$script:RamTrack.BackColor = [System.Drawing.Color]::FromArgb(38, 42, 50)
$pnlRes.Controls.Add($script:RamTrack)

$script:RamFill = New-Object System.Windows.Forms.Panel
$script:RamFill.Tag       = 'keep'
$script:RamFill.Location  = New-Object System.Drawing.Point(0, 0)
$script:RamFill.Size      = New-Object System.Drawing.Size(0, 9)
$script:RamFill.BackColor = [System.Drawing.Color]::FromArgb(102, 217, 239)
$script:RamTrack.Controls.Add($script:RamFill)

$pnlRes.BringToFront()

# RAM has no natural 100% for a scan worker, so the bar is scaled against a moving high-water
# mark rather than an invented ceiling. A bar pinned at full would say "out of memory", which
# would be a lie; against the peak it honestly shows "this is the most it has used so far".
$script:RamPeakMb = 256

# $CpuPct is SYSTEM-WIDE percent, the same denominator Task Manager uses, so the two agree.
# Callers compute it as (cpu-seconds / wall-seconds / ProcessorCount) * 100. The earlier
# version divided by wall time only, which is percent-of-ONE-CORE: a single pegged core read
# 100% here while Task Manager showed 12.5% on an 8-core box, and the two looked like a bug.
#
# $Cores is the core-equivalent (1.5 = one and a half cores busy). It is the number that
# actually tells you whether a scan is pegged, because a single-threaded worker cannot exceed
# 1.0 no matter how many cores the box has -- so 12% could be idle or could be maxed out, and
# only the core figure distinguishes them. Both are shown.
#
# $Src names the process being measured. Without it there is no way to tell a worker reading
# 0% from the GUI being sampled because the worker PID was never picked up.
function Update-ScanResources {
    param([int]$CpuPct, [int]$RamMb, [double]$Cores = -1, [string]$Src = '')
    $coreTxt = if ($Cores -ge 0) { ' {0:N1}c' -f $Cores } else { '' }
    $lblCpuPct.Text = 'CPU {0,3}%{1}' -f $CpuPct, $coreTxt
    $lblRamMb.Text  = 'RAM {0,5}M{1}' -f $RamMb, $(if ($Src) { " $Src" } else { '' })

    $c = if ($CpuPct -ge 85) { [System.Drawing.Color]::FromArgb(249, 38, 114) }
         elseif ($CpuPct -ge 50) { [System.Drawing.Color]::FromArgb(230, 176, 40) }
         else { [System.Drawing.Color]::FromArgb(166, 226, 46) }
    try {
        $w = [int]([Math]::Max(0, [Math]::Min(100, $CpuPct)) * $script:CpuTrack.Width / 100)
        $script:CpuFill.Width     = $w
        $script:CpuFill.BackColor = $c
        $lblCpuPct.ForeColor      = $c
    } catch { }

    if ($RamMb -gt $script:RamPeakMb) { $script:RamPeakMb = $RamMb }
    try {
        $rw = if ($script:RamPeakMb -gt 0) { [int]($RamMb * $script:RamTrack.Width / $script:RamPeakMb) } else { 0 }
        $script:RamFill.Width = [Math]::Max(0, [Math]::Min($script:RamTrack.Width, $rw))
    } catch { }
}

# Task Manager's "Memory" column is the ACTIVE PRIVATE working set. Process.WorkingSet64 is
# private + SHARED -- every mapped DLL page the process shares with other processes counts
# toward it -- so the two differ by 100 MB or more on a .NET/WinForms host and the gauge
# looks wrong next to Task Manager even though both numbers are correct.
#
# Private working set is not exposed by System.Diagnostics.Process, so it comes from the perf
# class. WorkingSetPrivate there is PERF_COUNTER_LARGE_RAWCOUNT: the raw value IS the byte
# count, no rate computation needed. Falls back to WorkingSet64 if the query fails, because
# performance counters do get corrupted on real machines and a slightly-too-large number
# beats a blank gauge.
function Get-TcpkPrivateWsMb {
    param([int]$ProcId, [long]$FallbackBytes)
    try {
        $c = Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -Filter "IDProcess=$ProcId" -OperationTimeoutSec 5 -ErrorAction Stop
        if ($c) {
            $wsp = @($c)[0].WorkingSetPrivate
            if ($wsp -and $wsp -gt 0) { return [int]($wsp / 1MB) }
        }
    } catch { }
    return [int]($FallbackBytes / 1MB)
}

function Reset-ScanResources {
    $lblCpuPct.Text = 'CPU   --'
    $lblRamMb.Text  = 'RAM   --'
    $lblCpuPct.ForeColor = [System.Drawing.Color]::FromArgb(166, 226, 46)
    try { $script:CpuFill.Width = 0; $script:RamFill.Width = 0 } catch { }
    $script:RamPeakMb = 256
}

# Keeps the gauge live for the WHOLE tool, not only during an audit. Samples the audit
# worker when one is running, otherwise this GUI process.
#
# HONEST LIMIT: the tool tabs run their checks SYNCHRONOUSLY on the UI thread, so while one
# is in flight the message pump is blocked and this timer cannot tick. The gauge therefore
# freezes during a long check -- which is itself the signal that the UI thread is busy, not
# a bug. Per-action cost is reported separately by Invoke-IcptTool, which measures across
# the call and prints CPU seconds and peak working set when it returns.
$script:ResLastCpu = 0.0
$script:ResLastAt  = [DateTime]::Now
$script:ResTimer = New-Object System.Windows.Forms.Timer
$script:ResTimer.Interval = 2000
$script:ResTimer.Add_Tick({
    try {
        # The audit's own poll loop samples the worker and keeps a separate baseline, so bail
        # out FIRST when one is active rather than querying a process we then discard.
        if ($script:ScanWorkerPid -gt 0) { return }
        $pr = Get-Process -Id $PID -ErrorAction Stop
        $now = [DateTime]::Now
        $el = ($now - $script:ResLastAt).TotalSeconds
        if ($el -lt 1.0) { return }
        $d = $pr.CPU - $script:ResLastCpu
        $script:ResLastCpu = $pr.CPU
        $script:ResLastAt  = $now
        $cores = [Math]::Max(1, [Environment]::ProcessorCount)
        $ce  = [Math]::Max(0.0, $d / $el)                       # core-equivalent
        $pct = [Math]::Max(0, [Math]::Min(100, [int](($ce / $cores) * 100)))
        Update-ScanResources -CpuPct $pct -RamMb (Get-TcpkPrivateWsMb -ProcId $pr.Id -FallbackBytes $pr.WorkingSet64) -Cores $ce -Src 'gui'
    } catch { }
})
$script:ResTimer.Start()

# Findings (right)
$findLabel = New-Object System.Windows.Forms.Label
$findLabel.Text = "Findings (live)"
$findLabel.Dock = 'Top'
$findLabel.Height = 22
$findLabel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40); $findLabel.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$findLabel.Padding = New-Object System.Windows.Forms.Padding(6, 4, 0, 0)
$split.Panel2.Controls.Add($findLabel)

$lvFindings = New-Object System.Windows.Forms.ListView
$lvFindings.Dock = 'Fill'
$lvFindings.View = 'Details'
$lvFindings.FullRowSelect = $true
$lvFindings.GridLines = $true
$lvFindings.Font = New-Object System.Drawing.Font('Segoe UI', 9)
[void]$lvFindings.Columns.Add('Severity', 80)
[void]$lvFindings.Columns.Add('Confidence', 90)
[void]$lvFindings.Columns.Add('RuleId', 250)
[void]$lvFindings.Columns.Add('Title', 600)
$split.Panel2.Controls.Add($lvFindings)
$lvFindings.BringToFront()

# Progress bar + live status -- placed in the appearance row of the header, just right
# of the "Theme" button, instead of a separate full-width row. This fills the empty
# space in that row and keeps the audit's progress next to the controls. The status
# label is Left+Right anchored so it stretches to fill the empty band when the window
# is widened (stopping short of the right-anchored logo).
$pbar = New-Object System.Windows.Forms.ProgressBar
$pbar.Location = New-Object System.Drawing.Point(466, 110)
$pbar.Size = New-Object System.Drawing.Size(200, 16)
$pbar.Minimum = 0; $pbar.Maximum = 100; $pbar.Value = 0
$pbar.Style = 'Continuous'   # solid fill (no chunk animation / value-set lag)
$pbar.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
$topPanel.Controls.Add($pbar)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Ready. Pick a target, then click Run Audit."
$lblStatus.Location = New-Object System.Drawing.Point(674, 109)
$lblStatus.Size = New-Object System.Drawing.Size(320, 18)
$lblStatus.TextAlign = 'MiddleLeft'
$lblStatus.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($lblStatus)

# Footer -- shortcuts to the generated reports (enabled after an audit completes).
$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Dock = 'Bottom'
$bottomPanel.Height = 34
$bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.Controls.Add($bottomPanel)

$lblReports = New-Object System.Windows.Forms.Label
$lblReports.Text = "Generated reports:"; $lblReports.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$lblReports.Dock = 'Left'
$lblReports.Width = 150
$lblReports.TextAlign = 'MiddleLeft'
$lblReports.Padding = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
$bottomPanel.Controls.Add($lblReports)

$btnOpenHtml = New-Object System.Windows.Forms.Button
$btnOpenHtml.Text = "Open HTML report"
$btnOpenHtml.Dock = 'Right'
$btnOpenHtml.Width = 140
$btnOpenHtml.Enabled = $false
$btnOpenHtml.FlatStyle = 'Flat'; $btnOpenHtml.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnOpenHtml.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$bottomPanel.Controls.Add($btnOpenHtml)

$btnOpenExcel = New-Object System.Windows.Forms.Button
$btnOpenExcel.Text = "Open Excel report"
$btnOpenExcel.Dock = 'Right'
$btnOpenExcel.Width = 140
$btnOpenExcel.Enabled = $false
$btnOpenExcel.FlatStyle = 'Flat'; $btnOpenExcel.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnOpenExcel.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$bottomPanel.Controls.Add($btnOpenExcel)

$btnOpenMarkdown = New-Object System.Windows.Forms.Button
$btnOpenMarkdown.Text = "Open Markdown"
$btnOpenMarkdown.Dock = 'Right'
$btnOpenMarkdown.Width = 130
$btnOpenMarkdown.Enabled = $false
$btnOpenMarkdown.FlatStyle = 'Flat'; $btnOpenMarkdown.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnOpenMarkdown.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$bottomPanel.Controls.Add($btnOpenMarkdown)

$btnOpenFolder = New-Object System.Windows.Forms.Button
$btnOpenFolder.Text = "Open output folder"
$btnOpenFolder.Dock = 'Right'
$btnOpenFolder.Width = 140
$btnOpenFolder.Enabled = $false
$btnOpenFolder.FlatStyle = 'Flat'; $btnOpenFolder.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60); $btnOpenFolder.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$bottomPanel.Controls.Add($btnOpenFolder)

# --- Helper functions ---
$script:CurrentOutDir = $null

function Write-LogLine {
    param([string]$Text, [System.Drawing.Color]$Color = [System.Drawing.Color]::White)
    $txtLog.SelectionStart = $txtLog.TextLength
    $txtLog.SelectionLength = 0
    $txtLog.SelectionColor = $Color
    $txtLog.AppendText("$Text`r`n")
    $txtLog.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Add-Finding($f) {
    $item = New-Object System.Windows.Forms.ListViewItem($f.Severity)
    if ($script:SevColour.ContainsKey($f.Severity)) {
        $item.ForeColor = $script:SevColour[$f.Severity]
    }
    [void]$item.SubItems.Add(([string]$f.Confidence))
    [void]$item.SubItems.Add(([string]$f.RuleId))
    [void]$item.SubItems.Add(([string]$f.Title))
    [void]$lvFindings.Items.Add($item)
    # NOTE: no per-item DoEvents here -- bulk callers wrap with BeginUpdate/EndUpdate
    # for smooth rendering. Calling DoEvents per finding made the table janky.
}

function Update-Status([string]$msg) {
    $lblStatus.Text = $msg
    [System.Windows.Forms.Application]::DoEvents()
}

# --- audit progress bar (0-100%) ---
# Checks fill 0-88%; the post-check phases (triage / IL verify / LLM / reports)
# carry 88-99%; the job ending snaps to 100. Progress is monotonic (never rewinds).
$script:ChkDone  = 0
$script:ChkTotal = 1
$script:ProgPct  = 0

function Reset-Progress([int]$total) {
    $script:ChkDone  = 0
    $script:ProgPct  = 0
    $script:ChkTotal = [Math]::Max(1, $total)
    $pbar.Value = 0
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-Progress([int]$pct) {
    if ($pct -lt 0) { $pct = 0 } elseif ($pct -gt 100) { $pct = 100 }
    if ($pct -le $script:ProgPct) { return }    # never go backwards
    $script:ProgPct = $pct
    $pbar.Value = $pct
    [System.Windows.Forms.Application]::DoEvents()
}

function Update-RunStatus {
    $lblStatus.Text = "Running... $($script:ProgPct)%   |   Findings: $($lvFindings.Items.Count)"
}

# Advance the bar from a single streamed audit log line.
function Step-ProgressFromLog([string]$msg) {
    # A completed check prints e.g. "  Test-TcpkSecrets   3 findings  (   2s)" (or FAILED).
    if ($msg -match '\d+ findings\s+\(\s*\d+s\)\s*$' -or $msg -match '\bFAILED\s+\(') {
        $script:ChkDone++
        $p = [int][Math]::Round(88.0 * $script:ChkDone / $script:ChkTotal)
        Set-Progress ([Math]::Min(88, $p))
        return
    }
    # Post-check phase milestones (substring match against the audit's own log lines).
    switch -Regex ($msg) {
        'Triaging via Resolve' { Set-Progress 90 }
        'IL verify:'           { Set-Progress 92 }
        'LLM Stage-2'          { Set-Progress 93 }
        'LLM annotated'        { Set-Progress 95 }
        'SBOM written'         { Set-Progress 96 }
        'written:'             { Set-Progress 97 }   # "Excel written: ...", report lines
        'Recon profile'        { Set-Progress 98 }
    }
}

# --- Recon tab rendering ---
$script:ReconCyan   = [System.Drawing.Color]::FromArgb(102, 217, 239)
$script:ReconGray   = [System.Drawing.Color]::FromArgb(150, 150, 150)
$script:ReconWhite  = [System.Drawing.Color]::White
$script:ReconGreen  = [System.Drawing.Color]::FromArgb(166, 226, 46)
$script:ReconOrange = [System.Drawing.Color]::FromArgb(253, 151, 31)
$script:ReconRed    = [System.Drawing.Color]::FromArgb(249, 38, 114)

function Write-Recon([string]$Text, [System.Drawing.Color]$Color = $script:ReconWhite) {
    $txtRecon.SelectionStart = $txtRecon.TextLength
    $txtRecon.SelectionLength = 0
    $txtRecon.SelectionColor = $Color
    $txtRecon.AppendText($Text)
}
function Write-ReconHdr([string]$Title) {
    Write-Recon "`r`n" $script:ReconWhite
    Write-Recon ("== $Title ".PadRight(72, '=') + "`r`n") $script:ReconCyan
}
function Write-ReconKv([string]$Key, $Val) {
    if ($null -eq $Val -or "$Val" -eq '') { return }
    Write-Recon ("  {0,-15}" -f $Key) $script:ReconGray
    Write-Recon ("$Val`r`n") $script:ReconWhite
}

function Render-Recon([string]$OutDir) {
    $pf = Join-Path $OutDir 'profile.json'
    if (-not (Test-Path $pf)) {
        $txtRecon.Text = "No profile.json was produced for this audit."
        return
    }
    $p = $null
    try { $p = Get-Content -LiteralPath $pf -Raw | ConvertFrom-Json } catch {
        $txtRecon.Text = "Could not parse profile.json: $($_.Exception.Message)"
        return
    }
    $txtRecon.Clear()

    Write-Recon "TARGET RECONNAISSANCE PROFILE`r`n" $script:ReconGreen

    Write-ReconHdr 'Application'
    Write-ReconKv 'Name'         $p.Name
    Write-ReconKv 'Version'      $p.Version
    Write-ReconKv 'Publisher'    $p.Publisher
    Write-ReconKv 'Architecture' $p.Architecture
    Write-ReconKv 'Type'         $p.AppType
    Write-ReconKv 'Main exe'     $p.MainExecutable
    $rt = $p.Runtime; if ($p.RuntimeDetail) { $rt = "$($p.Runtime)  ($($p.RuntimeDetail))" }
    Write-ReconKv 'Runtime'      $rt
    Write-ReconKv 'Privilege'    $p.PrivilegeModel
    Write-ReconKv 'Package'      $p.PackageFullName
    Write-ReconKv 'Install path' $p.InstallPath

    Write-ReconHdr 'Code signing'
    Write-ReconKv 'Status'    $p.Signature.Status
    Write-ReconKv 'Subject'   $p.Signature.Subject
    Write-ReconKv 'Issuer'    $p.Signature.Issuer
    if ($p.Signature.NotAfter) {
        $exp = $p.Signature.NotAfter
        if ($p.Signature.KeySize)   { $exp += "  ($($p.Signature.KeySize)-bit" }
        if ($p.Signature.Algorithm) { $exp += ", $($p.Signature.Algorithm))" } elseif ($p.Signature.KeySize) { $exp += ")" }
        Write-ReconKv 'Expires' $exp
    }
    if ($p.Signature.Note) { Write-ReconKv 'Note' $p.Signature.Note }

    Write-ReconHdr 'Technology stack'
    Write-ReconKv 'UI frameworks' (($p.UiFrameworks)     -join ', ')
    Write-ReconKv 'Network'       (($p.NetworkProtocols) -join ', ')
    Write-ReconKv 'Update'        (($p.UpdateMechanism)  -join ', ')

    Write-ReconHdr 'Attack surface'
    $c = $p.Counts
    Write-Recon ("  {0} DLLs   {1} EXE   {2} drivers   {3} endpoints   {4} ports   {5} COM   {6} pipes   {7} services   {8} handlers   {9} file-assoc`r`n" -f `
        $c.Dll, $c.Exe, $c.Sys, $c.Endpoint, $c.Port, $c.Com, $c.Pipe, $c.Service, $c.ProtocolHandler, $c.FileAssoc) $script:ReconWhite

    Write-ReconHdr ("Network endpoints (" + @($p.Endpoints).Count + ")")
    if (@($p.Endpoints).Count -eq 0) {
        Write-Recon "  (none found in first-party binaries)`r`n" $script:ReconGray
    } else {
        foreach ($e in $p.Endpoints) {
            Write-Recon ("  {0,-46} " -f $e.Host) $script:ReconGreen
            $d = "$($e.Detail)"; if ($d.Length -gt 90) { $d = $d.Substring(0,90) + '...' }
            Write-Recon "$d`r`n" $script:ReconGray
        }
    }

    Write-ReconHdr ("Listening ports (" + @($p.ListeningPorts).Count + ")")
    if (@($p.ListeningPorts).Count -eq 0) {
        Write-Recon "  (no live-process port scan -- supply a running ProcessName to enumerate ports)`r`n" $script:ReconGray
    } else {
        foreach ($lp in $p.ListeningPorts) {
            $col = if ($lp.Severity -in 'HIGH','CRITICAL') { $script:ReconRed } elseif ($lp.Severity -eq 'MEDIUM') { $script:ReconOrange } else { $script:ReconWhite }
            Write-Recon ("  {0,-4} {1,-24} {2,-16} [{3}]`r`n" -f $lp.Proto, $lp.Endpoint, $lp.Scope, $lp.Severity) $col
        }
    }

    if (@($p.ProtocolHandlers).Count) {
        Write-ReconHdr ("Protocol handlers (" + @($p.ProtocolHandlers).Count + ")")
        foreach ($h in $p.ProtocolHandlers) { Write-Recon "  $($h.Title)`r`n" $script:ReconWhite }
    }
    if (@($p.ComServers).Count) {
        Write-ReconHdr ("COM servers (" + @($p.ComServers).Count + ")")
        foreach ($cs in $p.ComServers) { Write-Recon "  $($cs.Title)`r`n" $script:ReconWhite }
    }
    if (@($p.NamedPipes).Count) {
        Write-ReconHdr ("Named pipes (" + @($p.NamedPipes).Count + ")")
        foreach ($pp in $p.NamedPipes) { Write-Recon "  $($pp.Title)`r`n" $script:ReconWhite }
    }
    if (@($p.FileAssociations).Count) {
        Write-ReconHdr ("File-type associations (" + @($p.FileAssociations).Count + ")")
        foreach ($fa in $p.FileAssociations) { Write-Recon "  $($fa.Title)`r`n" $script:ReconWhite }
    }

    Write-ReconHdr ("Third-party SDKs (" + @($p.ThirdPartySdks).Count + ")")
    if (@($p.ThirdPartySdks).Count -eq 0) {
        Write-Recon "  (none identified)`r`n" $script:ReconGray
    } else {
        foreach ($s in $p.ThirdPartySdks) {
            Write-Recon ("  {0,-34} " -f $s.Name) $script:ReconWhite
            Write-Recon ("{0,-28} " -f $s.Company) $script:ReconGray
            Write-Recon ("{0}`r`n" -f $s.Version) $script:ReconOrange
        }
    }

    if (@($p.TlsPosture).Count) {
        Write-ReconHdr 'Transport security posture'
        foreach ($t in $p.TlsPosture) {
            $col = if ("$t" -match 'ABSENT|disabled|cleartext|no-auth') { $script:ReconRed } else { $script:ReconWhite }
            Write-Recon "  $t`r`n" $col
        }
    }
    if (@($p.UpdateUrls).Count) {
        Write-ReconHdr ("Update URLs (" + @($p.UpdateUrls).Count + ")")
        foreach ($u in $p.UpdateUrls) { Write-Recon "  $u`r`n" $script:ReconGray }
    }
    if (@($p.NonProdEndpoints).Count) {
        Write-ReconHdr ("Non-production / environment-specific endpoints (" + @($p.NonProdEndpoints).Count + ")")
        foreach ($u in $p.NonProdEndpoints) { Write-Recon "  $u`r`n" $script:ReconOrange }
    }

    # --- INTERESTING STRINGS (from strings.json sidecar; recon-tab only) ---
    $sf = Join-Path $OutDir 'strings.json'
    if (Test-Path $sf) {
        $s = $null
        try { $s = Get-Content -LiteralPath $sf -Raw | ConvertFrom-Json } catch { }
        if ($s) {
            function _StrSection([string]$Title, $Items, [System.Drawing.Color]$Color) {
                $arr = @($Items)
                if ($arr.Count -eq 0) { return }
                Write-ReconHdr ("$Title (" + $arr.Count + ")")
                foreach ($it in $arr) { Write-Recon "  $it`r`n" $Color }
            }
            Write-Recon "`r`n" $script:ReconWhite
            Write-Recon (('#' * 72) + "`r`n") $script:ReconGreen
            Write-Recon "INTERESTING STRINGS  (extracted from first-party binaries)`r`n" $script:ReconGreen
            Write-Recon (('#' * 72) + "`r`n") $script:ReconGreen
            _StrSection 'URLs'                 $s.Urls         $script:ReconCyan
            _StrSection 'File paths'           $s.FilePaths    $script:ReconWhite
            _StrSection 'Registry keys'        $s.RegistryKeys $script:ReconWhite
            _StrSection 'IP addresses'         $s.IpAddresses  $script:ReconOrange
            _StrSection 'Email addresses'      $s.Emails       $script:ReconOrange
            _StrSection 'Command-line tool references' $s.Commands $script:ReconRed
            _StrSection 'Secret-ish literals'  $s.Interesting  $script:ReconRed
        }
    }

    $txtRecon.SelectionStart = 0
    $txtRecon.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# Apply the GUI's AI selections into the TCPK module config (and enable cloud gate).
function Set-AiConfigFromGui {
    $sel = $cmbAi.SelectedItem
    $preset = $script:AiPresets[$sel]
    if (-not $preset) { return $false }
    $provider = $preset.name
    $model = $txtAiModel.Text
    $key = $txtAiKey.Text

    # Write into the module's config + enable cloud if needed (in-module-scope)
    InModuleScope TCPK -ArgumentList $provider, $model, $key, $preset.needsKey {
        param($provider, $model, $key, $needsKey)
        Set-TcpkLlmConfig -Provider $provider -Model $model -ApiKey $key -Enabled $true | Out-Null
        if ($needsKey) { $script:TcpkLlmCloudEnabled = $true }
    }
    return $true
}

# --- Exploit tab: plan population, gate toggle, run dispatcher ---
$script:ExploitPlan = @()
$script:ExploitGateOn = $false

function Write-Exp([string]$Text, [System.Drawing.Color]$Color = $script:ReconWhite) {
    $txtExpDetail.SelectionStart = $txtExpDetail.TextLength
    $txtExpDetail.SelectionLength = 0
    $txtExpDetail.SelectionColor = $Color
    $txtExpDetail.AppendText($Text)
}

function Populate-Exploits([string]$OutDir) {
    $lvExp.Items.Clear(); $script:ExploitPlan = @()
    $ef = Join-Path $OutDir 'exploits.json'
    if (-not (Test-Path $ef)) { return }
    # PS 5.1 ConvertFrom-Json quirk: it emits a top-level JSON array as a SINGLE
    # pipeline object. You must (1) assign it to a variable, THEN (2) wrap that
    # variable in @(). Wrapping the call directly -- @(ConvertFrom-Json ...) --
    # collapses to one element. Two steps are required.
    $parsed = $null
    try { $parsed = ConvertFrom-Json (Get-Content -LiteralPath $ef -Raw) } catch { return }
    if ($null -eq $parsed) { return }
    $plan = @($parsed)
    $script:ExploitPlan = $plan
    foreach ($it in $plan) {
        $row = New-Object System.Windows.Forms.ListViewItem("$($it.Kind)")
        if ($script:SevColour.ContainsKey("$($it.Severity)")) { $row.ForeColor = $script:SevColour["$($it.Severity)"] }
        [void]$row.SubItems.Add("$($it.Severity)")
        [void]$row.SubItems.Add("$($it.Id)")
        [void]$row.SubItems.Add($(if ($it.Module) { "$($it.Module)" } else { "$($it.Area)" }))
        [void]$row.SubItems.Add("$($it.Status)")
        [void]$lvExp.Items.Add($row)
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Populate-Sbom([string]$OutDir) {
    $script:SbomItems = New-Object System.Collections.Generic.List[object]
    $lvSbom.Items.Clear()
    $sf = Join-Path $OutDir 'sbom.cdx.json'
    if (-not (Test-Path $sf)) { return }
    $bom = $null
    try { $bom = ConvertFrom-Json (Get-Content -LiteralPath $sf -Raw) } catch { return }
    if ($null -eq $bom) { return }
    # map component bom-ref -> CVE ids (from the embedded vulnerabilities array)
    $cveByRef = @{}
    foreach ($v in @($bom.vulnerabilities)) {
        foreach ($a in @($v.affects)) {
            $ref = "$($a.ref)"
            if (-not $cveByRef.ContainsKey($ref)) { $cveByRef[$ref] = New-Object System.Collections.Generic.List[string] }
            if (-not $cveByRef[$ref].Contains("$($v.id)")) { $cveByRef[$ref].Add("$($v.id)") }
        }
    }
    foreach ($c in @($bom.components)) {
        $ref = "$($c.'bom-ref')"
        $managed = ''
        $mp = @($c.properties | Where-Object { $_.name -eq 'tcpk:managed' } | Select-Object -First 1)
        if ($mp) { $managed = if ("$($mp.value)" -eq 'True') { 'managed' } else { 'native' } }
        $sha = ''
        $h = @($c.hashes | Where-Object { $_.alg -eq 'SHA-256' } | Select-Object -First 1)
        if ($h) { $sha = "$($h.content)" }
        $cves = if ($cveByRef.ContainsKey($ref)) { ($cveByRef[$ref] -join ', ') } else { '' }
        $row = New-Object System.Windows.Forms.ListViewItem("$($c.name)")
        [void]$row.SubItems.Add("$($c.version)")
        [void]$row.SubItems.Add($managed)
        [void]$row.SubItems.Add("$($c.publisher)")
        [void]$row.SubItems.Add("$($c.purl)")
        [void]$row.SubItems.Add($sha)
        [void]$row.SubItems.Add($cves)
        if ($cves) { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
        $row.Tag = ("$($c.name) $($c.version) $managed $($c.publisher) $($c.purl) $sha $cves").ToLowerInvariant()
        [void]$script:SbomItems.Add($row)
    }
    Filter-Sbom
    [System.Windows.Forms.Application]::DoEvents()
}

# Live filter for the SBOM tab: re-show only cached rows matching the filter text.
function Filter-Sbom {
    if ($null -eq $script:SbomItems) { return }
    $q = "$($txtSbomFilter.Text)".ToLowerInvariant().Trim()
    $lvSbom.BeginUpdate()
    $lvSbom.Items.Clear()
    foreach ($it in $script:SbomItems) {
        if ($q -eq '' -or "$($it.Tag)".Contains($q)) { [void]$lvSbom.Items.Add($it) }
    }
    $lvSbom.EndUpdate()
}

function Populate-Hardening([string]$OutDir) {
    $script:HardItems = New-Object System.Collections.Generic.List[object]
    $lvHard.Items.Clear()
    $hf = Join-Path $OutDir 'hardening.json'
    if (-not (Test-Path $hf)) { return }
    $parsed = $null
    try { $parsed = ConvertFrom-Json (Get-Content -LiteralPath $hf -Raw) } catch { return }
    if ($null -eq $parsed) { return }
    foreach ($h in @($parsed)) {
        $row = New-Object System.Windows.Forms.ListViewItem("$($h.DLL)")
        [void]$row.SubItems.Add("$($h.Arch)")
        [void]$row.SubItems.Add("$($h.ASLR)")
        [void]$row.SubItems.Add("$($h.DEP)")
        [void]$row.SubItems.Add("$($h.CFG)")
        [void]$row.SubItems.Add("$($h.HighEntropyVA)")
        [void]$row.SubItems.Add("$($h.SafeSEH)")
        [void]$row.SubItems.Add("$($h.GS)")
        [void]$row.SubItems.Add("$($h.ForceIntegrity)")
        [void]$row.SubItems.Add("$($h.Status)")
        [void]$row.SubItems.Add("$($h.Missing)")
        switch ("$($h.Status)") {
            'WEAK'     { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
            'PARTIAL'  { $row.ForeColor = [System.Drawing.Color]::FromArgb(214, 137, 16) }
            'HARDENED' { $row.ForeColor = [System.Drawing.Color]::FromArgb(39, 174, 96) }
        }
        $row.Tag = ("$($h.DLL) $($h.Arch) $($h.Status) $($h.Missing)").ToLowerInvariant()
        [void]$script:HardItems.Add($row)
    }
    Filter-Hardening
    [System.Windows.Forms.Application]::DoEvents()
}

# Live filter for the DLL Mitigation Matrix tab.
function Filter-Hardening {
    if ($null -eq $script:HardItems) { return }
    $q = "$($txtHardFilter.Text)".ToLowerInvariant().Trim()
    $lvHard.BeginUpdate()
    $lvHard.Items.Clear()
    foreach ($it in $script:HardItems) {
        if ($q -eq '' -or "$($it.Tag)".Contains($q)) { [void]$lvHard.Items.Add($it) }
    }
    $lvHard.EndUpdate()
}

function Populate-Signing([string]$OutDir) {
    $script:SignItems = New-Object System.Collections.Generic.List[object]
    $lvSign.Items.Clear()
    $sf = Join-Path $OutDir 'signing.json'
    if (-not (Test-Path $sf)) { return }
    $parsed = $null
    try { $parsed = ConvertFrom-Json (Get-Content -LiteralPath $sf -Raw) } catch { return }
    if ($null -eq $parsed) { return }
    foreach ($s in @($parsed)) {
        $row = New-Object System.Windows.Forms.ListViewItem("$($s.DLL)")
        [void]$row.SubItems.Add("$($s.Signed)")
        [void]$row.SubItems.Add("$($s.Status)")
        [void]$row.SubItems.Add("$($s.Signer)")
        [void]$row.SubItems.Add("$($s.Algorithm)")
        [void]$row.SubItems.Add("$($s.ValidFrom)")
        [void]$row.SubItems.Add("$($s.Expires)")
        [void]$row.SubItems.Add("$($s.Type)")
        switch ("$($s.Status)") {
            'UNSIGNED'  { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
            'TAMPERED'  { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
            'UNTRUSTED' { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
            'EXPIRED'    { $row.ForeColor = [System.Drawing.Color]::FromArgb(192, 57, 43) }
            'EXPIRED-TS' { $row.ForeColor = [System.Drawing.Color]::FromArgb(214, 137, 16) }
            'SIGNED'    { $row.ForeColor = [System.Drawing.Color]::FromArgb(39, 174, 96) }
            'CATALOG'   { $row.ForeColor = [System.Drawing.Color]::FromArgb(39, 174, 96) }
        }
        $row.Tag = ("$($s.DLL) $($s.Signed) $($s.Status) $($s.Signer)").ToLowerInvariant()
        [void]$script:SignItems.Add($row)
    }
    Filter-Signing
    [System.Windows.Forms.Application]::DoEvents()
}

# Live filter for the DLL Signing tab.
function Filter-Signing {
    if ($null -eq $script:SignItems) { return }
    $q = "$($txtSignFilter.Text)".ToLowerInvariant().Trim()
    $lvSign.BeginUpdate()
    $lvSign.Items.Clear()
    foreach ($it in $script:SignItems) {
        if ($q -eq '' -or "$($it.Tag)".Contains($q)) { [void]$lvSign.Items.Add($it) }
    }
    $lvSign.EndUpdate()
}

# Authorization / gate toggle
$chkExpEnable.Add_CheckedChanged({
    if ($chkExpEnable.Checked) {
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Confirm you have WRITTEN AUTHORIZATION to test this target." + [Environment]::NewLine + [Environment]::NewLine +
            "Exploit modules generate PoC artifacts (Frida scripts, proxy DLLs, manifests) for verification. They do not autonomously attack. Proceed?",
            "TCPK -- authorization required", 'YesNo', 'Warning')
        if ($r -ne 'Yes') { $chkExpEnable.Checked = $false; return }
        try {
            Enable-TcpkExploit -Acknowledge | Out-Null
            $script:ExploitGateOn = $true
            $expBanner.BackColor = [System.Drawing.Color]::FromArgb(20, 50, 20)
            $lblExpStatus.Text = "Exploit gate: ON (authorized). Select an item and click Generate PoC + Verify."
        } catch {
            $chkExpEnable.Checked = $false
            $lblExpStatus.Text = "Enable failed: $($_.Exception.Message)"
        }
    } else {
        try { Disable-TcpkExploit | Out-Null } catch { }
        $script:ExploitGateOn = $false
        $expBanner.BackColor = [System.Drawing.Color]::FromArgb(60, 20, 20)
        $lblExpStatus.Text = "Exploit gate: OFF"
        $btnExpRun.Enabled = $false
    }
})

# Selection -> detail
$lvExp.Add_SelectedIndexChanged({
    if ($lvExp.SelectedIndices.Count -eq 0) { $btnExpRun.Enabled = $false; return }
    $it = $script:ExploitPlan[$lvExp.SelectedIndices[0]]
    $txtExpDetail.Clear()
    Write-Exp "$($it.Id)   [$($it.Severity)]   ($($it.Kind))`r`n" $script:ReconGreen
    Write-Exp ("-" * 72 + "`r`n") $script:ReconGray
    Write-Exp "Title     : " $script:ReconGray; Write-Exp "$($it.Title)`r`n"
    Write-Exp "Component : " $script:ReconGray; Write-Exp "$($it.Component)`r`n"
    Write-Exp "Area      : " $script:ReconGray; Write-Exp "$($it.Area)`r`n"
    Write-Exp "Status    : " $script:ReconGray; Write-Exp "$($it.Status)`r`n" $script:ReconOrange
    if ($it.Module) { Write-Exp "Module    : " $script:ReconGray; Write-Exp "$($it.Module)  (params: $($it.ParamSpec))`r`n" $script:ReconCyan }
    Write-Exp "`r`nTechnique:`r`n" $script:ReconCyan; Write-Exp "  $($it.Technique)`r`n"
    Write-Exp "`r`nWhat 'Generate PoC + Verify' does:`r`n" $script:ReconCyan; Write-Exp "  $($it.Verify)`r`n"
    if ($it.References) { Write-Exp "`r`nReferences:`r`n" $script:ReconCyan; foreach ($ref in $it.References) { Write-Exp "  $ref`r`n" $script:ReconGray } }
    $btnExpRun.Enabled = ($script:ExploitGateOn -and ($it.Module -or $it.Kind -eq 'CVE'))
})

# Run dispatcher (gated)
$btnExpRun.Add_Click({
    if ($lvExp.SelectedIndices.Count -eq 0) { return }
    $it = $script:ExploitPlan[$lvExp.SelectedIndices[0]]
    if (-not $script:ExploitGateOn) {
        [System.Windows.Forms.MessageBox]::Show("Tick the authorization box to enable exploit modules first.", "TCPK", 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $script:CurrentOutDir) {
        [System.Windows.Forms.MessageBox]::Show("Run an audit first.", "TCPK", 'OK', 'Information') | Out-Null
        return
    }
    $pocDir = Join-Path $script:CurrentOutDir 'poc'
    if (-not (Test-Path $pocDir)) { New-Item -ItemType Directory -Path $pocDir -Force | Out-Null }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Generate PoC / run verification for:" + [Environment]::NewLine + [Environment]::NewLine +
        "$($it.Id)  --  $($it.Title)" + [Environment]::NewLine +
        "Module: $(if ($it.Module) { $it.Module } else { 'version-presence verification' })" + [Environment]::NewLine +
        "Output: $pocDir" + [Environment]::NewLine + [Environment]::NewLine + "Proceed?",
        "TCPK -- confirm action", 'YesNo', 'Warning')
    if ($confirm -ne 'Yes') { return }

    Write-Exp "`r`n===== RUN =====`r`n" $script:ReconGreen
    $proc = if ($txtProc.Text) { $txtProc.Text } else { 'target' }
    $prod = if ($txtPkg.Text)  { $txtPkg.Text }  else { 'product' }
    try {
        switch ("$($it.Module)") {
            'New-TcpkFridaTlsBypass' {
                $o = Join-Path $pocDir 'tls-bypass.js'
                New-TcpkFridaTlsBypass -OutFile $o -TargetExe "$proc.exe" | Out-Null
                Write-Exp "PoC written: $o`r`n" $script:ReconCyan
                Write-Exp "Verify live: frida -f '$proc.exe' -l '$o'  (then watch if HTTPS via your MITM proxy succeeds)`r`n"
            }
            'New-TcpkPoisonedUpdateManifest' {
                $o = Join-Path $pocDir 'poisoned-update.json'
                New-TcpkPoisonedUpdateManifest -OutFile $o -ProductName $prod | Out-Null
                Write-Exp "PoC written: $o`r`n" $script:ReconCyan
                Write-Exp "Verify live: serve this from the update origin; if the client accepts it unsigned, the update flow is exploitable.`r`n"
            }
            'New-TcpkProxyDll' {
                New-TcpkProxyDll -Path $it.Component -OutDir $pocDir | Out-Null
                Write-Exp "Proxy-DLL scaffold written to: $pocDir`r`n" $script:ReconCyan
                Write-Exp "Verify live: compile + drop next to the app in the writable dir; if your marker fires, the hijack works.`r`n"
            }
            'New-TcpkComHijackTemplate' {
                $clsid = if ("$($it.Component)" -match '\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?') { $matches[0] }
                         elseif ("$($it.Title)" -match '\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?') { $matches[0] } else { $null }
                if ($clsid) {
                    New-TcpkComHijackTemplate -Clsid $clsid -OutDir $pocDir | Out-Null
                    Write-Exp "COM-hijack template written to: $pocDir (CLSID $clsid)`r`n" $script:ReconCyan
                } else {
                    Write-Exp "No CLSID found in this item. Run manually: New-TcpkComHijackTemplate -Clsid <guid> -OutDir '$pocDir'`r`n" $script:ReconOrange
                }
            }
            'Start-TcpkPipeMitm' {
                Write-Exp "Named-pipe relay is interactive (long-running). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Start-TcpkPipeMitm -LocalPipe <name> -UpstreamPipe <name> -LogFile '$pocDir\pipe.log'`r`n"
                Write-Exp "Run it in a console, point the client at <LocalPipe>, and inspect $pocDir\pipe.log.`r`n"
            }
            'Invoke-TcpkDpapiCrossUser' {
                $res = Invoke-TcpkDpapiCrossUser -Path $it.Component
                Write-Exp "DPAPI decrypt attempt finished. Result: $($res.Title)`r`n" $script:ReconCyan
            }
            'New-TcpkIlPatch' {
                Write-Exp "IL binary patching (requires target DLL path + method). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  New-TcpkIlPatch -DllPath '<assembly.dll>' -TypeName '<Namespace.Class>' -MethodName '<Check>' -Mode ReturnTrue -OutDir '$pocDir'`r`n"
                Write-Exp "Modes: ReturnTrue, ReturnFalse, ReturnNull, Nop, FlipBranch, StripSn`r`n"
                Write-Exp "Produces a patched copy; swap it in to verify the client-side gate is bypassable.`r`n"
            }
            'Invoke-TcpkMemoryFlagFlip' {
                Write-Exp "Memory flag flip (interactive -- must target a running process). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Invoke-TcpkMemoryFlagFlip -ProcessName '$prod' -Pattern '<hex-bytes>' -NewBytesHex '01'`r`n"
                Write-Exp "Dry-run first (no -Apply), then -Apply to patch live memory.`r`n"
            }
            'Invoke-TcpkGuiUnlock' {
                Write-Exp "GUI unlock (interactive -- must target a running process). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Invoke-TcpkGuiUnlock -ProcessName '$prod'`r`n"
                Write-Exp "Dry-run first (no -Apply), then -Apply to enable disabled/hidden controls.`r`n"
            }
            'Get-TcpkStoredCredentials' {
                $res = Get-TcpkStoredCredentials -Confirm -Filter $prod
                $count = @($res).Count
                Write-Exp "Credential Manager extraction finished. $count finding(s) returned.`r`n" $script:ReconCyan
                if ($count -gt 0) { Write-Exp "Check the Findings tab for recovered credentials.`r`n" }
            }
            'Test-TcpkCredentialLiveness' {
                Write-Exp "Credential liveness test (connects to a live service). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Test-TcpkCredentialLiveness -Target '<host:port>' -Protocol http -ConfirmActive -Username '<user>' -Password '<pass>'`r`n"
                Write-Exp "Protocols: http, sql, ftp. Use -BearerToken for token-based auth.`r`n"
            }
            'Invoke-TcpkHookBypass' {
                Write-Exp "Frida hook bypass (launches target with a hook). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Invoke-TcpkHookBypass -Target '<app.exe>' -Function '<FuncName>' -ConfirmDynamic`r`n"
                Write-Exp "Optional: -ReturnValue 1, -Module '<dll>', -DurationSec 20`r`n"
            }
            'Invoke-TcpkInputFuzz' {
                Write-Exp "Input fuzzing (launches target repeatedly). Ready command:`r`n" $script:ReconOrange
                Write-Exp "  Invoke-TcpkInputFuzz -TargetExe '<app.exe>' -SeedFile '<sample.ext>' -OutDir '$pocDir'`r`n"
                Write-Exp "Optional: -ArgTemplate '{FUZZ}' -Iterations 25 -TimeoutSec 10`r`n"
            }
            'New-TcpkRegistryHijackTemplate' {
                $exeName = if ("$($it.Component)" -match '[^\\/:]+\.exe') { $matches[0] }
                           elseif ("$($it.Title)" -match ':\s*(\S+\.exe)') { $matches[1] }
                           elseif ("$($it.Title)" -match '(\S+)') { $matches[1] } else { 'target.exe' }
                $mode = if ("$($it.Id)" -match 'ifeo') { 'Ifeo' } else { 'RunKey' }
                New-TcpkRegistryHijackTemplate -Mode $mode -TargetExe $exeName -OutDir $pocDir | Out-Null
                Write-Exp "Registry hijack template ($mode) written to: $pocDir`r`n" $script:ReconCyan
                Write-Exp "Import the .reg on the authorized target to verify the persistence vector.`r`n"
            }
            default {
                # CVE / version-presence verification (no auto-execution)
                Write-Exp "Version-presence verification`r`n" $script:ReconCyan
                Write-Exp "  Component: $($it.Component)`r`n"
                Write-Exp "  Status   : $($it.Status)`r`n" $script:ReconOrange
                Write-Exp "`r`nExploitation guidance (manual / advisory PoC):`r`n" $script:ReconCyan
                Write-Exp "  $($it.Technique)`r`n"
                if ($it.References) { Write-Exp "`r`nAdvisory:`r`n" $script:ReconCyan; foreach ($ref in $it.References) { Write-Exp "  $ref`r`n" $script:ReconGray } }
            }
        }
        Write-Exp "===== DONE =====`r`n" $script:ReconGreen
        $lblExpStatus.Text = "Last action: $($it.Id)  ->  $pocDir"
    } catch {
        Write-Exp "FAILED: $($_.Exception.Message)`r`n" $script:ReconRed
    }
    $txtExpDetail.SelectionStart = $txtExpDetail.TextLength
    $txtExpDetail.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
})

# --- Logs / Runtime tab population ---
function Write-Log2([string]$Text, [System.Drawing.Color]$Color = $script:ReconWhite) {
    $txtLogs.SelectionStart = $txtLogs.TextLength
    $txtLogs.SelectionLength = 0
    $txtLogs.SelectionColor = $Color
    $txtLogs.AppendText($Text)
}

function Populate-Logs([string]$OutDir) {
    $txtLogs.Clear()
    $lf = Join-Path $OutDir 'run.jsonl'
    if (-not (Test-Path $lf)) { $txtLogs.Text = "No run.jsonl produced for this audit."; return }

    # Read JSONL line-by-line (argument form per line avoids the PS 5.1 array-collapse quirk)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in (Get-Content -LiteralPath $lf)) {
        if (-not $line.Trim()) { continue }
        try { $entries.Add((ConvertFrom-Json $line)) } catch { }
    }
    if ($entries.Count -eq 0) { $txtLogs.Text = "run.jsonl was empty."; return }

    $colors = @{
        DEBUG   = $script:ReconGray
        INFO    = $script:ReconWhite
        SUCCESS = $script:ReconGreen
        WARN    = $script:ReconOrange
        ERROR   = $script:ReconRed
    }

    $checks = @($entries | Where-Object { $_.durationMs -ge 0 -and $_.component -notin 'audit','summary','report','triage' })
    $errs   = @($entries | Where-Object { $_.level -eq 'ERROR' })
    $withFindings = @($checks | Where-Object { $_.level -eq 'SUCCESS' })
    $empty  = @($checks | Where-Object { $_.level -eq 'INFO' })
    $auditDone = $entries | Where-Object { $_.component -eq 'audit' -and $_.message -like 'Audit complete*' } | Select-Object -First 1
    $totalMs = if ($auditDone) { [int]$auditDone.durationMs } else { ([int](($checks | Measure-Object durationMs -Sum).Sum)) }

    # ---- runtime analysis summary ----
    Write-Log2 "RUNTIME ANALYSIS`r`n" $script:ReconGreen
    Write-Log2 ("=" * 72 + "`r`n") $script:ReconGray
    Write-Log2 "  Total audit time : " $script:ReconGray; Write-Log2 ("{0}s  ({1} ms)`r`n" -f [int]($totalMs/1000), $totalMs)
    Write-Log2 "  Checks executed  : " $script:ReconGray; Write-Log2 ("{0}`r`n" -f $checks.Count)
    Write-Log2 "    with findings  : " $script:ReconGray; Write-Log2 ("{0}`r`n" -f $withFindings.Count) $script:ReconGreen
    Write-Log2 "    empty (0)      : " $script:ReconGray; Write-Log2 ("{0}`r`n" -f $empty.Count)
    Write-Log2 "    errors         : " $script:ReconGray; Write-Log2 ("{0}`r`n" -f $errs.Count) $(if ($errs.Count) { $script:ReconRed } else { $script:ReconGreen })

    Write-Log2 "`r`n  Slowest checks:`r`n" $script:ReconCyan
    foreach ($c in ($checks | Sort-Object durationMs -Descending | Select-Object -First 10)) {
        Write-Log2 ("    {0,7} ms   " -f $c.durationMs) $script:ReconOrange
        Write-Log2 ("{0}`r`n" -f $c.component) $script:ReconWhite
    }
    if ($errs.Count) {
        Write-Log2 "`r`n  Errors:`r`n" $script:ReconRed
        foreach ($e in $errs) { Write-Log2 ("    [{0}] {1}: {2}`r`n" -f $e.time, $e.component, $e.message) $script:ReconRed }
    }

    # ---- full verbose trace ----
    Write-Log2 ("`r`n" + ("=" * 72) + "`r`n") $script:ReconGray
    Write-Log2 "FULL TRACE (verbose, chronological)`r`n" $script:ReconGreen
    Write-Log2 ("=" * 72 + "`r`n") $script:ReconGray
    foreach ($e in $entries) {
        $col = if ($colors.ContainsKey("$($e.level)")) { $colors["$($e.level)"] } else { $script:ReconWhite }
        $dur = if ($e.durationMs -ge 0) { " ({0}ms)" -f $e.durationMs } else { '' }
        Write-Log2 ("{0}  " -f $e.time) $script:ReconGray
        Write-Log2 ("{0,-7} " -f $e.level) $col
        Write-Log2 ("{0,-22} " -f $e.component) $script:ReconCyan
        Write-Log2 ("{0}{1}`r`n" -f $e.message, $dur) $script:ReconWhite
    }
    $txtLogs.SelectionStart = 0
    $txtLogs.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# --- Appearance: font + theme ---
$script:DarkTheme  = $true
$script:UiFontName = 'Consolas'
$script:UiFontSize = 10

# Modern flat-UI accent + owner-drawn tab colours
$script:Accent     = [System.Drawing.Color]::FromArgb(45, 212, 191)   # teal accent
$script:AccentDim  = [System.Drawing.Color]::FromArgb(58, 150, 132)
$script:AccentText = [System.Drawing.Color]::FromArgb(18, 20, 22)      # dark text on accent
$script:TabBg      = [System.Drawing.Color]::FromArgb(45, 45, 48)
$script:TabFg      = [System.Drawing.Color]::FromArgb(204, 204, 204)
$script:TabStripBg = [System.Drawing.Color]::FromArgb(37, 37, 38)

function Style-FlatBtn($b, [System.Drawing.Color]$bg, [System.Drawing.Color]$fg, [System.Drawing.Color]$border) {
    if (-not $b) { return }
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.BorderColor = $border
    $b.BackColor = $bg
    $b.ForeColor = $fg
    $hover = [System.Drawing.Color]::FromArgb([Math]::Min(255, $bg.R + 22), [Math]::Min(255, $bg.G + 22), [Math]::Min(255, $bg.B + 22))
    $b.FlatAppearance.MouseOverBackColor = $hover
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
}

# WinForms greys a DISABLED button's text to a near-black tone derived from its
# BackColor -- on a dark theme that makes the label invisible (e.g. "Open HTML
# report" / "Pause" before they're enabled). We repaint disabled buttons ourselves
# with a legible muted label so the action is always readable. Wire ONCE per button.
$script:ReadableDisabledWired = $false
function Enable-ReadableDisabled($b) {
    if (-not $b) { return }
    $b.Add_EnabledChanged({ param($s, $e) $s.Invalidate() })
    $b.Add_Paint({
        param($s, $e)
        if ($s.Enabled) { return }   # enabled buttons paint normally (good contrast)
        $g = $e.Graphics
        $rect = $s.ClientRectangle
        # erase the faint system-greyed text the base painter already drew
        $bgBrush = New-Object System.Drawing.SolidBrush($s.BackColor)
        $g.FillRectangle($bgBrush, $rect); $bgBrush.Dispose()
        # dim 1px border so the (disabled) button still reads as a button
        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(96, 96, 100), 1)
        $g.DrawRectangle($pen, 0, 0, $rect.Width - 1, $rect.Height - 1); $pen.Dispose()
        # legible muted label
        $flags = [System.Windows.Forms.TextFormatFlags]::HorizontalCenter `
            -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter `
            -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
        [System.Windows.Forms.TextRenderer]::DrawText($g, $s.Text, $s.Font, $rect, [System.Drawing.Color]::FromArgb(170, 170, 174), $flags)
    })
}
function Wire-ReadableDisabledButtons {
    if ($script:ReadableDisabledWired) { return }
    foreach ($b in @($btnRun, $btnPause, $btnOpenHtml, $btnOpenExcel, $btnOpenMarkdown, $btnOpenFolder, $btnTestAi, $btnBrowse, $btnAutoDetect, $btnExpRun)) {
        Enable-ReadableDisabled $b
    }
    $script:ReadableDisabledWired = $true
}

$script:TabDrawAttached = $false
function Apply-ModernStyle {
    $pal = Get-UiPalette $script:DarkTheme

    # Standard tabs: the OS always renders the labels (visible names are
    # non-negotiable). Owner-draw proved unreliable for text here, so we keep
    # the rest of the modern styling (flat buttons/accent) but normal tabs.
    $tabs.SizeMode = 'Normal'
    $tabs.DrawMode = 'Normal'
    if ($false) {
        $tabs.Add_DrawItem({
            param($s, $e)
            try {
                # Fallback literal colours so a null $script var can never blank the text
                $cAccent     = if ($script:Accent)     { $script:Accent }     else { [System.Drawing.Color]::FromArgb(78,201,176) }
                $cAccentText = if ($script:AccentText) { $script:AccentText } else { [System.Drawing.Color]::FromArgb(18,20,22) }
                $cAccentDim  = if ($script:AccentDim)  { $script:AccentDim }  else { [System.Drawing.Color]::FromArgb(58,150,132) }
                $cTabBg      = if ($script:TabBg)      { $script:TabBg }      else { [System.Drawing.Color]::FromArgb(45,45,48) }
                $cTabFg      = if ($script:TabFg)      { $script:TabFg }      else { [System.Drawing.Color]::FromArgb(220,220,220) }
                $cStripBg    = if ($script:TabStripBg) { $script:TabStripBg } else { [System.Drawing.Color]::FromArgb(37,37,38) }

                $tp  = $s.TabPages[$e.Index]
                $sel = ($e.Index -eq $s.SelectedIndex)
                $bg  = if ($sel) { $cAccent }     else { $cTabBg }
                $fg  = if ($sel) { $cAccentText } else { $cTabFg }
                $r   = $e.Bounds
                $g   = $e.Graphics
                $sbStrip = New-Object System.Drawing.SolidBrush($cStripBg)
                $g.FillRectangle($sbStrip, $r); $sbStrip.Dispose()
                $pad = New-Object System.Drawing.Rectangle($r.X + 2, $r.Y + 3, $r.Width - 4, $r.Height - 5)
                $sbBg = New-Object System.Drawing.SolidBrush($bg)
                $g.FillRectangle($sbBg, $pad); $sbBg.Dispose()
                if ($sel) {
                    $sbBar = New-Object System.Drawing.SolidBrush($cAccentDim)
                    $g.FillRectangle($sbBar, (New-Object System.Drawing.Rectangle($pad.X, $pad.Bottom - 3, $pad.Width, 3))); $sbBar.Dispose()
                }
                $flags = [System.Windows.Forms.TextFormatFlags]::HorizontalCenter `
                    -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter `
                    -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
                [System.Windows.Forms.TextRenderer]::DrawText($g, $tp.Text.Trim(), $s.Font, $pad, $fg, $flags)
            } catch { }
        })
        $script:TabDrawAttached = $true
    }

    # --- flat inputs ---
    foreach ($tb in @($txtTarget, $txtPkg, $txtProc, $txtAiKey)) { if ($tb) { $tb.BorderStyle = 'FixedSingle' } }
    foreach ($cb in @($cmbProfile, $cmbAi, $cmbFont, $cmbSize, $txtAiModel)) { if ($cb) { $cb.FlatStyle = 'Flat' } }

    # --- flat buttons ---
    $btnRun.Tag = 'keep'
    Style-FlatBtn $btnRun $script:Accent $script:AccentText $script:Accent
    $btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    foreach ($b in @($btnBrowse, $btnAutoDetect, $btnTestAi, $btnTheme, $btnPause, $btnOpenHtml, $btnOpenExcel, $btnOpenMarkdown, $btnOpenFolder)) {
        Style-FlatBtn $b $pal.PanelBg $pal.LabelFg $script:Accent
    }
    if ($btnExpRun) {
        $btnExpRun.Tag = 'keep'
        Style-FlatBtn $btnExpRun ([System.Drawing.Color]::FromArgb(155,0,0)) ([System.Drawing.Color]::White) ([System.Drawing.Color]::FromArgb(200,70,70))
    }
}

function Apply-UiFont {
    $name = "$($cmbFont.SelectedItem)"; if (-not $name) { $name = $script:DefaultFontName }
    if (-not $name) { $name = 'Cascadia Mono' }
    $size = try { [single]$cmbSize.SelectedItem } catch { 10 }
    if ($size -lt 7) { $size = 10 }
    $script:UiFontName = $name; $script:UiFontSize = $size
    try {
        $f = New-Object System.Drawing.Font($name, $size)
        # Apply to every control in the tree -- "everywhere in the tool".
        # $form.Font drives inherited controls; explicit-font controls are updated below.
        $form.Font = $f
        $queue = [System.Collections.Generic.Queue[System.Windows.Forms.Control]]::new()
        $queue.Enqueue($form)
        while ($queue.Count -gt 0) {
            $ctl = $queue.Dequeue()
            $ctl.Font = $f
            foreach ($child in $ctl.Controls) { $queue.Enqueue($child) }
        }
    } catch { }
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-UiPalette([bool]$dark) {
    if ($dark) {
        # Layered dark, blue-biased (deeper + more considered than a flat grey). Distinct
        # layers: window ground (#0C0F15) < panel (#131821) < input fields (#1C2330, lifted
        # so they stand out) ; text/log areas are deepest (#0D1016) for readability. Near-
        # white text with a faint blue cast reads as intentional, not inherited grey.
        @{ FormBg =[System.Drawing.Color]::FromArgb(12,15,21);   PanelBg=[System.Drawing.Color]::FromArgb(19,24,33)
           InputBg=[System.Drawing.Color]::FromArgb(28,35,48);   TextBg =[System.Drawing.Color]::FromArgb(13,16,22)
           TextFg =[System.Drawing.Color]::FromArgb(230,234,241)
           ListBg =[System.Drawing.Color]::FromArgb(18,23,31);   ListFg =[System.Drawing.Color]::FromArgb(230,234,241)
           LabelFg=[System.Drawing.Color]::FromArgb(233,237,243) }
    } else {
        # Light: white cards raised on a soft grey-blue ground (modern, not flat).
        @{ FormBg =[System.Drawing.Color]::FromArgb(240,242,246); PanelBg=[System.Drawing.Color]::White
           InputBg=[System.Drawing.Color]::White;                 TextBg =[System.Drawing.Color]::White
           TextFg =[System.Drawing.Color]::FromArgb(26,32,41)
           ListBg =[System.Drawing.Color]::White;                 ListFg =[System.Drawing.Color]::FromArgb(26,32,41)
           LabelFg=[System.Drawing.Color]::FromArgb(30,36,45) }
    }
}

function Set-CtlThemeRecursive($ctl, $pal) {
    foreach ($c in $ctl.Controls) {
        if ("$($c.Tag)" -eq 'keep') { continue }
        switch ($c.GetType().Name) {
            'Panel'          { $c.BackColor = $pal.PanelBg }
            'SplitContainer' { $c.BackColor = $pal.PanelBg }
            'SplitterPanel'  { $c.BackColor = $pal.PanelBg }
            'TabControl'     { $c.BackColor = $pal.PanelBg }
            'TabPage'        { $c.BackColor = $pal.TextBg }
            'Label'          { $c.ForeColor = $pal.LabelFg; $c.BackColor = $ctl.BackColor }
            'CheckBox'       { $c.ForeColor = $pal.LabelFg; $c.BackColor = $ctl.BackColor }
            'TextBox'          { $c.BackColor = $pal.InputBg; $c.ForeColor = $pal.TextFg }
            'RichTextBox'      { $c.BackColor = $pal.TextBg;  $c.ForeColor = $pal.TextFg }
            'ListView'         { $c.BackColor = $pal.ListBg;  $c.ForeColor = $pal.ListFg }
            'ListBox'          { $c.BackColor = $pal.ListBg;  $c.ForeColor = $pal.ListFg }
            'ComboBox'         { $c.BackColor = $pal.InputBg; $c.ForeColor = $pal.TextFg }
            'FlowLayoutPanel'  { $c.BackColor = $pal.PanelBg }
            'TableLayoutPanel' { $c.BackColor = $pal.PanelBg }
            'Button'         { $c.BackColor = $pal.PanelBg; $c.ForeColor = $pal.LabelFg; try { $c.FlatAppearance.BorderColor = $script:Accent } catch { } }
        }
        if ($c.Controls.Count -gt 0) { Set-CtlThemeRecursive $c $pal }
    }
}

function Update-SevColours([bool]$dark) {
    if ($dark) {
        # bright, readable on the dark (#2b2b2b) background
        $script:SevColour = @{
            'CRITICAL' = [System.Drawing.Color]::FromArgb(255, 85, 85)    # bright red
            'HIGH'     = [System.Drawing.Color]::FromArgb(255, 138, 101)  # orange-red
            'MEDIUM'   = [System.Drawing.Color]::FromArgb(255, 193, 110)  # amber
            'LOW'      = [System.Drawing.Color]::FromArgb(126, 217, 140)  # green
            'INFO'     = [System.Drawing.Color]::FromArgb(176, 184, 194)  # light grey
        }
    } else {
        # deeper tones, readable on white
        $script:SevColour = @{
            'CRITICAL' = [System.Drawing.Color]::FromArgb(155, 0, 0)
            'HIGH'     = [System.Drawing.Color]::FromArgb(192, 57, 43)
            'MEDIUM'   = [System.Drawing.Color]::FromArgb(176, 110, 0)
            'LOW'      = [System.Drawing.Color]::FromArgb(17, 122, 101)
            'INFO'     = [System.Drawing.Color]::FromArgb(80, 92, 104)
        }
    }
}

function Update-ListSeverityColours {
    foreach ($it in $lvFindings.Items) {
        $sev = "$($it.Text)"; if ($script:SevColour.ContainsKey($sev)) { $it.ForeColor = $script:SevColour[$sev] }
    }
    foreach ($it in $lvExp.Items) {
        if ($it.SubItems.Count -gt 1) { $sev = "$($it.SubItems[1].Text)"; if ($script:SevColour.ContainsKey($sev)) { $it.ForeColor = $script:SevColour[$sev] } }
    }
}

# Append a coloured run to a RichTextBox (used to build the summary + top-issues panels).
function Add-DashRun($rtb, [string]$text, $color, [bool]$bold) {
    $rtb.SelectionStart  = $rtb.TextLength
    $rtb.SelectionLength = 0
    if ($color) { $rtb.SelectionColor = $color }
    $style = if ($bold) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular }
    $rtb.SelectionFont = New-Object System.Drawing.Font($rtb.Font.FontFamily, $rtb.Font.Size, $style)
    $rtb.AppendText($text)
}

function Update-Dashboard {
    # Recompute the Dashboard + restyle for the current theme. Prefers the enriched
    # $script:LastFindings (carries CvssScore/CvssRating/File/Confidence sub-types); falls
    # back to the live $lvFindings table for counts before any audit has stashed findings.
    # Safe in the empty state and before/after a theme toggle.
    if (-not $script:DashCountLbl) { return }
    $pal  = Get-UiPalette $script:DarkTheme
    $dimC = [System.Drawing.Color]::FromArgb(140, 145, 150)
    $valC = $pal.LabelFg
    $sevRank = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }

    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
    $confirmed = 0; $proven = 0; $leads = 0; $fp = 0
    $rules = @{}
    $maxScore = $null
    $rows = New-Object System.Collections.Generic.List[object]

    # NOTE: never wrap $script:LastFindings with @() -- if it is a generic List, @(list)
    # throws "Argument types do not match" on PS 5.1. Enumerate it bare instead.
    $useLf = $false
    if ($script:LastFindings) { foreach ($x in $script:LastFindings) { $useLf = $true; break } }
    if ($useLf) {
        foreach ($f in $script:LastFindings) {
            $sev = "$($f.Severity)".ToUpper()
            if ($counts.ContainsKey($sev)) { $counts[$sev]++ }
            $conf = "$($f.Confidence)"
            if     ($conf -match '^Confirmed') { $confirmed++; $proven++ }
            elseif ($conf -match '^Likely-FP') { $fp++ }
            else   { $leads++ }
            $rid = "$($f.RuleId)"; if ($rid) { $rules[$rid] = $true }
            $sc = $null; try { if ($null -ne $f.CvssScore -and "$($f.CvssScore)" -ne '') { $sc = [double]$f.CvssScore } } catch { }
            if ($null -ne $sc -and ($null -eq $maxScore -or $sc -gt $maxScore)) { $maxScore = $sc }
            $loc = if ($f.File) { Split-Path "$($f.File)" -Leaf } elseif ($f.Module) { "$($f.Module)" } else { '-' }
            $rows.Add([pscustomobject]@{ Sev = $sev; Rule = $rid; Finding = "$($f.Title)"; Conf = $conf; Cvss = $sc; Loc = $loc })
        }
        $total = $rows.Count
    } else {
        foreach ($it in $lvFindings.Items) {
            $s = "$($it.Text)"; if ($counts.ContainsKey($s)) { $counts[$s]++ }
            $c1 = if ($it.SubItems.Count -gt 1) { "$($it.SubItems[1].Text)" } else { '' }
            if ($c1 -match '^Confirmed') { $confirmed++ }
        }
        $total = $lvFindings.Items.Count
    }
    $script:DashAssure = @{ Proven = $proven; Leads = $leads; LikelyFp = $fp }
    $script:DashCounts = $counts

    # --- KPI cards (Tag='keep' -> restyle name caption here so it stays legible in light) ---
    $nameFg = if ($script:DarkTheme) { [System.Drawing.Color]::FromArgb(176, 184, 194) } else { [System.Drawing.Color]::FromArgb(90, 96, 104) }
    foreach ($card in $script:DashCardPanels) {
        $card.BackColor = $pal.PanelBg
        if ($card.SevNameLbl) { $card.SevNameLbl.BackColor = $pal.PanelBg; $card.SevNameLbl.ForeColor = $nameFg }
        if ($card.CountLbl)   { $card.CountLbl.BackColor   = $pal.PanelBg }
    }
    foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
        if (-not $script:DashCountLbl.ContainsKey($sev)) { continue }
        $lbl = $script:DashCountLbl[$sev]
        $n   = [int]$counts[$sev]
        $lbl.Text = "$n"
        $sc  = if ($script:SevColour -and $script:SevColour.ContainsKey($sev)) { $script:SevColour[$sev] } else { $valC }
        if ($n -eq 0) {
            $lbl.ForeColor = [System.Drawing.Color]::FromArgb(92, 98, 106)
            $lbl.Parent.SevStripe.BackColor = [System.Drawing.Color]::FromArgb(58, 64, 72)
        } else {
            $lbl.ForeColor = $sc
            $lbl.Parent.SevStripe.BackColor = $sc
        }
    }

    # --- MAX CVSS tile ---
    if ($script:DashMaxCvssLbl) {
        if ($null -ne $maxScore) {
            $script:DashMaxCvssLbl.Text = ('{0:0.0}' -f $maxScore)
            $script:DashMaxCvssLbl.ForeColor = if ($script:Accent) { $script:Accent } else { [System.Drawing.Color]::FromArgb(45, 212, 191) }
        } else {
            $script:DashMaxCvssLbl.Text = '-'
            $script:DashMaxCvssLbl.ForeColor = [System.Drawing.Color]::FromArgb(92, 98, 106)
        }
    }

    # --- owner-drawn panels ---
    if ($dashSevBars)   { $dashSevBars.BackColor   = $pal.TextBg; $dashSevBars.Invalidate() }
    if ($dashAssurance) { $dashAssurance.BackColor = $pal.TextBg; $dashAssurance.Invalidate() }

    # --- header subtitle ---
    $tgt = "$($txtTarget.Text)"; if (-not $tgt) { $tgt = "$($txtPkg.Text)" }; if (-not $tgt) { $tgt = '(not set)' }
    if ($total -eq 0) {
        $dashSub.Text = 'No audit run yet.'
    } else {
        $maxTxt = if ($null -ne $maxScore) { ('{0:0.0}' -f $maxScore) } else { '-' }
        $dashSub.Text = ("{0}  --  {1} findings  --  {2} confirmed  --  {3} distinct rules  --  max CVSS {4}" -f (Split-Path $tgt -Leaf), $total, $confirmed, $rules.Count, $maxTxt)
    }

    # --- Top findings table ---
    $lvDashTop.BeginUpdate()
    $lvDashTop.Items.Clear()
    $lvDashTop.BackColor = $pal.TextBg
    if ($rows.Count) {
        $sorted = @($rows | Sort-Object @{ E = { $sevRank["$($_.Sev)"] } }, @{ E = { if ($null -ne $_.Cvss) { -1 * [double]$_.Cvss } else { 0 } } })
        $show = [Math]::Min(14, $sorted.Count)
        for ($i = 0; $i -lt $show; $i++) {
            $r  = $sorted[$i]
            $it = New-Object System.Windows.Forms.ListViewItem("$($r.Sev)")
            $it.Tag = "$($r.Sev)"
            [void]$it.SubItems.Add("$($r.Rule)")
            [void]$it.SubItems.Add("$($r.Finding)")
            [void]$it.SubItems.Add("$($r.Conf)")
            [void]$it.SubItems.Add($(if ($null -ne $r.Cvss) { ('{0:0.0}' -f $r.Cvss) } else { '-' }))
            [void]$it.SubItems.Add("$($r.Loc)")
            [void]$lvDashTop.Items.Add($it)
        }
    }
    $lvDashTop.EndUpdate()

    # --- panels + labels follow the theme (uniform deep ground) ---
    foreach ($p in @($dashTopBox, $dashMid, $dashSevBox, $dashAssBox, $dashHeader, $dashCards)) {
        if ($p) { $p.BackColor = $pal.TextBg }
    }
    foreach ($l in @($dashTopTitle, $dashSevTitle, $dashAssTitle, $dashTitle)) {
        if ($l) { $l.BackColor = $pal.TextBg; $l.ForeColor = $pal.LabelFg }
    }
    $dashSub.BackColor = $pal.TextBg; $dashSub.ForeColor = $dimC
}

function Apply-UiTheme {
    $pal = Get-UiPalette $script:DarkTheme
    Update-SevColours $script:DarkTheme
    $form.BackColor = $pal.FormBg
    Set-CtlThemeRecursive $form $pal
    Update-ListSeverityColours

    # Owner-drawn tab colours follow the theme; accent stays constant
    $script:TabBg      = $pal.PanelBg
    $script:TabFg      = $pal.LabelFg
    $script:TabStripBg = $pal.FormBg
    if ($tabs) { try { $tabs.BackColor = $pal.FormBg; $tabs.Invalidate() } catch { } }
    # Re-assert accent on the primary action buttons (they carry the accent in both themes)
    if ($btnRun)    { try { Style-FlatBtn $btnRun $script:Accent $script:AccentText $script:Accent } catch { } }

    # Verbose colour palette for the recon / logs / exploit text panels
    if ($script:DarkTheme) {
        $script:ReconCyan=[System.Drawing.Color]::FromArgb(104,196,224); $script:ReconGray=[System.Drawing.Color]::FromArgb(140,145,150)
        $script:ReconWhite=[System.Drawing.Color]::FromArgb(187,187,187); $script:ReconGreen=[System.Drawing.Color]::FromArgb(152,195,121)
        $script:ReconOrange=[System.Drawing.Color]::FromArgb(209,154,102); $script:ReconRed=[System.Drawing.Color]::FromArgb(224,108,117)
    } else {
        $script:ReconCyan=[System.Drawing.Color]::FromArgb(0,95,135); $script:ReconGray=[System.Drawing.Color]::FromArgb(110,110,110)
        $script:ReconWhite=[System.Drawing.Color]::FromArgb(30,30,30); $script:ReconGreen=[System.Drawing.Color]::FromArgb(20,120,40)
        $script:ReconOrange=[System.Drawing.Color]::FromArgb(170,90,0); $script:ReconRed=[System.Drawing.Color]::FromArgb(185,20,40)
    }
    # Re-render the colour-coded panels with the new palette if data exists
    if ($script:CurrentOutDir) {
        try { Render-Recon $script:CurrentOutDir } catch { }
        try { Populate-Logs $script:CurrentOutDir } catch { }
    }
    # Keep the disclaimer strip red regardless of theme
    if ($disclaimerStrip) { $disclaimerStrip.BackColor = [System.Drawing.Color]::FromArgb(120,0,0); $disclaimerStrip.ForeColor = [System.Drawing.Color]::White }
    try { Update-Dashboard } catch { }
    [System.Windows.Forms.Application]::DoEvents()
}

# --- Test AI button ---
$btnTestAi.Add_Click({
    $sel = $cmbAi.SelectedItem
    $preset = $script:AiPresets[$sel]
    if ($preset.needsKey -and -not $txtAiKey.Text) {
        $lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(192,57,43)
        $lblAiStatus.Text = "Enter an API key for $sel first."
        return
    }
    $lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(86,101,115)
    $lblAiStatus.Text = "Testing $sel ..."
    [System.Windows.Forms.Application]::DoEvents()
    [void](Set-AiConfigFromGui)
    # Pull the LIVE model list for this key and fill the dropdown (always the latest).
    $modelCount = 0
    try {
        $models = @(Get-TcpkLlmModels)
        if ($models.Count) {
            $modelCount = $models.Count
            $cur = $txtAiModel.Text
            $txtAiModel.Items.Clear()
            foreach ($m in $models) { [void]$txtAiModel.Items.Add($m) }
            $txtAiModel.Text = $cur   # keep current selection; user can drop down to pick another
        }
    } catch { }
    try {
        $r = Test-TcpkLlm
        $modelNote = if ($modelCount) { "  ($modelCount models in dropdown)" } else { '' }
        if ($r.ModelResponds) {
            $lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(17,122,101)
            $lblAiStatus.Text = "OK: $($r.Provider)/$($r.Model) responded.$modelNote"
        } else {
            $lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(192,57,43)
            $lblAiStatus.Text = "Reachable=$($r.Reachable), model didn't reply -- pick a valid model from the dropdown.$modelNote"
        }
    } catch {
        $lblAiStatus.ForeColor = [System.Drawing.Color]::FromArgb(192,57,43)
        $lblAiStatus.Text = "FAILED: $($_.Exception.Message.Split([char]10)[0])"
    }
})

# --- Browse: ask up front whether the target is a folder or an MSIX file ---
$btnBrowse.Add_Click({
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "Is the target an INSTALL FOLDER?" + [Environment]::NewLine + [Environment]::NewLine +
        "Yes  = pick a folder (most installed apps, e.g. C:\Program Files\...)" + [Environment]::NewLine +
        "No   = pick a single .msix / .appx file" + [Environment]::NewLine +
        "Cancel = do nothing",
        "TCPK -- choose target type",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
        # Folder picker
        $dlg2 = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg2.Description = "Pick the install folder to audit"
        $dlg2.ShowNewFolderButton = $false
        if ($dlg2.ShowDialog() -eq 'OK') {
            $txtTarget.Text = $dlg2.SelectedPath
        }
    }
    elseif ($choice -eq [System.Windows.Forms.DialogResult]::No) {
        # File picker
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = "MSIX/AppX file (*.msix;*.appx;*.msixbundle)|*.msix;*.appx;*.msixbundle|All files (*.*)|*.*"
        $dlg.Title = "Pick the .msix / .appx file"
        if ($dlg.ShowDialog() -eq 'OK') {
            $txtTarget.Text = $dlg.FileName
        }
    }
    # Cancel: do nothing
})

# --- Auto-detect: figure out PackageName / family / process from the target path ---
$btnAutoDetect.Add_Click({
    $path = $txtTarget.Text
    if (-not $path) {
        [System.Windows.Forms.MessageBox]::Show("Enter or browse to a target first.", "TCPK", 'OK', 'Information') | Out-Null
        return
    }

    # App-kind identity (what kind of application is this) -- shown BEFORE the audit runs.
    $lblIdent.Text = "App identity: identifying..."
    $lblIdent.Refresh()
    try {
        $ident = Get-TcpkAppIdentity -Path $path
        $lblIdent.Text = "App identity: $($ident.Summary)"
        $lblIdent.ForeColor = [System.Drawing.Color]::FromArgb(30, 100, 60)
    } catch {
        $lblIdent.Text = "App identity: could not identify ($($_.Exception.Message))"
        $lblIdent.ForeColor = [System.Drawing.Color]::FromArgb(150, 60, 40)
    }

    # Try to extract package family name from the path
    if ($path -match 'WindowsApps\\([A-Za-z0-9.\-]+)_[\d.]+_[a-z0-9]+__([a-z0-9]+)') {
        $pkgName = $matches[1]
        $pkgFamily = "${pkgName}_$($matches[2])"
        $txtPkg.Text = $pkgName

        # Try to guess process name from any .exe in the folder
        $exe = Get-ChildItem $path -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exe) {
            $txtProc.Text = $exe.BaseName
            Update-Status "Auto-detected: $pkgName / $pkgFamily / $($exe.BaseName)"
        } else {
            Update-Status "Auto-detected package; no process name guess available."
        }
    } else {
        # Not a WindowsApps MSIX path -- classic Win32 install folder (e.g. Program Files).
        # Use the folder name as PackageName and the largest .exe as the process guess.
        $pkgName = Split-Path $path -Leaf
        $txtPkg.Text = $pkgName
        $exe = Get-ChildItem $path -Filter '*.exe' -File -ErrorAction SilentlyContinue |
               Sort-Object Length -Descending | Select-Object -First 1
        if ($exe) {
            $txtProc.Text = $exe.BaseName
            Update-Status "Classic install detected: '$pkgName' / process guess '$($exe.BaseName)' (largest .exe). Edit if wrong."
        } else {
            Update-Status "Classic install folder '$pkgName' -- no .exe found at top level; set ProcessName manually if needed."
        }
    }
})

# --- Run audit ---
$btnRun.Add_Click({
    $target = $txtTarget.Text
    if (-not $target -or -not (Test-Path -LiteralPath $target)) {
        [System.Windows.Forms.MessageBox]::Show("Target not found: $target", 'TCPK', 'OK', 'Error') | Out-Null
        return
    }

    # Jump to the Audit tab so the live log + findings are visible while the run streams
    # (the user may have launched on the Dashboard landing tab).
    try { $tabs.SelectedTab = $tabAudit } catch { }

    $btnRun.Enabled = $false
    $btnOpenHtml.Enabled = $false
    $btnOpenExcel.Enabled = $false
    $btnOpenMarkdown.Enabled = $false
    $btnOpenFolder.Enabled = $false
    # pause/resume: clear any stale signal, then enable Pause for this run
    Remove-Item -LiteralPath $script:PauseFlag -Force -ErrorAction SilentlyContinue
    $btnPause.Text = "Pause"; $btnPause.Enabled = $true
    $txtLog.Clear()
    $lvFindings.Items.Clear()
    $script:LastFindings = $null   # empty the dashboard for the new run
    try { Update-Dashboard } catch { }

    Write-LogLine "TCPK $(if ($script:TcpkVersion) { "v$($script:TcpkVersion)" }) -- audit starting" ([System.Drawing.Color]::FromArgb(46, 204, 113))
    Write-LogLine "Target:    $target"
    Write-LogLine "Profile:   $($cmbProfile.SelectedItem)"
    Write-LogLine ""

    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $outDir = Join-Path (Split-Path -Parent $PSScriptRoot) "out\$(Split-Path $target -Leaf)_$stamp"
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $script:CurrentOutDir = $outDir

    # Build the cmdlet list per profile
    $params = @{
        Target = $target
        Acknowledge = $true
        OutDir = $outDir
        InformationAction = 'Continue'
        PauseSignalPath = $script:PauseFlag
    }
    if ($cmbProfile.SelectedItem) { $params.ScanProfile = "$($cmbProfile.SelectedItem)" }
    if ($chkOnlineCve.Checked) { $params.OnlineCve = $true }   # opt-in OSV live CVE (sends pkg names to osv.dev)
    if ($txtProc.Text) { $params.ProcessName = $txtProc.Text }
    if ($txtPkg.Text)  { $params.PackageName = $txtPkg.Text }

    # Auto-derive PackageFamilyName from PackageName if possible
    if ($txtPkg.Text) {
        $pkg = Get-AppxPackage -Name "*$($txtPkg.Text)*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pkg) { $params.PackageFamilyName = $pkg.PackageFamilyName }
    }

    # --- AI verification runs INLINE in the audit (single AI-aware report pass) ---
    # Configure the backend + confirm cloud use BEFORE the job starts; the job's
    # runspace reads llm-config.json, and -AllowCloudLlm opens the cloud gate there.
    # This replaces the old write-reports-then-rewrite post-pass (no stale window).
    if ($chkAi.Checked) {
        $aiSel = $cmbAi.SelectedItem
        $aiPreset = $script:AiPresets[$aiSel]
        $aiKeyOk = (-not $aiPreset.needsKey) -or [bool]$txtAiKey.Text
        $aiCloudOk = $true
        if ($aiKeyOk -and $aiPreset.name -ne 'ollama') {
            $msg = "The AI pass will send DECOMPILED CODE (IL) of the target to the CLOUD provider '$($aiPreset.name)'.`r`n`r`nFor a confidential engagement this may breach your authorization / NDA -- the code leaves this machine.`r`n`r`nSend the target's code to '$($aiPreset.name)'?`r`n`r`n(No = skip the AI pass and keep everything local. Tip: choose 'ollama (local)' for fully offline AI.)"
            $ans = [System.Windows.Forms.MessageBox]::Show($msg, "TCPK -- cloud AI confirmation", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning, [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
            $aiCloudOk = ($ans -eq [System.Windows.Forms.DialogResult]::Yes)
        }
        if (-not $aiKeyOk) {
            Write-LogLine "AI verify skipped: $aiSel needs an API key (none entered)." ([System.Drawing.Color]::FromArgb(214,137,16))
        } elseif (-not $aiCloudOk) {
            Write-LogLine "AI verify skipped: cloud provider '$($aiPreset.name)' not confirmed -- target code kept local." ([System.Drawing.Color]::FromArgb(214,137,16))
        } else {
            [void](Set-AiConfigFromGui)   # writes provider/model/key to llm-config.json (read by the job)
            $params.EnableLlm = $true
            if ($aiPreset.name -ne 'ollama') { $params.AllowCloudLlm = $true }
            Write-LogLine "[AI] $aiSel will verify code-construct findings inline; reports will include AI verdicts." ([System.Drawing.Color]::FromArgb(174,214,241))
        }
    }

    Update-Status "Running audit..."

    # Size the progress bar: count the audit's _RunCheck calls (= checks). The runtime
    # bucket (E) is gated on -ProcessName, so subtract those when no live process is
    # targeted. Self-adjusting (counts from the source), with a safe fallback.
    $chkTotal = 110
    try {
        $auditFile = Join-Path (Split-Path $tcpkPsd1 -Parent) 'Public\Invoke-TcpkAudit.ps1'
        if (Test-Path -LiteralPath $auditFile) {
            $al  = Get-Content -LiteralPath $auditFile
            $raw = @($al | Select-String -Pattern "^\s*_RunCheck '").Count
            $rt  = @($al | Select-String -Pattern '_RunCheck.*-ProcessName \$ProcessName').Count
            if ($raw -gt 0) { $chkTotal = if ($params.ProcessName) { $raw } else { [Math]::Max(1, $raw - $rt) } }
        }
    } catch { }
    Reset-Progress $chkTotal
    Reset-ScanResources
    $script:ScanWorkerPid = 0; $script:ScanWorkerLastCpu = 0.0; $script:ScanWorkerLastAt = [DateTime]::Now

    # Run as job so we can stream output
    $jobScript = {
        param($modulePath, $params)
        Import-Module $modulePath -Force
        # First line out: the worker's own PID, so the GUI can sample its CPU/RAM.
        # Start-Job runs a real separate process, so $PID here is the scan worker.
        "WPID`t$PID"
        Invoke-TcpkAudit @params 6>&1 |
            ForEach-Object {
                if ($_ -is [string]) {
                    if ($_ -notmatch '^LOGX\t') { "LOG`t$_" }     # LOGX = verbose trace -> Logs/Runtime tab only
                }
                elseif ($_ -is [System.Management.Automation.InformationRecord]) {
                    $t = "$_"
                    if ($t -match '^TCPKFND\t(.+)$') {
                        "LOG`t$t"
                        "FND`t$($matches[1])"
                    } elseif ($t -notmatch '^LOGX\t') { "LOG`t$t" }
                }
                elseif ($_.GetType().Name -eq 'TcpkFinding') {
                    "FND`t$($_.Severity)`t$($_.Confidence)`t$($_.RuleId)`t$($_.Title)"
                }
            }
    }
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $tcpkPsd1, $params

    while ($job.State -eq 'Running') {
        $out = Receive-Job -Job $job -Keep:$false
        foreach ($line in $out) {
            if ($line -match '^LOG\t(.+)$') {
                $msg = $matches[1]
                $colour = [System.Drawing.Color]::White
                if ($msg -match 'CRITICAL') { $colour = $script:SevColour['CRITICAL'] }
                elseif ($msg -match 'HIGH')   { $colour = $script:SevColour['HIGH'] }
                elseif ($msg -match 'findings') { $colour = [System.Drawing.Color]::FromArgb(174, 214, 241) }
                Write-LogLine $msg $colour
                Step-ProgressFromLog $msg
                Update-RunStatus
            }
            elseif ($line -match '^FND\t(.+?)\t(.+?)\t(.+?)\t(.+)$') {
                $f = [pscustomobject]@{
                    Severity = $matches[1]
                    Confidence = $matches[2]
                    RuleId = $matches[3]
                    Title = $matches[4]
                }
                Add-Finding $f
                Update-RunStatus
            }
            elseif ($line -match '^WPID\t(\d+)$') {
                $script:ScanWorkerPid = [int]$matches[1]
                # Baseline immediately so the first sample is a true delta. If this
                # throws (the worker may not be queryable the instant it emits), the
                # baseline stays at click time and the first reading over-reads; it is
                # clamped, so the cost is one spurious high tick, not a wrong trend.
                try {
                    $wp0 = Get-Process -Id $script:ScanWorkerPid -ErrorAction Stop
                    $script:ScanWorkerLastCpu = $wp0.CPU
                    $script:ScanWorkerLastAt  = [DateTime]::Now
                } catch { }
            }
        }
        # Sample worker CPU/RAM every 2s and refresh the toolbar readout.
        if ($script:ScanWorkerPid -gt 0) {
            $sElapsed = ([DateTime]::Now - $script:ScanWorkerLastAt).TotalSeconds
            if ($sElapsed -ge 2.0) {
                try {
                    $wp = Get-Process -Id $script:ScanWorkerPid -ErrorAction Stop
                    $cpuDelta = $wp.CPU - $script:ScanWorkerLastCpu
                    $nCores   = [Math]::Max(1, [Environment]::ProcessorCount)
                    $ce       = [Math]::Max(0.0, $cpuDelta / $sElapsed)
                    $cpuPct   = [Math]::Max(0, [Math]::Min(100, [int](($ce / $nCores) * 100)))
                    $ramMb    = Get-TcpkPrivateWsMb -ProcId $wp.Id -FallbackBytes $wp.WorkingSet64
                    $script:ScanWorkerLastCpu = $wp.CPU
                    $script:ScanWorkerLastAt  = [DateTime]::Now
                    Update-ScanResources -CpuPct $cpuPct -RamMb $ramMb -Cores $ce -Src 'worker'
                } catch { $script:ScanWorkerPid = 0 }
            }
        }
        Start-Sleep -Milliseconds 150
        [System.Windows.Forms.Application]::DoEvents()
    }
    $script:ScanWorkerPid = 0
    Reset-ScanResources
    # Drain remaining output from the job (LOG + FND)
    $remaining = Receive-Job -Job $job -Wait -AutoRemoveJob
    foreach ($line in $remaining) {
        if ($line -match '^LOG\t(.+)$') {
            $dmsg = $matches[1]
            Write-LogLine $dmsg
            Step-ProgressFromLog $dmsg
        }
        elseif ($line -match '^FND\t(.+?)\t(.+?)\t(.+?)\t(.+)$') {
            $f = [pscustomobject]@{
                Severity   = $matches[1]
                Confidence = $matches[2]
                RuleId     = $matches[3]
                Title      = $matches[4]
            }
            Add-Finding $f
        }
    }
    # Audit job finished -> the run (including report writing) is complete.
    Set-Progress 100
    Update-RunStatus

    # Findings come from the JSON the audit writes -- more reliable than
    # PowerShell-job pipeline streaming for typed objects.
    $jsonPath = Join-Path $outDir 'findings.json'
    if (Test-Path $jsonPath) {
        Write-LogLine ""
        Write-LogLine "Loading findings from $jsonPath..." ([System.Drawing.Color]::FromArgb(174, 214, 241))
        try {
            $findings = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json

            # Enrich each finding with its computed CVSS (Get-TcpkCvssVector is module-private)
            # so the Dashboard can show MAX CVSS + per-finding scores. One module-scope call
            # over all findings; falls back to the raw set if anything goes wrong.
            $script:LastFindings = $null
            try {
                $mod = @(Get-Module TCPK)[0]
                if ($mod) {
                    $script:LastFindings = & $mod {
                        param($fs)
                        foreach ($f in $fs) {
                            $sc = $null; $rt = ''
                            try { $cv = Get-TcpkCvssVector $f; if ($cv) { $sc = $cv.Score; $rt = $cv.Rating } } catch { }
                            $f | Add-Member -NotePropertyName CvssScore  -NotePropertyValue $sc -Force
                            $f | Add-Member -NotePropertyName CvssRating -NotePropertyValue $rt -Force
                            $f
                        }
                    } $findings
                }
            } catch { }
            if (-not $script:LastFindings) { $script:LastFindings = $findings }

            # AI verification now runs INLINE inside Invoke-TcpkAudit (via the
            # -EnableLlm / -AllowCloudLlm wiring set up before the job started), so
            # findings.json already carries the AI verdicts and every report
            # (HTML / Excel / JSON) is AI-aware in a single pass -- no re-export.

            # Sort by severity (CRITICAL first) and populate the table
            $sevRank = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3; 'INFO' = 4 }
            $sorted = $findings | Sort-Object @{ E = { $sevRank[$_.Severity] } }, RuleId

            # Bulk-load with BeginUpdate/EndUpdate so the table paints once (smooth),
            # instead of redrawing per finding.
            $lvFindings.Items.Clear()
            $lvFindings.BeginUpdate()
            try { foreach ($f in $sorted) { Add-Finding $f } } finally { $lvFindings.EndUpdate() }
            try { Update-Dashboard } catch { }
            Write-LogLine "Loaded $(@($findings).Count) findings into the table." ([System.Drawing.Color]::FromArgb(46, 204, 113))
        } catch {
            Write-LogLine "Could not parse findings.json: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(231, 76, 60))
        }
    } else {
        Write-LogLine "findings.json not produced -- audit may have failed before reporting." ([System.Drawing.Color]::FromArgb(231, 76, 60))
    }

    # Populate the Recon / Target tab from profile.json
    try {
        Render-Recon $outDir
        Write-LogLine ""
        Write-LogLine "Recon profile ready -- click the 'Recon / Target' tab to view application + network details." ([System.Drawing.Color]::FromArgb(102, 217, 239))
    } catch {
        Write-LogLine "Recon render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    # Populate the Exploit / CVE tab from exploits.json
    try {
        Populate-Exploits $outDir
        Write-LogLine "Exploit/CVE plan ready -- click the 'Exploit / CVE' tab ($(@($script:ExploitPlan).Count) actionable items)." ([System.Drawing.Color]::FromArgb(249, 38, 114))
    } catch {
        Write-LogLine "Exploit plan render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    # Populate the SBOM tab from sbom.cdx.json
    try {
        Populate-Sbom $outDir
        Write-LogLine "SBOM ready -- click the 'SBOM' tab ($($lvSbom.Items.Count) components)." ([System.Drawing.Color]::FromArgb(102, 217, 239))
    } catch {
        Write-LogLine "SBOM render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    # Populate the DLL Mitigation Matrix tab from hardening.json
    try {
        Populate-Hardening $outDir
        Write-LogLine "DLL mitigation matrix ready -- click the 'DLL Mitigation Matrix' tab ($($lvHard.Items.Count) DLLs)." ([System.Drawing.Color]::FromArgb(102, 217, 239))
    } catch {
        Write-LogLine "DLL matrix render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    # Populate the DLL Signing tab from signing.json
    try {
        Populate-Signing $outDir
        Write-LogLine "DLL signing matrix ready -- click the 'DLL Signing' tab ($($lvSign.Items.Count) DLLs)." ([System.Drawing.Color]::FromArgb(102, 217, 239))
    } catch {
        Write-LogLine "DLL signing render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    # Populate the Logs / Runtime tab from run.jsonl
    try {
        Populate-Logs $outDir
        Write-LogLine "Runtime log ready -- click the 'Logs / Runtime' tab for the verbose timed trace + analysis." ([System.Drawing.Color]::FromArgb(174, 214, 241))
    } catch {
        Write-LogLine "Runtime log render failed: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(214, 137, 16))
    }

    Write-LogLine ""
    Write-LogLine "Audit complete. Reports in: $outDir" ([System.Drawing.Color]::FromArgb(46, 204, 113))
    Update-Status "Audit complete -- $($lvFindings.Items.Count) findings shown."
    # Land on the Dashboard so the severity summary is the first thing seen post-audit.
    try { Update-Dashboard; $tabs.SelectedTab = $tabDash } catch { }
    $btnRun.Enabled = $true
    # pause/resume: audit finished -> disable Pause and clear any signal
    $btnPause.Enabled = $false; $btnPause.Text = "Pause"
    Remove-Item -LiteralPath $script:PauseFlag -Force -ErrorAction SilentlyContinue
    $btnOpenHtml.Enabled = (Test-Path (Join-Path $outDir 'index.html'))
    $btnOpenExcel.Enabled = (Test-Path (Join-Path $outDir 'report.xlsx'))
    $btnOpenMarkdown.Enabled = (Test-Path (Join-Path $outDir 'report.md'))
    $btnOpenFolder.Enabled = $true
})

$btnOpenHtml.Add_Click({
    $html = Join-Path $script:CurrentOutDir 'index.html'
    if (Test-Path $html) { Start-Process $html }
})

$btnOpenExcel.Add_Click({
    $xl = Join-Path $script:CurrentOutDir 'report.xlsx'
    if (Test-Path $xl) { Start-Process $xl }
})

$btnOpenMarkdown.Add_Click({
    $md = Join-Path $script:CurrentOutDir 'report.md'
    if (Test-Path $md) { Start-Process $md }
})

$btnOpenFolder.Add_Click({
    if ($script:CurrentOutDir -and (Test-Path $script:CurrentOutDir)) {
        Start-Process explorer.exe $script:CurrentOutDir
    }
})

# --- Persistent disclaimer strip (always visible at the bottom edge) ---
$disclaimerStrip = New-Object System.Windows.Forms.Label
$disclaimerStrip.Dock = 'Bottom'
$disclaimerStrip.Height = 22
$disclaimerStrip.BackColor = [System.Drawing.Color]::FromArgb(120, 0, 0)
$disclaimerStrip.ForeColor = [System.Drawing.Color]::White
$disclaimerStrip.TextAlign = 'MiddleCenter'
$disclaimerStrip.Font = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
$disclaimerStrip.Text = "FOR AUTHORIZED TESTING ONLY  --  misuse is solely YOUR responsibility; the author(s) / community accept NO liability.  Provided AS IS, no warranty.  See DISCLAIMER.txt"
$form.Controls.Add($disclaimerStrip)
$disclaimerStrip.BringToFront()

# Controls that keep their colour regardless of theme (accent buttons, banners)
foreach ($keep in @($btnRun, $btnExpRun, $disclaimerStrip, $expBanner)) { if ($keep) { $keep.Tag = 'keep' } }

# Apply initial appearance: dark theme + coding font + modern flat styling
Apply-UiFont
Apply-UiTheme
Apply-ModernStyle
# Keep disabled-button labels legible on the dark theme (wire once, after styling).
Wire-ReadableDisabledButtons

# --- Mandatory startup disclaimer acknowledgement ---
$ackText = @"
TCPK -- DISCLAIMER / TERMS OF USE

This tool is for AUTHORIZED security testing and educational use ONLY.

By clicking YES you confirm that:
  - You have explicit, WRITTEN AUTHORIZATION to test the target.
  - ANY MISUSE (testing systems you do not own or lack permission to
    test, or any unlawful activity) is SOLELY YOUR RESPONSIBILITY.
  - The author(s) and the open-source community accept NO LIABILITY
    for any damage, legal consequence, or misuse of this tool.
  - The software is provided "AS IS", without warranty of any kind.

If you do NOT agree, click No and the tool will close.

Do you agree to these terms?
"@
$ack = [System.Windows.Forms.MessageBox]::Show(
    $ackText, "TCPK -- Authorized use only",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning)
if ($ack -ne [System.Windows.Forms.DialogResult]::Yes) {
    [System.Windows.Forms.MessageBox]::Show("Terms not accepted. TCPK will exit.", "TCPK", 'OK', 'Information') | Out-Null
    return
}

# The disclaimer strip is added + BringToFront'd after the TabControl, so the Fill tabs end
# up overlapping the strip -- the tab's bottom row (the Exploit "gate" line + Generate button)
# was clipped behind it. Re-assert the tabs to the front, after all controls + styling, so the
# Fill reserves its space above BOTH the disclaimer strip and the reports footer.
$tabs.BringToFront()

# Show
[void]$form.ShowDialog()
