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

    Drop this folder onto a USB drive; double-click TCPK.bat (or the compiled
    TCPK.exe) to launch. No install needed.
#>
[CmdletBinding()]
param()

# Resolve the TCPK module path. This must work whether the GUI is launched as a script
# (-File: $PSScriptRoot is set) OR as a compiled .exe (ps2exe leaves $PSScriptRoot empty,
# so we also probe the EXE's own directory, the AppDomain base dir, and the working
# directory). Keep the whole TCPK folder together: the launcher must sit beside the TCPK\
# module folder. NOTE: a compiled TCPK.exe must be REBUILT from this script to pick up
# these extra search locations.
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
        "TCPK module (TCPK\TCPK.psd1) was not found next to the launcher.`n`nKeep the whole folder together -- TCPK.bat / TCPK.exe must sit beside the TCPK\ module folder. Searched:`n  $searched",
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
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# Window / taskbar icon (assets\tcpk.ico). Replace that file to rebrand.
$script:TcpkAssets = Join-Path $PSScriptRoot 'assets'
$icoPath = Join-Path $script:TcpkAssets 'tcpk.ico'
if (Test-Path $icoPath) { try { $form.Icon = New-Object System.Drawing.Icon($icoPath) } catch {} }

# --- Top panel: target + profile + AI + run ---
$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = 'Top'
$topPanel.Height = 206
$topPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
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
    $picLogo.Size = New-Object System.Drawing.Size(168, 152)
    $picLogo.Location = New-Object System.Drawing.Point(1008, 12)
    $picLogo.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
    $picLogo.BackColor = [System.Drawing.Color]::Transparent
    try { $picLogo.Image = [System.Drawing.Image]::FromFile($badgePath) } catch {}
    $topPanel.Controls.Add($picLogo)
    $picLogo.BringToFront()
}

$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Target (MSIX file or install folder):"
$lblTarget.Location = New-Object System.Drawing.Point(14, 12)
$lblTarget.Size = New-Object System.Drawing.Size(220, 18)
$topPanel.Controls.Add($lblTarget)

$txtTarget = New-Object System.Windows.Forms.TextBox
$txtTarget.Location = New-Object System.Drawing.Point(14, 32)
$txtTarget.Size = New-Object System.Drawing.Size(800, 24)
$txtTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtTarget.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($txtTarget)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Location = New-Object System.Drawing.Point(820, 30)
$btnBrowse.Size = New-Object System.Drawing.Size(90, 28)
$btnBrowse.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnBrowse)

$btnAutoDetect = New-Object System.Windows.Forms.Button
$btnAutoDetect.Text = "Auto-Detect"
$btnAutoDetect.Location = New-Object System.Drawing.Point(916, 30)
$btnAutoDetect.Size = New-Object System.Drawing.Size(90, 28)
$btnAutoDetect.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($btnAutoDetect)

# Application-identity line: filled by Auto-Detect BEFORE the audit runs, so the operator
# sees what kind of app this is (type / runtime / UI / signer) up front.
$lblIdent = New-Object System.Windows.Forms.Label
$lblIdent.Text = "App identity: click Auto-Detect to identify the target (type / runtime / UI / signer)."
$lblIdent.Location = New-Object System.Drawing.Point(14, 176)
$lblIdent.Size = New-Object System.Drawing.Size(992, 24)
$lblIdent.AutoEllipsis = $true
$lblIdent.ForeColor = [System.Drawing.Color]::FromArgb(40, 116, 166)
$lblIdent.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblIdent.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($lblIdent)

$lblProfile = New-Object System.Windows.Forms.Label
$lblProfile.Text = "Profile:"
$lblProfile.Location = New-Object System.Drawing.Point(14, 70)
$lblProfile.Size = New-Object System.Drawing.Size(60, 18)
$topPanel.Controls.Add($lblProfile)

$cmbProfile = New-Object System.Windows.Forms.ComboBox
$cmbProfile.Location = New-Object System.Drawing.Point(80, 67)
$cmbProfile.Size = New-Object System.Drawing.Size(120, 24)
$cmbProfile.DropDownStyle = 'DropDownList'
@('Quick','Standard','Full') | ForEach-Object { [void]$cmbProfile.Items.Add($_) }
$cmbProfile.SelectedIndex = 2
$topPanel.Controls.Add($cmbProfile)

$lblPkg = New-Object System.Windows.Forms.Label
$lblPkg.Text = "PackageName:"
$lblPkg.Location = New-Object System.Drawing.Point(220, 70)
$lblPkg.Size = New-Object System.Drawing.Size(90, 18)
$topPanel.Controls.Add($lblPkg)

$txtPkg = New-Object System.Windows.Forms.TextBox
$txtPkg.Location = New-Object System.Drawing.Point(310, 67)
$txtPkg.Size = New-Object System.Drawing.Size(140, 24)
$topPanel.Controls.Add($txtPkg)

$lblProc = New-Object System.Windows.Forms.Label
$lblProc.Text = "ProcessName:"
$lblProc.Location = New-Object System.Drawing.Point(460, 70)
$lblProc.Size = New-Object System.Drawing.Size(90, 18)
$topPanel.Controls.Add($lblProc)

$txtProc = New-Object System.Windows.Forms.TextBox
$txtProc.Location = New-Object System.Drawing.Point(550, 67)
$txtProc.Size = New-Object System.Drawing.Size(140, 24)
$topPanel.Controls.Add($txtProc)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run Audit"
$btnRun.Location = New-Object System.Drawing.Point(820, 65)
$btnRun.Size = New-Object System.Drawing.Size(118, 32)
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
$btnPause.Location = New-Object System.Drawing.Point(942, 65)
$btnPause.Size = New-Object System.Drawing.Size(64, 32)
$btnPause.Enabled = $false
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
$chkOnlineCve.Text = "Online CVE"
$chkOnlineCve.Location = New-Object System.Drawing.Point(700, 69)
$chkOnlineCve.Size = New-Object System.Drawing.Size(112, 22)
$chkOnlineCve.Checked = $true
$topPanel.Controls.Add($chkOnlineCve)
$ttOnlineCve = New-Object System.Windows.Forms.ToolTip
$ttOnlineCve.SetToolTip($chkOnlineCve, "Live CVE lookup: OSV (NuGet/Electron) + NVD/CPE (native libs: OpenSSL/zlib/sqlite). Uncheck = offline catalog only. Sends only package/CPE name+version.")

# --- AI row (y=108) -----------------------------------------------------------
$chkAi = New-Object System.Windows.Forms.CheckBox
$chkAi.Text = "AI-verify findings"
$chkAi.Location = New-Object System.Drawing.Point(14, 112)
$chkAi.Size = New-Object System.Drawing.Size(130, 22)
$chkAi.Checked = $false   # unchecked by default -- let the operator opt in
$topPanel.Controls.Add($chkAi)

$lblAi = New-Object System.Windows.Forms.Label
$lblAi.Text = "Model:"
$lblAi.Location = New-Object System.Drawing.Point(150, 114)
$lblAi.Size = New-Object System.Drawing.Size(44, 18)
$topPanel.Controls.Add($lblAi)

$cmbAi = New-Object System.Windows.Forms.ComboBox
$cmbAi.Location = New-Object System.Drawing.Point(196, 110)
$cmbAi.Size = New-Object System.Drawing.Size(120, 24)
$cmbAi.DropDownStyle = 'DropDownList'
# Provider list. 'custom' = any other OpenAI-compatible endpoint (set its URL in llm-config.json).
@('ollama (local)','claude','openai','gemini','grok','deepseek','custom') | ForEach-Object { [void]$cmbAi.Items.Add($_) }
$cmbAi.SelectedIndex = 0
$topPanel.Controls.Add($cmbAi)

# Free-text model box: type ANY model the provider exposes -- nothing is hardcoded.
# A sensible default is pre-filled per provider; click "Test AI" to load the live
# list from your key (Get-TcpkLlmModels) into the dropdown for convenience.
$txtAiModel = New-Object System.Windows.Forms.ComboBox
$txtAiModel.Location = New-Object System.Drawing.Point(322, 110)
$txtAiModel.Size = New-Object System.Drawing.Size(170, 24)
$txtAiModel.DropDownStyle = 'DropDown'
$txtAiModel.Text = 'qwen2.5-coder:7b'   # default for ollama (provider[0]); overtype with anything
$topPanel.Controls.Add($txtAiModel)

$lblKey = New-Object System.Windows.Forms.Label
$lblKey.Text = "API key:"
$lblKey.Location = New-Object System.Drawing.Point(500, 114)
$lblKey.Size = New-Object System.Drawing.Size(52, 18)
$topPanel.Controls.Add($lblKey)

$txtAiKey = New-Object System.Windows.Forms.TextBox
$txtAiKey.Location = New-Object System.Drawing.Point(554, 110)
$txtAiKey.Size = New-Object System.Drawing.Size(180, 24)
$txtAiKey.UseSystemPasswordChar = $true
$txtAiKey.Enabled = $false   # disabled for local ollama
$topPanel.Controls.Add($txtAiKey)

$btnTestAi = New-Object System.Windows.Forms.Button
$btnTestAi.Text = "Test AI"
$btnTestAi.Location = New-Object System.Drawing.Point(744, 108)
$btnTestAi.Size = New-Object System.Drawing.Size(70, 28)
$topPanel.Controls.Add($btnTestAi)

$lblAiStatus = New-Object System.Windows.Forms.Label
$lblAiStatus.Text = ""
$lblAiStatus.Location = New-Object System.Drawing.Point(820, 114)
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
$lblFont.Text = "Font:"; $lblFont.Location = New-Object System.Drawing.Point(14, 150); $lblFont.Size = New-Object System.Drawing.Size(36, 18)
$topPanel.Controls.Add($lblFont)

$cmbFont = New-Object System.Windows.Forms.ComboBox
$cmbFont.Location = New-Object System.Drawing.Point(52, 147); $cmbFont.Size = New-Object System.Drawing.Size(160, 24)
$cmbFont.DropDownStyle = 'DropDownList'
$codingFonts | ForEach-Object { [void]$cmbFont.Items.Add($_) }
$cmbFont.SelectedItem = $(if ($codingFonts -contains 'Fira Code') { 'Fira Code' } elseif ($codingFonts -contains 'Cascadia Code') { 'Cascadia Code' } else { 'Consolas' })
$cmbFont.Add_SelectedIndexChanged({ Apply-UiFont })
$topPanel.Controls.Add($cmbFont)

$lblSize = New-Object System.Windows.Forms.Label
$lblSize.Text = "Size:"; $lblSize.Location = New-Object System.Drawing.Point(224, 150); $lblSize.Size = New-Object System.Drawing.Size(34, 18)
$topPanel.Controls.Add($lblSize)

$cmbSize = New-Object System.Windows.Forms.ComboBox
$cmbSize.Location = New-Object System.Drawing.Point(258, 147); $cmbSize.Size = New-Object System.Drawing.Size(56, 24)
$cmbSize.DropDownStyle = 'DropDownList'
@(8, 9, 10, 11, 12, 14, 16) | ForEach-Object { [void]$cmbSize.Items.Add($_) }
$cmbSize.SelectedItem = 10
$cmbSize.Add_SelectedIndexChanged({ Apply-UiFont })
$topPanel.Controls.Add($cmbSize)

$btnTheme = New-Object System.Windows.Forms.Button
$btnTheme.Text = "Theme: Dark"; $btnTheme.Location = New-Object System.Drawing.Point(330, 145); $btnTheme.Size = New-Object System.Drawing.Size(120, 28)
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
$tabDash.Text = '  Dashboard  '
$tabDash.BackColor = [System.Drawing.Color]::FromArgb(13, 16, 22)
[void]$tabs.TabPages.Add($tabDash)

$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = '  Audit  '
$tabAudit.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
[void]$tabs.TabPages.Add($tabAudit)

$tabRecon = New-Object System.Windows.Forms.TabPage
$tabRecon.Text = '  Recon / Target  '
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
$tabExploit.Text = '  Exploit / CVE  '
$tabExploit.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
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
$chkExpEnable.Location = New-Object System.Drawing.Point(12, 30); $chkExpEnable.Size = New-Object System.Drawing.Size(460, 22)
$expBanner.Controls.Add($chkExpEnable)
$tabExploit.Controls.Add($expBanner)

# --- The "Dynamic / Active tools" toolbar was moved to the Runtime / Live tab, which now
# hosts every process-based check -- the read-only ones AND the gated active tools together.
# The Exploit / CVE tab is left to CVE matches + gated PoC generation (below). ---

# Bottom: run button + status
$expBottom = New-Object System.Windows.Forms.Panel
$expBottom.Dock = 'Bottom'; $expBottom.Height = 44; $expBottom.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$btnExpRun = New-Object System.Windows.Forms.Button
$btnExpRun.Text = "Generate PoC + Verify"; $btnExpRun.Dock = 'Right'; $btnExpRun.Width = 200; $btnExpRun.Enabled = $false
$btnExpRun.BackColor = [System.Drawing.Color]::FromArgb(155, 0, 0); $btnExpRun.ForeColor = [System.Drawing.Color]::White
$btnExpRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$expBottom.Controls.Add($btnExpRun)
$lblExpStatus = New-Object System.Windows.Forms.Label
$lblExpStatus.Dock = 'Fill'; $lblExpStatus.TextAlign = 'MiddleLeft'; $lblExpStatus.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$lblExpStatus.Text = "Exploit gate: OFF  --  tick the authorization box above to enable."
$expBottom.Controls.Add($lblExpStatus)
$tabExploit.Controls.Add($expBottom)

# --- SBOM tab (software bill of materials + embedded CVEs) ---
# NB: add the Dock=Top hint FIRST, then the Dock=Fill ListView LAST -- otherwise the
# ListView fills the whole tab and its column-header row is hidden behind the hint.
$tabSbom = New-Object System.Windows.Forms.TabPage
$tabSbom.Text = '  SBOM  '
$tabSbom.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabSbom)
# header panel: hint + live filter (ONE Top panel) then the Fill ListView added last
$sbomHeader = New-Object System.Windows.Forms.Panel
$sbomHeader.Dock = 'Top'; $sbomHeader.Height = 50
$sbomHint = New-Object System.Windows.Forms.Label
$sbomHint.AutoSize = $true; $sbomHint.Location = New-Object System.Drawing.Point(6, 6)
$sbomHint.Text = "Run an audit -- every shipped component (name, version, purl, SHA-256) + any matched CVEs (from sbom.cdx.json)."
$sbomLblF = New-Object System.Windows.Forms.Label
$sbomLblF.AutoSize = $true; $sbomLblF.Location = New-Object System.Drawing.Point(6, 28); $sbomLblF.Text = "Filter:"
$txtSbomFilter = New-Object System.Windows.Forms.TextBox
$txtSbomFilter.Location = New-Object System.Drawing.Point(52, 25); $txtSbomFilter.Size = New-Object System.Drawing.Size(470, 22)
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
$tabHard.Text = '  DLL Mitigation Matrix  '
$tabHard.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabHard)
$hardHeader = New-Object System.Windows.Forms.Panel
$hardHeader.Dock = 'Top'; $hardHeader.Height = 50
$hardHint = New-Object System.Windows.Forms.Label
$hardHint.AutoSize = $true; $hardHint.Location = New-Object System.Drawing.Point(6, 6)
$hardHint.Text = "Run an audit -- per-DLL mitigations (ASLR / DEP / CFG / HighEntropyVA / SafeSEH / GS stack cookie / ForceIntegrity). Red = WEAK, orange = PARTIAL, green = HARDENED."
$hardLblF = New-Object System.Windows.Forms.Label
$hardLblF.AutoSize = $true; $hardLblF.Location = New-Object System.Drawing.Point(6, 28); $hardLblF.Text = "Filter:"
$txtHardFilter = New-Object System.Windows.Forms.TextBox
$txtHardFilter.Location = New-Object System.Drawing.Point(52, 25); $txtHardFilter.Size = New-Object System.Drawing.Size(470, 22)
$txtHardFilter.Add_TextChanged({ Filter-Hardening })
$hardHeader.Controls.AddRange(@($hardHint, $hardLblF, $txtHardFilter))
$tabHard.Controls.Add($hardHeader)
$lvHard = New-Object System.Windows.Forms.ListView
$lvHard.Dock = 'Fill'; $lvHard.View = 'Details'; $lvHard.FullRowSelect = $true; $lvHard.GridLines = $true
$lvHard.HeaderStyle = 'Nonclickable'
$lvHard.Font = New-Object System.Drawing.Font('Segoe UI', 9)
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
$tabSign.Text = '  DLL Signing  '
$tabSign.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabSign)
$signHeader = New-Object System.Windows.Forms.Panel
$signHeader.Dock = 'Top'; $signHeader.Height = 50
$signHint = New-Object System.Windows.Forms.Label
$signHint.AutoSize = $true; $signHint.Location = New-Object System.Drawing.Point(6, 6)
$signHint.Text = "Run an audit -- per-DLL code-signing status (information only). Red = UNSIGNED / TAMPERED / UNTRUSTED, green = SIGNED / CATALOG."
$signLblF = New-Object System.Windows.Forms.Label
$signLblF.AutoSize = $true; $signLblF.Location = New-Object System.Drawing.Point(6, 28); $signLblF.Text = "Filter:"
$txtSignFilter = New-Object System.Windows.Forms.TextBox
$txtSignFilter.Location = New-Object System.Drawing.Point(52, 25); $txtSignFilter.Size = New-Object System.Drawing.Size(470, 22)
$txtSignFilter.Add_TextChanged({ Filter-Signing })
$signHeader.Controls.AddRange(@($signHint, $signLblF, $txtSignFilter))
$tabSign.Controls.Add($signHeader)
$lvSign = New-Object System.Windows.Forms.ListView
$lvSign.Dock = 'Fill'; $lvSign.View = 'Details'; $lvSign.FullRowSelect = $true; $lvSign.GridLines = $true
$lvSign.HeaderStyle = 'Nonclickable'
$lvSign.Font = New-Object System.Drawing.Font('Segoe UI', 9)
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
$tabLogs.Text = '  Logs / Runtime  '
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
function Invoke-IcptTool($box, [string]$title, [scriptblock]$call) {
    Write-IcptLine $box "`r`n== $title ==`r`n" ([System.Drawing.Color]::FromArgb(102,217,239))
    Update-Status "$title ... (the window may pause while this runs)"
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $res = & $call
        $n = 0
        foreach ($f in @($res)) {
            if (-not $f) { continue }
            $n++
            $c = $script:SevColour[[string]$f.Severity]; if (-not $c) { $c = [System.Drawing.Color]::White }
            Write-IcptLine $box ("[{0}] [{1}] {2}`r`n" -f $f.Severity, $f.Confidence, $f.Title) $c
            if ($f.Evidence) { Write-IcptLine $box ("      {0}`r`n" -f $f.Evidence) ([System.Drawing.Color]::FromArgb(150,150,150)) }
        }
        if ($n -eq 0) { Write-IcptLine $box "(no findings returned)`r`n" ([System.Drawing.Color]::FromArgb(150,150,150)) }
        else { Write-IcptLine $box ("-> {0} finding(s)`r`n" -f $n) ([System.Drawing.Color]::FromArgb(166,226,46)) }
    } catch {
        Write-IcptLine $box ("ERROR: {0}`r`n" -f $_.Exception.Message) ([System.Drawing.Color]::FromArgb(249,38,114))
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        Update-Status "Ready."
    }
}

# ================= TAB A: Interception (traffic capture) =================
$tabIcptA = New-Object System.Windows.Forms.TabPage
$tabIcptA.Text = '  Interception  '
$tabIcptA.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
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
$chkGateA.Location = New-Object System.Drawing.Point(12,26); $chkGateA.Size = New-Object System.Drawing.Size(460,22)
$bannerA.Controls.Add($chkGateA)
$tabIcptA.Controls.Add($bannerA)

# Controls panel
$ctlA = New-Object System.Windows.Forms.Panel
$ctlA.Dock = 'Top'; $ctlA.Height = 200; $ctlA.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)

# App exe row
$lblExeA = New-Object System.Windows.Forms.Label
$lblExeA.Text = "App exe (.exe to launch through the proxy):"
$lblExeA.Location = New-Object System.Drawing.Point(12,8); $lblExeA.Size = New-Object System.Drawing.Size(320,18)
$ctlA.Controls.Add($lblExeA)
$txtExeA = New-Object System.Windows.Forms.TextBox
$txtExeA.Location = New-Object System.Drawing.Point(336,5); $txtExeA.Size = New-Object System.Drawing.Size(660,24); $txtExeA.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtExeA.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlA.Controls.Add($txtExeA)
$btnBrowseA = New-Object System.Windows.Forms.Button
$btnBrowseA.Text = "Browse..."; $btnBrowseA.Location = New-Object System.Drawing.Point(1002,3); $btnBrowseA.Size = New-Object System.Drawing.Size(84,26)
$btnBrowseA.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlA.Controls.Add($btnBrowseA)
$btnBrowseA.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtExeA.Text = $dlg.FileName }
})

# Traffic interception group
$gbTraffic = New-Object System.Windows.Forms.GroupBox
$gbTraffic.Text = "Traffic interception (mitmproxy)"
$gbTraffic.Location = New-Object System.Drawing.Point(10,36); $gbTraffic.Size = New-Object System.Drawing.Size(578,150)
$ctlA.Controls.Add($gbTraffic)
$lblMode = New-Object System.Windows.Forms.Label; $lblMode.Text = "Mode:"; $lblMode.Location = New-Object System.Drawing.Point(12,26); $lblMode.Size = New-Object System.Drawing.Size(44,18); $gbTraffic.Controls.Add($lblMode)
$cmbMode = New-Object System.Windows.Forms.ComboBox; $cmbMode.Location = New-Object System.Drawing.Point(58,23); $cmbMode.Size = New-Object System.Drawing.Size(96,24); $cmbMode.DropDownStyle = 'DropDownList'
@('Proxy','Tamper') | ForEach-Object { [void]$cmbMode.Items.Add($_) }; $cmbMode.SelectedIndex = 0; $gbTraffic.Controls.Add($cmbMode)
$lblDur = New-Object System.Windows.Forms.Label; $lblDur.Text = "Duration(s):"; $lblDur.Location = New-Object System.Drawing.Point(170,26); $lblDur.Size = New-Object System.Drawing.Size(72,18); $gbTraffic.Controls.Add($lblDur)
$numDur = New-Object System.Windows.Forms.NumericUpDown; $numDur.Location = New-Object System.Drawing.Point(244,23); $numDur.Size = New-Object System.Drawing.Size(60,24); $numDur.Minimum = 3; $numDur.Maximum = 600; $numDur.Value = 20; $gbTraffic.Controls.Add($numDur)
$lblTam = New-Object System.Windows.Forms.Label; $lblTam.Text = "Tamper rules (find=>replace, one per line; Tamper mode):"; $lblTam.Location = New-Object System.Drawing.Point(12,52); $lblTam.Size = New-Object System.Drawing.Size(360,18); $gbTraffic.Controls.Add($lblTam)
$txtTamper = New-Object System.Windows.Forms.TextBox; $txtTamper.Location = New-Object System.Drawing.Point(12,70); $txtTamper.Size = New-Object System.Drawing.Size(554,34); $txtTamper.Multiline = $true; $txtTamper.Font = New-Object System.Drawing.Font('Consolas', 9); $gbTraffic.Controls.Add($txtTamper)
$btnCap = New-Object System.Windows.Forms.Button; $btnCap.Text = "Launch + capture"; $btnCap.Location = New-Object System.Drawing.Point(12,112); $btnCap.Size = New-Object System.Drawing.Size(150,28)
$btnCap.BackColor = [System.Drawing.Color]::FromArgb(155,0,0); $btnCap.ForeColor = [System.Drawing.Color]::White; $btnCap.FlatStyle = 'Flat'; $gbTraffic.Controls.Add($btnCap)
$btnLoad = New-Object System.Windows.Forms.Button; $btnLoad.Text = "Load capture file..."; $btnLoad.Location = New-Object System.Drawing.Point(172,112); $btnLoad.Size = New-Object System.Drawing.Size(150,28); $btnLoad.FlatStyle = 'Flat'; $gbTraffic.Controls.Add($btnLoad)
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

# ================= TAB B: Live Exploit / Creds =================
$tabIcptB = New-Object System.Windows.Forms.TabPage
$tabIcptB.Text = '  Live Exploit / Creds  '
$tabIcptB.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
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
$chkGateB.Location = New-Object System.Drawing.Point(12,26); $chkGateB.Size = New-Object System.Drawing.Size(460,22)
$bannerB.Controls.Add($chkGateB)
$tabIcptB.Controls.Add($bannerB)

# Controls panel
$ctlB = New-Object System.Windows.Forms.Panel
$ctlB.Dock = 'Top'; $ctlB.Height = 322; $ctlB.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)

# App exe row (for hook bypass)
$lblExeB = New-Object System.Windows.Forms.Label
$lblExeB.Text = "App exe (.exe to launch + hook):"
$lblExeB.Location = New-Object System.Drawing.Point(12,8); $lblExeB.Size = New-Object System.Drawing.Size(320,18)
$ctlB.Controls.Add($lblExeB)
$txtExeB = New-Object System.Windows.Forms.TextBox
$txtExeB.Location = New-Object System.Drawing.Point(336,5); $txtExeB.Size = New-Object System.Drawing.Size(660,24); $txtExeB.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtExeB.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlB.Controls.Add($txtExeB)
$btnBrowseB = New-Object System.Windows.Forms.Button
$btnBrowseB.Text = "Browse..."; $btnBrowseB.Location = New-Object System.Drawing.Point(1002,3); $btnBrowseB.Size = New-Object System.Drawing.Size(84,26)
$btnBrowseB.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right)
$ctlB.Controls.Add($btnBrowseB)
$btnBrowseB.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtExeB.Text = $dlg.FileName }
})

# Native hook bypass group
$gbHook = New-Object System.Windows.Forms.GroupBox
$gbHook.Text = "Native hook bypass (frida)"
$gbHook.Location = New-Object System.Drawing.Point(10,36); $gbHook.Size = New-Object System.Drawing.Size(578,150)
$ctlB.Controls.Add($gbHook)
$lblHFn = New-Object System.Windows.Forms.Label; $lblHFn.Text = "Function (native export):"; $lblHFn.Location = New-Object System.Drawing.Point(12,26); $lblHFn.Size = New-Object System.Drawing.Size(150,18); $gbHook.Controls.Add($lblHFn)
$txtHookFn = New-Object System.Windows.Forms.TextBox; $txtHookFn.Location = New-Object System.Drawing.Point(170,23); $txtHookFn.Size = New-Object System.Drawing.Size(200,24); $txtHookFn.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbHook.Controls.Add($txtHookFn)
$lblHMod = New-Object System.Windows.Forms.Label; $lblHMod.Text = "Module (optional):"; $lblHMod.Location = New-Object System.Drawing.Point(12,54); $lblHMod.Size = New-Object System.Drawing.Size(150,18); $gbHook.Controls.Add($lblHMod)
$txtHookMod = New-Object System.Windows.Forms.TextBox; $txtHookMod.Location = New-Object System.Drawing.Point(170,51); $txtHookMod.Size = New-Object System.Drawing.Size(200,24); $txtHookMod.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbHook.Controls.Add($txtHookMod)
$lblHRet = New-Object System.Windows.Forms.Label; $lblHRet.Text = "Return value:"; $lblHRet.Location = New-Object System.Drawing.Point(12,82); $lblHRet.Size = New-Object System.Drawing.Size(90,18); $gbHook.Controls.Add($lblHRet)
$numHookRet = New-Object System.Windows.Forms.NumericUpDown; $numHookRet.Location = New-Object System.Drawing.Point(104,79); $numHookRet.Size = New-Object System.Drawing.Size(70,24); $numHookRet.Minimum = 0; $numHookRet.Maximum = 2147483647; $numHookRet.Value = 1; $gbHook.Controls.Add($numHookRet)
$chkHookSkip = New-Object System.Windows.Forms.CheckBox; $chkHookSkip.Text = "Skip body"; $chkHookSkip.Location = New-Object System.Drawing.Point(190,81); $chkHookSkip.Size = New-Object System.Drawing.Size(90,20); $gbHook.Controls.Add($chkHookSkip)
$btnHookRun = New-Object System.Windows.Forms.Button; $btnHookRun.Text = "Force return (bypass check)"; $btnHookRun.Location = New-Object System.Drawing.Point(12,112); $btnHookRun.Size = New-Object System.Drawing.Size(220,28)
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
$gbCred.Text = "Windows stored credentials (Credential Manager)"
$gbCred.Location = New-Object System.Drawing.Point(598,36); $gbCred.Size = New-Object System.Drawing.Size(578,150)
$ctlB.Controls.Add($gbCred)
$lblCFilt = New-Object System.Windows.Forms.Label; $lblCFilt.Text = "Filter (optional target substring):"; $lblCFilt.Location = New-Object System.Drawing.Point(12,28); $lblCFilt.Size = New-Object System.Drawing.Size(190,18); $gbCred.Controls.Add($lblCFilt)
$txtCredFilter = New-Object System.Windows.Forms.TextBox; $txtCredFilter.Location = New-Object System.Drawing.Point(206,25); $txtCredFilter.Size = New-Object System.Drawing.Size(200,24); $txtCredFilter.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbCred.Controls.Add($txtCredFilter)
$chkCredReveal = New-Object System.Windows.Forms.CheckBox; $chkCredReveal.Text = "Reveal secrets (default masks)"; $chkCredReveal.Location = New-Object System.Drawing.Point(12,54); $chkCredReveal.Size = New-Object System.Drawing.Size(260,20); $gbCred.Controls.Add($chkCredReveal)
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
$gbLive.Text = "Credential liveness (replay a recovered credential against a live service)"
$gbLive.Location = New-Object System.Drawing.Point(10,192); $gbLive.Size = New-Object System.Drawing.Size(1166,118)
$ctlB.Controls.Add($gbLive)
$lblLProto = New-Object System.Windows.Forms.Label; $lblLProto.Text = "Protocol:"; $lblLProto.Location = New-Object System.Drawing.Point(12,26); $lblLProto.Size = New-Object System.Drawing.Size(58,18); $gbLive.Controls.Add($lblLProto)
$cmbLiveProto = New-Object System.Windows.Forms.ComboBox; $cmbLiveProto.Location = New-Object System.Drawing.Point(72,23); $cmbLiveProto.Size = New-Object System.Drawing.Size(72,24); $cmbLiveProto.DropDownStyle = 'DropDownList'
@('http','sql','ftp') | ForEach-Object { [void]$cmbLiveProto.Items.Add($_) }; $cmbLiveProto.SelectedIndex = 0; $gbLive.Controls.Add($cmbLiveProto)
$lblLTgt = New-Object System.Windows.Forms.Label; $lblLTgt.Text = "Target (URL / host / ftp://):"; $lblLTgt.Location = New-Object System.Drawing.Point(160,26); $lblLTgt.Size = New-Object System.Drawing.Size(160,18); $gbLive.Controls.Add($lblLTgt)
$txtLiveTarget = New-Object System.Windows.Forms.TextBox; $txtLiveTarget.Location = New-Object System.Drawing.Point(322,23); $txtLiveTarget.Size = New-Object System.Drawing.Size(820,24); $txtLiveTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLiveTarget.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right); $gbLive.Controls.Add($txtLiveTarget)
$lblLUser = New-Object System.Windows.Forms.Label; $lblLUser.Text = "User:"; $lblLUser.Location = New-Object System.Drawing.Point(12,56); $lblLUser.Size = New-Object System.Drawing.Size(40,18); $gbLive.Controls.Add($lblLUser)
$txtLiveUser = New-Object System.Windows.Forms.TextBox; $txtLiveUser.Location = New-Object System.Drawing.Point(54,53); $txtLiveUser.Size = New-Object System.Drawing.Size(150,24); $gbLive.Controls.Add($txtLiveUser)
$lblLPass = New-Object System.Windows.Forms.Label; $lblLPass.Text = "Pass:"; $lblLPass.Location = New-Object System.Drawing.Point(216,56); $lblLPass.Size = New-Object System.Drawing.Size(40,18); $gbLive.Controls.Add($lblLPass)
$txtLivePass = New-Object System.Windows.Forms.TextBox; $txtLivePass.Location = New-Object System.Drawing.Point(258,53); $txtLivePass.Size = New-Object System.Drawing.Size(150,24); $txtLivePass.UseSystemPasswordChar = $true; $gbLive.Controls.Add($txtLivePass)
$lblLExtra = New-Object System.Windows.Forms.Label; $lblLExtra.Text = "Bearer / DB:"; $lblLExtra.Location = New-Object System.Drawing.Point(420,56); $lblLExtra.Size = New-Object System.Drawing.Size(78,18); $gbLive.Controls.Add($lblLExtra)
$txtLiveExtra = New-Object System.Windows.Forms.TextBox; $txtLiveExtra.Location = New-Object System.Drawing.Point(500,53); $txtLiveExtra.Size = New-Object System.Drawing.Size(150,24); $gbLive.Controls.Add($txtLiveExtra)
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
    }
}

$tabRt = New-Object System.Windows.Forms.TabPage
$tabRt.Text = '  Runtime / Live  '
$tabRt.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabRt)

# Process-selector row (Dock=Top)
$rtTop = New-Object System.Windows.Forms.Panel
$rtTop.Dock = 'Top'; $rtTop.Height = 66; $rtTop.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$lblRtProc = New-Object System.Windows.Forms.Label
$lblRtProc.Text = "Process:"; $lblRtProc.Location = New-Object System.Drawing.Point(12,10); $lblRtProc.Size = New-Object System.Drawing.Size(56,18)
$rtTop.Controls.Add($lblRtProc)
$txtRtProc = New-Object System.Windows.Forms.ComboBox
$txtRtProc.Location = New-Object System.Drawing.Point(70,7); $txtRtProc.Size = New-Object System.Drawing.Size(220,24); $txtRtProc.DropDownStyle = 'DropDown'
$rtTop.Controls.Add($txtRtProc)
$btnRtRefresh = New-Object System.Windows.Forms.Button
$btnRtRefresh.Text = "Refresh"; $btnRtRefresh.Location = New-Object System.Drawing.Point(296,6); $btnRtRefresh.Size = New-Object System.Drawing.Size(74,26)
$rtTop.Controls.Add($btnRtRefresh)
$btnRtRefresh.Add_Click({
    $sel = $txtRtProc.Text
    $txtRtProc.Items.Clear()
    try { Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique | Sort-Object | ForEach-Object { [void]$txtRtProc.Items.Add($_) } } catch {}
    if ($sel) { $txtRtProc.Text = $sel }
})
$lblRtSec = New-Object System.Windows.Forms.Label
$lblRtSec.Text = "Trace capture (s):"; $lblRtSec.Location = New-Object System.Drawing.Point(384,10); $lblRtSec.Size = New-Object System.Drawing.Size(108,18)
$rtTop.Controls.Add($lblRtSec)
$numRtSec = New-Object System.Windows.Forms.NumericUpDown
$numRtSec.Location = New-Object System.Drawing.Point(494,7); $numRtSec.Size = New-Object System.Drawing.Size(60,24); $numRtSec.Minimum = 5; $numRtSec.Maximum = 300; $numRtSec.Value = 30
$rtTop.Controls.Add($numRtSec)
$lblRtHint = New-Object System.Windows.Forms.Label
$lblRtHint.Text = "read-only. Process checks use the process above; System-wide ignore it; Target-path use the Target box up top."
$lblRtHint.Location = New-Object System.Drawing.Point(566,10); $lblRtHint.Size = New-Object System.Drawing.Size(600,18)
$lblRtHint.ForeColor = [System.Drawing.Color]::FromArgb(86,101,115)
$lblRtHint.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$rtTop.Controls.Add($lblRtHint)
# Authorization gate for the ACTIVE (gated) tools -- the red buttons below. Read-only checks
# do not need it. Ticking it also calls Enable-TcpkExploit before the gated tool runs.
$chkRtGate = New-Object System.Windows.Forms.CheckBox
$chkRtGate.Text = "I am authorized to test this target -- enable the active (gated) tools (red buttons)"
$chkRtGate.Location = New-Object System.Drawing.Point(12,40); $chkRtGate.Size = New-Object System.Drawing.Size(620,20)
$rtTop.Controls.Add($chkRtGate)
# Clear the output console (findings accumulate as you run checks).
$btnRtClear = New-Object System.Windows.Forms.Button
$btnRtClear.Text = "Clear output"; $btnRtClear.Location = New-Object System.Drawing.Point(660,37); $btnRtClear.Size = New-Object System.Drawing.Size(110,26); $btnRtClear.FlatStyle = 'Flat'
$rtTop.Controls.Add($btnRtClear)
$tabRt.Controls.Add($rtTop)

# Button grid (Dock=Top). kind: proc / trace / sys / path -- colour-coded.
$rtBtnPanel = New-Object System.Windows.Forms.Panel
$rtBtnPanel.Dock = 'Top'; $rtBtnPanel.Height = 120; $rtBtnPanel.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$rtRed = [System.Drawing.Color]::FromArgb(240,208,208)
$rtGrey = [System.Drawing.Color]::FromArgb(230,230,230)
$rtColour = @{ proc = $rtGrey; mem = $rtGrey; trace = [System.Drawing.Color]::FromArgb(255,235,205); sys = [System.Drawing.Color]::FromArgb(220,235,245); path = [System.Drawing.Color]::FromArgb(225,245,225); 'gui-unlock' = $rtRed; 'pipe-probe' = $rtRed; 'flag-flip' = $rtRed; 'input-fuzz' = $rtRed }
$rtSpecs = @(
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
    @{ T='GUI Unlock';        Fn='';                                K='gui-unlock' }
    @{ T='Pipe Probe';        Fn='';                                K='pipe-probe' }
    @{ T='Flag-Flip';         Fn='';                                K='flag-flip' }
    @{ T='Input Fuzz...';     Fn='';                                K='input-fuzz' }
)
$rx = 10; $ry = 10; $rcol = 0
foreach ($s in $rtSpecs) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $s.T; $b.Size = New-Object System.Drawing.Size(180,30)
    $b.Location = New-Object System.Drawing.Point($rx,$ry)
    $b.BackColor = $rtColour[$s.K]; $b.FlatStyle = 'Flat'
    $b.Add_Click([scriptblock]::Create("Invoke-RtCheck '$($s.Fn)' '$($s.K)'"))
    $rtBtnPanel.Controls.Add($b)
    $rcol++
    if ($rcol -ge 8) { $rcol = 0; $rx = 10; $ry += 36 } else { $rx += 186 }
}
$tabRt.Controls.Add($rtBtnPanel)

$txtRt = New-Object System.Windows.Forms.RichTextBox
$txtRt.Dock = 'Fill'; $txtRt.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtRt.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $txtRt.ForeColor = [System.Drawing.Color]::White
$txtRt.ReadOnly = $true; $txtRt.WordWrap = $false
$txtRt.Text = "Runtime / live-process analysis.`r`n`r`nPick the target process (Refresh lists what's running), then click a check:`r`n  grey  = read-only process checks (modules, ports, token, mitigations, DACL, env, mem secrets, handles, windows, memory)`r`n  amber = DLL Hijack Trace -- ETW capture for N seconds; exercise the app during the window (needs admin)`r`n  blue  = system-wide (named pipes, ALPC/mailslots)`r`n  green = target-path checks (COM / named objects / RPC) -- use the Target box at the top`r`n  red   = ACTIVE / gated tools (GUI unlock, pipe probe, flag-flip, input fuzz) -- tick the authorization box first`r`n`r`nFindings stream here, severity-coloured."
$tabRt.Controls.Add($txtRt)
$txtRt.BringToFront()
$btnRtClear.Add_Click({
    $txtRt.Clear()
    $txtRt.SelectionColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
    $txtRt.AppendText("(output cleared -- click a check to run again)`r`n")
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
    if ($asar.Length -gt 400MB) { return @{ error = "asar too large ($([int]($asar.Length/1MB)) MB)" } }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($asar.FullName)
        if ($bytes.Length -lt 16) { return @{ error = 'asar invalid' } }
        $headerObjSize = [System.BitConverter]::ToUInt32($bytes, 4)
        $jsonSize = [System.BitConverter]::ToUInt32($bytes, 12)
        if (($jsonSize + 16) -gt $bytes.Length) { return @{ error = 'asar header invalid' } }
        $tree = [System.Text.Encoding]::UTF8.GetString($bytes, 16, $jsonSize) | ConvertFrom-Json
        $base = 8 + $headerObjSize
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-asar-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $files = New-Object System.Collections.Generic.List[object]
        $stack = New-Object System.Collections.Generic.Stack[object]
        $stack.Push([pscustomobject]@{ node = $tree; rel = '' })
        $total = [int64]0; $cap = [int64]200MB
        while ($stack.Count) {
            $cur = $stack.Pop()
            if (-not $cur.node.files) { continue }
            foreach ($prop in $cur.node.files.PSObject.Properties) {
                $child = $prop.Value
                $childRel = if ($cur.rel) { "$($cur.rel)/$($prop.Name)" } else { "$($prop.Name)" }
                if ($child.files) { $stack.Push([pscustomobject]@{ node = $child; rel = $childRel }); continue }
                if ($null -eq $child.offset) { continue }
                $sz = [int64]$child.size; $off = $base + [int64]$child.offset
                if ($sz -lt 0 -or ($off + $sz) -gt $bytes.Length) { continue }
                if (($total + $sz) -gt $cap -or $files.Count -ge 8000) { continue }
                $dest = Join-Path $outDir ($childRel -replace '/', '\')
                $ddir = Split-Path -Parent $dest
                if ($ddir -and -not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                $buf = New-Object 'byte[]' $sz
                if ($sz -gt 0) { [System.Array]::Copy($bytes, $off, $buf, 0, $sz) }
                [System.IO.File]::WriteAllBytes($dest, $buf)
                $files.Add([pscustomobject]@{ path = $childRel; size = $sz; full = $dest })
                $total += $sz
            }
        }
        return @{ outDir = $outDir; bytes = $total; files = @($files.ToArray() | Sort-Object path) }
    } catch { return @{ error = "$($_.Exception.Message)" } }
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
$tabAsar.Text = '  Asar  '
$tabAsar.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabAsar)

# Top bar built from TableLayoutPanel rows so the path box stretches and the buttons stay
# right-aligned at ANY window width (absolute positions left a dead gap when maximized).
$asarTop = New-Object System.Windows.Forms.Panel
$asarTop.Dock = 'Top'; $asarTop.Height = 70; $asarTop.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$asarAnchLR = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

$asarRow1 = New-Object System.Windows.Forms.TableLayoutPanel
$asarRow1.Dock = 'Top'; $asarRow1.Height = 40; $asarRow1.ColumnCount = 6; $asarRow1.RowCount = 1
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 164)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 100)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$asarRow1.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 108)))

$lblAsarT = New-Object System.Windows.Forms.Label
$lblAsarT.Text = "app.asar / install folder:"; $lblAsarT.Dock = 'Fill'; $lblAsarT.TextAlign = 'MiddleLeft'
$lblAsarT.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$asarRow1.Controls.Add($lblAsarT, 0, 0)

$txtAsarTarget = New-Object System.Windows.Forms.TextBox
$txtAsarTarget.Anchor = $asarAnchLR; $txtAsarTarget.Margin = New-Object System.Windows.Forms.Padding(2, 8, 6, 0)
$txtAsarTarget.Font = New-Object System.Drawing.Font('Consolas', 9)
$asarRow1.Controls.Add($txtAsarTarget, 1, 0)

$btnAsarBrowse = New-Object System.Windows.Forms.Button
$btnAsarBrowse.Text = "Browse..."; $btnAsarBrowse.Dock = 'Fill'; $btnAsarBrowse.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$asarRow1.Controls.Add($btnAsarBrowse, 2, 0)

$btnAsarExtract = New-Object System.Windows.Forms.Button
$btnAsarExtract.Text = "Extract"; $btnAsarExtract.Dock = 'Fill'; $btnAsarExtract.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$btnAsarExtract.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnAsarExtract.ForeColor = [System.Drawing.Color]::White; $btnAsarExtract.FlatStyle = 'Flat'
$btnAsarExtract.Tag = 'keep'
$asarRow1.Controls.Add($btnAsarExtract, 3, 0)

$btnAsarHex = New-Object System.Windows.Forms.Button
$btnAsarHex.Text = "Hex view"; $btnAsarHex.Dock = 'Fill'; $btnAsarHex.Margin = New-Object System.Windows.Forms.Padding(2, 6, 2, 6)
$asarRow1.Controls.Add($btnAsarHex, 4, 0)

# npm supply-chain audit of the bundled Electron packages (OSV CVEs + deprecated flags).
$btnAsarNpm = New-Object System.Windows.Forms.Button
$btnAsarNpm.Text = "npm audit"; $btnAsarNpm.Dock = 'Fill'; $btnAsarNpm.Margin = New-Object System.Windows.Forms.Padding(2, 6, 8, 6)
$btnAsarNpm.BackColor = [System.Drawing.Color]::FromArgb(23, 111, 130); $btnAsarNpm.ForeColor = [System.Drawing.Color]::White; $btnAsarNpm.FlatStyle = 'Flat'
$asarRow1.Controls.Add($btnAsarNpm, 5, 0)

$asarRow2 = New-Object System.Windows.Forms.Panel
$asarRow2.Dock = 'Top'; $asarRow2.Height = 26
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
            }
        } $t (Split-Path -Leaf $t)
        $txtAsarView.Text = "$($out.report)"
        $txtAsarView.SelectionStart = 0; $txtAsarView.ScrollToCaret()
        $lblAsar.Text = "npm audit done: $($out.pkgs) packages, $($out.vulns) vulnerabilities, $($out.dep) deprecated."
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
function Get-GuiHexText([string]$path, [int64]$offset, [int]$length) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($length -le 0 -or $length -gt 16384) { $length = 4096 }
    if ($offset -lt 0) { $offset = 0 }
    $fi = Get-Item -LiteralPath $path; $total = [int64]$fi.Length
    if ($offset -ge $total) { return @{ text = ''; size = $total; offset = $offset } }
    $count = [int][Math]::Min([int64]$length, $total - $offset)
    $buf = New-Object 'byte[]' $count
    $fsr = [System.IO.File]::OpenRead($path)
    try { [void]$fsr.Seek($offset, 'Begin'); [void]$fsr.Read($buf, 0, $count) } finally { $fsr.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $count; $i += 16) {
        $n = [Math]::Min(16, $count - $i)
        [void]$sb.Append(('{0:x8}  ' -f ($offset + $i)))
        $asc = New-Object System.Text.StringBuilder
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -lt $n) { $bv = $buf[$i + $j]; [void]$sb.Append(('{0:x2} ' -f $bv)); $ch = if ($bv -ge 32 -and $bv -lt 127) { [char]$bv } else { '.' }; [void]$asc.Append($ch) }
            else { [void]$sb.Append('   ') }
            if ($j -eq 7) { [void]$sb.Append(' ') }
        }
        [void]$sb.Append(' |').Append($asc.ToString()).Append("|`r`n")
    }
    return @{ text = $sb.ToString(); size = $total; offset = $offset; count = $count }
}
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
    if ((Get-Item -LiteralPath $path).Length -gt 300MB) { return [int64]-2 }
    $needle = $null
    if ($kind -eq 'hex') {
        $hx = ($query -replace '[^0-9a-fA-F]', ''); if ($hx.Length -lt 2 -or ($hx.Length % 2)) { return [int64]-3 }
        $needle = [byte[]](0..(($hx.Length / 2) - 1) | ForEach-Object { [Convert]::ToByte($hx.Substring($_ * 2, 2), 16) })
    } else { $needle = [System.Text.Encoding]::ASCII.GetBytes($query) }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $nlen = $needle.Length; if (-not $nlen) { return [int64]-1 }
    $lim = $bytes.Length - $nlen
    for ($i = [int]([Math]::Max([int64]0, $from)); $i -le $lim; $i++) {
        $ok = $true; for ($j = 0; $j -lt $nlen; $j++) { if ($bytes[$i + $j] -ne $needle[$j]) { $ok = $false; break } }
        if ($ok) { return [int64]$i }
    }
    return [int64]-1
}
# Extract printable ASCII + UTF-16LE ("wide") strings with their byte offsets, so a name /
# URL / path can be clicked to jump into the hex view. $filter narrows (case-insensitive
# substring) -- the "find a name" case. Regex over a Latin1 view keeps every offset exact.
function Get-GuiHexStrings([string]$path, [int]$min, [string]$filter, [string]$kind, [int]$cap) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return @{ error = 'file not found' } }
    if ((Get-Item -LiteralPath $path).Length -gt 300MB) { return @{ error = 'file too large to scan' } }
    if ($min -lt 2) { $min = 2 } elseif ($min -gt 200) { $min = 200 }
    if ($cap -lt 1) { $cap = 1 } elseif ($cap -gt 20000) { $cap = 20000 }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)   # Latin1: 1 byte <-> 1 char
    $flt = "$filter"
    $cmp = [System.StringComparison]::OrdinalIgnoreCase
    $hits = New-Object System.Collections.Generic.List[object]
    $total = 0
    if ($kind -eq 'both' -or $kind -eq 'ascii') {
        foreach ($m in ([regex]::Matches($text, "[\x20-\x7E]{$min,}"))) {
            $v = $m.Value
            if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
            $total++
            if ($hits.Count -lt $cap) { if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }; $hits.Add([pscustomobject]@{ offset = [int64]$m.Index; kind = 'a'; text = $v }) }
        }
    }
    if ($kind -eq 'both' -or $kind -eq 'wide') {
        foreach ($m in ([regex]::Matches($text, "(?:[\x20-\x7E]\x00){$min,}"))) {
            $v = [System.Text.Encoding]::Unicode.GetString($bytes, $m.Index, $m.Length)
            if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
            $total++
            if ($hits.Count -lt $cap) { if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }; $hits.Add([pscustomobject]@{ offset = [int64]$m.Index; kind = 'w'; text = $v }) }
        }
    }
    $items = @($hits | Sort-Object offset)
    return @{ items = $items; total = $total; capped = [bool]($total -gt $items.Count) }
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
    $lvHexStr.Visible = $true; $lvHexStr.BeginUpdate(); $lvHexStr.Items.Clear()
    foreach ($x in $r.items) {
        $it = New-Object System.Windows.Forms.ListViewItem("0x$([Convert]::ToString([int64]$x.offset,16))")
        [void]$it.SubItems.Add($x.kind); [void]$it.SubItems.Add($x.text); $it.Tag = [int64]$x.offset
        [void]$lvHexStr.Items.Add($it)
    }
    $lvHexStr.EndUpdate()
    $lblHexSInfo.Text = "$($r.total) match$(if($r.total -eq 1){''}else{'es'})$(if($r.capped){" (showing first $($r.items.Count))"}else{''})"
}
function Load-GuiHex([int64]$off) {
    $p = $txtHexPath.Text.Trim(); if (-not $p) { $lblHex.Text = 'enter a file path'; return }
    if ($off -lt 0) { $off = 0 }
    $r = Get-GuiHexRtf $p $off $script:HexPageSize
    if ($r.error) { $lblHex.Text = "Error: $($r.error)"; $txtHex.Text = ''; return }
    $script:HexPath = $p; $script:HexOffset = $off; $script:HexSize = $r.size
    if ($r.rtf) { $txtHex.Rtf = $r.rtf } else { $txtHex.Text = '' }
    $lblHex.Text = "$(Split-Path $p -Leaf) -- $($r.size) bytes, offset 0x$([Convert]::ToString($off,16)) ($($r.count) shown)"
    # highlight the row holding $script:HexHl (if it falls in this page)
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

$tabHex = New-Object System.Windows.Forms.TabPage
$tabHex.Text = '  Hex View  '
$tabHex.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabHex)
$hexTop = New-Object System.Windows.Forms.Panel
$hexTop.Dock = 'Top'; $hexTop.Height = 96; $hexTop.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$lblHexT = New-Object System.Windows.Forms.Label
$lblHexT.Text = "File:"; $lblHexT.Location = New-Object System.Drawing.Point(12, 14); $lblHexT.Size = New-Object System.Drawing.Size(40, 18)
$hexTop.Controls.Add($lblHexT)
$txtHexPath = New-Object System.Windows.Forms.TextBox
$txtHexPath.Location = New-Object System.Drawing.Point(54, 11); $txtHexPath.Size = New-Object System.Drawing.Size(600, 24); $txtHexPath.Font = New-Object System.Drawing.Font('Consolas', 9)
$hexTop.Controls.Add($txtHexPath)
$btnHexBrowse = New-Object System.Windows.Forms.Button
$btnHexBrowse.Text = "Browse..."; $btnHexBrowse.Location = New-Object System.Drawing.Point(662, 10); $btnHexBrowse.Size = New-Object System.Drawing.Size(80, 26)
$hexTop.Controls.Add($btnHexBrowse)
$btnHexLoad = New-Object System.Windows.Forms.Button
$btnHexLoad.Text = "Load"; $btnHexLoad.Location = New-Object System.Drawing.Point(748, 10); $btnHexLoad.Size = New-Object System.Drawing.Size(64, 26)
$btnHexLoad.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnHexLoad.ForeColor = [System.Drawing.Color]::White; $btnHexLoad.FlatStyle = 'Flat'
$hexTop.Controls.Add($btnHexLoad)
# Row 2 (y=42): paging + go-to + find
$btnHexPrev = New-Object System.Windows.Forms.Button
$btnHexPrev.Text = "< Prev"; $btnHexPrev.Location = New-Object System.Drawing.Point(12, 42); $btnHexPrev.Size = New-Object System.Drawing.Size(64, 26)
$hexTop.Controls.Add($btnHexPrev)
$btnHexNext = New-Object System.Windows.Forms.Button
$btnHexNext.Text = "Next >"; $btnHexNext.Location = New-Object System.Drawing.Point(80, 42); $btnHexNext.Size = New-Object System.Drawing.Size(64, 26)
$hexTop.Controls.Add($btnHexNext)
$lblHexGoto = New-Object System.Windows.Forms.Label
$lblHexGoto.Text = "go to (hex):"; $lblHexGoto.Location = New-Object System.Drawing.Point(158, 47); $lblHexGoto.Size = New-Object System.Drawing.Size(74, 18)
$hexTop.Controls.Add($lblHexGoto)
$txtHexGoto = New-Object System.Windows.Forms.TextBox
$txtHexGoto.Location = New-Object System.Drawing.Point(232, 44); $txtHexGoto.Size = New-Object System.Drawing.Size(90, 22); $txtHexGoto.Font = New-Object System.Drawing.Font('Consolas', 9)
$hexTop.Controls.Add($txtHexGoto)
$btnHexGo = New-Object System.Windows.Forms.Button
$btnHexGo.Text = "Go"; $btnHexGo.Location = New-Object System.Drawing.Point(326, 42); $btnHexGo.Size = New-Object System.Drawing.Size(50, 26)
$hexTop.Controls.Add($btnHexGo)
$lblHexFind = New-Object System.Windows.Forms.Label
$lblHexFind.Text = "find:"; $lblHexFind.Location = New-Object System.Drawing.Point(392, 47); $lblHexFind.Size = New-Object System.Drawing.Size(34, 18)
$hexTop.Controls.Add($lblHexFind)
$txtHexFind = New-Object System.Windows.Forms.TextBox
$txtHexFind.Location = New-Object System.Drawing.Point(426, 44); $txtHexFind.Size = New-Object System.Drawing.Size(160, 22); $txtHexFind.Font = New-Object System.Drawing.Font('Consolas', 9)
$hexTop.Controls.Add($txtHexFind)
$cmbHexKind = New-Object System.Windows.Forms.ComboBox
$cmbHexKind.Location = New-Object System.Drawing.Point(592, 44); $cmbHexKind.Size = New-Object System.Drawing.Size(70, 24); $cmbHexKind.DropDownStyle = 'DropDownList'
@('ascii', 'hex') | ForEach-Object { [void]$cmbHexKind.Items.Add($_) }; $cmbHexKind.SelectedIndex = 0
$hexTop.Controls.Add($cmbHexKind)
$btnHexFind = New-Object System.Windows.Forms.Button
$btnHexFind.Text = "Find next"; $btnHexFind.Location = New-Object System.Drawing.Point(668, 42); $btnHexFind.Size = New-Object System.Drawing.Size(84, 26)
$hexTop.Controls.Add($btnHexFind)
# Strings controls -- placed on row 2 (y=42), in the empty space to the RIGHT of "Find next".
# List printable ASCII/wide strings (names, URLs, paths), filterable.
$hexSep = New-Object System.Windows.Forms.Label
$hexSep.Text = ''; $hexSep.Location = New-Object System.Drawing.Point(766, 44); $hexSep.Size = New-Object System.Drawing.Size(2, 26); $hexSep.BackColor = [System.Drawing.Color]::FromArgb(205, 205, 205)
$hexTop.Controls.Add($hexSep)
$lblHexSMinL = New-Object System.Windows.Forms.Label
$lblHexSMinL.Text = "strings min:"; $lblHexSMinL.Location = New-Object System.Drawing.Point(782, 47); $lblHexSMinL.Size = New-Object System.Drawing.Size(72, 18)
$hexTop.Controls.Add($lblHexSMinL)
$txtHexSMin = New-Object System.Windows.Forms.TextBox
$txtHexSMin.Text = "4"; $txtHexSMin.Location = New-Object System.Drawing.Point(856, 44); $txtHexSMin.Size = New-Object System.Drawing.Size(40, 22); $txtHexSMin.Font = New-Object System.Drawing.Font('Consolas', 9)
$hexTop.Controls.Add($txtHexSMin)
$lblHexSFilterL = New-Object System.Windows.Forms.Label
$lblHexSFilterL.Text = "filter:"; $lblHexSFilterL.Location = New-Object System.Drawing.Point(902, 47); $lblHexSFilterL.Size = New-Object System.Drawing.Size(40, 18)
$hexTop.Controls.Add($lblHexSFilterL)
$txtHexSFilter = New-Object System.Windows.Forms.TextBox
$txtHexSFilter.Location = New-Object System.Drawing.Point(942, 44); $txtHexSFilter.Size = New-Object System.Drawing.Size(150, 22); $txtHexSFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
$hexTop.Controls.Add($txtHexSFilter)
$cmbHexSKind = New-Object System.Windows.Forms.ComboBox
$cmbHexSKind.Location = New-Object System.Drawing.Point(1098, 44); $cmbHexSKind.Size = New-Object System.Drawing.Size(100, 24); $cmbHexSKind.DropDownStyle = 'DropDownList'
@('ascii+wide', 'ascii', 'wide') | ForEach-Object { [void]$cmbHexSKind.Items.Add($_) }; $cmbHexSKind.SelectedIndex = 0
$hexTop.Controls.Add($cmbHexSKind)
$btnHexStrings = New-Object System.Windows.Forms.Button
$btnHexStrings.Text = "List strings"; $btnHexStrings.Location = New-Object System.Drawing.Point(1204, 42); $btnHexStrings.Size = New-Object System.Drawing.Size(96, 26)
$hexTop.Controls.Add($btnHexStrings)
$lblHexSInfo = New-Object System.Windows.Forms.Label
$lblHexSInfo.Location = New-Object System.Drawing.Point(1306, 47); $lblHexSInfo.Size = New-Object System.Drawing.Size(260, 18); $lblHexSInfo.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexTop.Controls.Add($lblHexSInfo)
$lblHex = New-Object System.Windows.Forms.Label
$lblHex.Location = New-Object System.Drawing.Point(12, 74); $lblHex.Size = New-Object System.Drawing.Size(1030, 18)
$lblHex.Text = "Enter a file path (a native DLL, or a file from an extracted asar), then Load. Go to an offset, find a hex/ASCII pattern, list strings, or click a row to inspect."
$lblHex.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$hexTop.Controls.Add($lblHex)
$tabHex.Controls.Add($hexTop)

# Body: hex view (Fill) on the left + Data Inspector (Dock=Right) -- nested in a Fill container
# so the top strip spans the full width.
$hexBody = New-Object System.Windows.Forms.Panel
$hexBody.Dock = 'Fill'
$hexInsPanel = New-Object System.Windows.Forms.Panel
$hexInsPanel.Dock = 'Right'; $hexInsPanel.Width = 300; $hexInsPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$hexInsTop = New-Object System.Windows.Forms.Panel
$hexInsTop.Dock = 'Top'; $hexInsTop.Height = 84; $hexInsTop.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$lblHexInsHdr = New-Object System.Windows.Forms.Label
$lblHexInsHdr.Text = "DATA INSPECTOR"; $lblHexInsHdr.Location = New-Object System.Drawing.Point(8, 6); $lblHexInsHdr.Size = New-Object System.Drawing.Size(200, 16); $lblHexInsHdr.ForeColor = [System.Drawing.Color]::FromArgb(200, 205, 210); $lblHexInsHdr.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$hexInsTop.Controls.Add($lblHexInsHdr)
$lblHexInsOff = New-Object System.Windows.Forms.Label
$lblHexInsOff.Text = "offset 0x0"; $lblHexInsOff.Location = New-Object System.Drawing.Point(8, 26); $lblHexInsOff.Size = New-Object System.Drawing.Size(200, 16); $lblHexInsOff.ForeColor = [System.Drawing.Color]::FromArgb(78, 201, 176)
$hexInsTop.Controls.Add($lblHexInsOff)
$lblHexInsIn2 = New-Object System.Windows.Forms.Label
$lblHexInsIn2.Text = "offset (hex):"; $lblHexInsIn2.Location = New-Object System.Drawing.Point(8, 54); $lblHexInsIn2.Size = New-Object System.Drawing.Size(80, 16); $lblHexInsIn2.ForeColor = [System.Drawing.Color]::FromArgb(180, 185, 190)
$hexInsTop.Controls.Add($lblHexInsIn2)
$txtHexInsIn = New-Object System.Windows.Forms.TextBox
$txtHexInsIn.Location = New-Object System.Drawing.Point(90, 51); $txtHexInsIn.Size = New-Object System.Drawing.Size(90, 22); $txtHexInsIn.Font = New-Object System.Drawing.Font('Consolas', 9); $txtHexInsIn.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48); $txtHexInsIn.ForeColor = [System.Drawing.Color]::White; $txtHexInsIn.BorderStyle = 'FixedSingle'
$hexInsTop.Controls.Add($txtHexInsIn)
$btnHexInspect = New-Object System.Windows.Forms.Button
$btnHexInspect.Text = "Inspect"; $btnHexInspect.Location = New-Object System.Drawing.Point(188, 50); $btnHexInspect.Size = New-Object System.Drawing.Size(84, 24); $btnHexInspect.FlatStyle = 'Flat'; $btnHexInspect.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
$hexInsTop.Controls.Add($btnHexInspect)
$hexInsPanel.Controls.Add($hexInsTop)
$lvHexIns = New-Object System.Windows.Forms.ListView
$lvHexIns.Dock = 'Fill'; $lvHexIns.View = 'Details'; $lvHexIns.FullRowSelect = $true; $lvHexIns.GridLines = $false; $lvHexIns.HeaderStyle = 'Nonclickable'
$lvHexIns.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexIns.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexIns.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexIns.Columns.Add('Field', 110); [void]$lvHexIns.Columns.Add('Value', 168)
$hexInsPanel.Controls.Add($lvHexIns); $lvHexIns.BringToFront()
$hexBody.Controls.Add($hexInsPanel)
# Center column: hex view (Fill) + strings results (Bottom, hidden until "List strings").
$hexCenter = New-Object System.Windows.Forms.Panel
$hexCenter.Dock = 'Fill'
$lvHexStr = New-Object System.Windows.Forms.ListView
$lvHexStr.Dock = 'Bottom'; $lvHexStr.Height = 180; $lvHexStr.Visible = $false
$lvHexStr.View = 'Details'; $lvHexStr.FullRowSelect = $true; $lvHexStr.GridLines = $false; $lvHexStr.HeaderStyle = 'Nonclickable'; $lvHexStr.MultiSelect = $false
$lvHexStr.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24); $lvHexStr.ForeColor = [System.Drawing.Color]::FromArgb(214, 220, 228); $lvHexStr.Font = New-Object System.Drawing.Font('Consolas', 9)
[void]$lvHexStr.Columns.Add('Offset', 90); [void]$lvHexStr.Columns.Add('K', 34); [void]$lvHexStr.Columns.Add('String (click to jump)', 1200)
$hexCenter.Controls.Add($lvHexStr)
$txtHex = New-Object System.Windows.Forms.RichTextBox
$txtHex.Dock = 'Fill'; $txtHex.Font = New-Object System.Drawing.Font('Consolas', 9.5)
$txtHex.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18); $txtHex.ForeColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
$txtHex.ReadOnly = $true; $txtHex.WordWrap = $false; $txtHex.BorderStyle = 'None'; $txtHex.HideSelection = $false
$hexCenter.Controls.Add($txtHex); $txtHex.BringToFront()
$hexBody.Controls.Add($hexCenter); $hexCenter.BringToFront()
$tabHex.Controls.Add($hexBody); $hexBody.BringToFront()
$btnHexBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq 'OK') { $txtHexPath.Text = $dlg.FileName }
})
$btnHexLoad.Add_Click({ $script:HexHl = [int64]-1; Load-GuiHex 0 })
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
    if ($o -eq [int64]-2) { $lblHex.Text = 'file too large to search' }
    elseif ($o -eq [int64]-3) { $lblHex.Text = 'hex needs an even number of hex digits' }
    elseif ($o -lt 0) { $lblHex.Text = "no match from 0x$([Convert]::ToString($from,16))" }
    else { Do-GuiHexInspect $o; $lblHex.Text = "match at 0x$([Convert]::ToString($o,16))" }
})
$txtHex.Add_MouseUp({
    if (-not $script:HexPath) { return }
    try { $ci = $txtHex.GetCharIndexFromPosition($_.Location); $line = $txtHex.GetLineFromCharIndex($ci); $off = $script:HexOffset + ($line * 16); Do-GuiHexInspect $off } catch { }
})
$btnHexStrings.Add_Click({ Do-GuiHexStrings })
$lvHexStr.Add_Click({ if ($lvHexStr.SelectedItems.Count -and $null -ne $lvHexStr.SelectedItems[0].Tag) { Do-GuiHexInspect ([int64]$lvHexStr.SelectedItems[0].Tag) } })

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
$tabDec.Text = '  DLL Decompiler  '
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
$chkDecWrap = New-Object System.Windows.Forms.CheckBox; $chkDecWrap.Text = 'Wrap'; $chkDecWrap.Checked = $true; $chkDecWrap.Location = New-Object System.Drawing.Point(194, 5); $chkDecWrap.Size = New-Object System.Drawing.Size(60, 20)
$lblDecCodeHint = New-Object System.Windows.Forms.Label; $lblDecCodeHint.Text = 'IL via Mono.Cecil (always); C# needs ilspycmd on PATH'; $lblDecCodeHint.Location = New-Object System.Drawing.Point(262, 2); $lblDecCodeHint.Size = New-Object System.Drawing.Size(520, 24); $lblDecCodeHint.TextAlign = 'MiddleLeft'
$decCodeBar.Controls.Add($btnDecIl); $decCodeBar.Controls.Add($btnDecCs); $decCodeBar.Controls.Add($chkDecWrap); $decCodeBar.Controls.Add($lblDecCodeHint)
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

function Load-DecAssembly([string]$path) {
    if (-not (Ensure-DecCecil)) { $lblDecStatus.Text = 'Mono.Cecil not available (tools\ILSpy\Mono.Cecil.dll missing).'; return }
    $path = "$path".Trim('"').Trim()
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { $lblDecStatus.Text = "File not found: $path"; return }
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

function Show-DecIl {
    $m = $lstDecMethods.SelectedItem
    if (-not $m) { return }
    $script:DecCurMethod = $m
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// $($m.DeclaringType.FullName)::$($m.Name)")
    [void]$sb.AppendLine("// returns $($m.ReturnType.FullName)")
    if (-not $m.HasBody) {
        [void]$sb.AppendLine('// (no managed body -- abstract / extern / P-Invoke / interface)')
    } else {
        [void]$sb.AppendLine("// $($m.Body.Instructions.Count) IL instructions, $($m.Body.Variables.Count) locals")
        [void]$sb.AppendLine('')
        foreach ($ins in $m.Body.Instructions) {
            $op  = $ins.OpCode.Name
            $arg = if ($null -ne $ins.Operand) { " $($ins.Operand)" } else { '' }
            [void]$sb.AppendLine(("  IL_{0:X4}: {1,-11}{2}" -f $ins.Offset, $op, $arg))
            if ($sb.Length -gt 200000) { [void]$sb.AppendLine('  ... (truncated)'); break }
        }
    }
    $txtDecCode.Text = $sb.ToString(); $txtDecCode.SelectionStart = 0; $txtDecCode.ScrollToCaret()
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
    foreach ($f in $found) { [void]$cmbDecDll.Items.Add($f.FullName) }
    if ($found.Count) { $cmbDecDll.SelectedIndex = 0 }
    $lblDecStatus.Text = ("{0} assemblies under {1}{2}" -f $found.Count, $base, $(if ($found.Count -ge 800) { ' (capped at 800)' } else { '' }))
})
$btnDecLoad.Add_Click({ Load-DecAssembly $cmbDecDll.Text })
$cmbDecDll.Add_SelectedIndexChanged({ if ($cmbDecDll.SelectedItem) { Load-DecAssembly "$($cmbDecDll.SelectedItem)" } })
$txtDecFilter.Add_TextChanged({ Populate-DecTypes })
$lstDecTypes.Add_SelectedIndexChanged({
    $ty = $lstDecTypes.SelectedItem
    if (-not $ty) { return }
    $lstDecMethods.BeginUpdate(); $lstDecMethods.Items.Clear()
    try { foreach ($mm in $ty.Methods) { [void]$lstDecMethods.Items.Add($mm) } } catch { }
    $lstDecMethods.EndUpdate()
    $lblDecMethods.Text = ("Methods ({0})" -f $lstDecMethods.Items.Count)
})
$lstDecMethods.Add_SelectedIndexChanged({ Show-DecIl })
$btnDecIl.Add_Click({ Show-DecIl })
$btnDecCs.Add_Click({
    # Use the CURRENT method selection (belongs to the loaded assembly); fall back to the
    # last-shown method only if it matches the current selection state.
    $m = $lstDecMethods.SelectedItem; if (-not $m) { $m = $script:DecCurMethod }
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
$tabPmon.Text = '  Process Monitor  '
$tabPmon.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
[void]$tabs.TabPages.Add($tabPmon)

$script:PmonMode = 'live'
$script:PmonRunning = $false
$script:PmonPid = 0
$script:PmonSeenMod = $null; $script:PmonSeenConn = $null; $script:PmonSeenChild = $null
$script:PmonCaptureEnd = $null
$script:PmonTimer = New-Object System.Windows.Forms.Timer
$script:PmonTimer.Interval = 2000

$pmGreen = [System.Drawing.Color]::FromArgb(166, 226, 46)
$pmCyan  = [System.Drawing.Color]::FromArgb(102, 217, 239)
$pmYellow = [System.Drawing.Color]::FromArgb(214, 137, 16)
$pmGrey  = [System.Drawing.Color]::FromArgb(150, 150, 150)

$pmonTop = New-Object System.Windows.Forms.Panel
$pmonTop.Dock = 'Top'; $pmonTop.Height = 84; $pmonTop.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
# Row 1: mode buttons + process picker
$btnPmLive = New-Object System.Windows.Forms.Button
$btnPmLive.Text = "Live watch"; $btnPmLive.Location = New-Object System.Drawing.Point(12, 10); $btnPmLive.Size = New-Object System.Drawing.Size(110, 28); $btnPmLive.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmLive)
$btnPmCap = New-Object System.Windows.Forms.Button
$btnPmCap.Text = "Activity capture"; $btnPmCap.Location = New-Object System.Drawing.Point(126, 10); $btnPmCap.Size = New-Object System.Drawing.Size(130, 28); $btnPmCap.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmCap)
$lblPmProc = New-Object System.Windows.Forms.Label
$lblPmProc.Text = "Process:"; $lblPmProc.Location = New-Object System.Drawing.Point(284, 16); $lblPmProc.Size = New-Object System.Drawing.Size(56, 18)
$pmonTop.Controls.Add($lblPmProc)
$cmbPmProc = New-Object System.Windows.Forms.ComboBox
$cmbPmProc.Location = New-Object System.Drawing.Point(340, 12); $cmbPmProc.Size = New-Object System.Drawing.Size(260, 24); $cmbPmProc.DropDownStyle = 'DropDown'
$pmonTop.Controls.Add($cmbPmProc)
$btnPmRefresh = New-Object System.Windows.Forms.Button
$btnPmRefresh.Text = "Refresh"; $btnPmRefresh.Location = New-Object System.Drawing.Point(606, 11); $btnPmRefresh.Size = New-Object System.Drawing.Size(74, 26)
$pmonTop.Controls.Add($btnPmRefresh)
$lblPmFilter = New-Object System.Windows.Forms.Label
$lblPmFilter.Text = "Module filter:"; $lblPmFilter.Location = New-Object System.Drawing.Point(694, 16); $lblPmFilter.Size = New-Object System.Drawing.Size(82, 18)
$pmonTop.Controls.Add($lblPmFilter)
$txtPmonFilter = New-Object System.Windows.Forms.TextBox
$txtPmonFilter.Location = New-Object System.Drawing.Point(778, 12); $txtPmonFilter.Size = New-Object System.Drawing.Size(180, 24); $txtPmonFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
$pmonTop.Controls.Add($txtPmonFilter)
# Row 2: interval / duration + start + stop + status
$lblPmNum = New-Object System.Windows.Forms.Label
$lblPmNum.Text = "Refresh interval (s):"; $lblPmNum.Location = New-Object System.Drawing.Point(12, 51); $lblPmNum.Size = New-Object System.Drawing.Size(210, 18)
$pmonTop.Controls.Add($lblPmNum)
$numPmNum = New-Object System.Windows.Forms.NumericUpDown
$numPmNum.Location = New-Object System.Drawing.Point(226, 48); $numPmNum.Size = New-Object System.Drawing.Size(60, 24); $numPmNum.Minimum = 0; $numPmNum.Maximum = 3600; $numPmNum.Value = 2
$pmonTop.Controls.Add($numPmNum)
$btnPmStart = New-Object System.Windows.Forms.Button
$btnPmStart.Text = "Start"; $btnPmStart.Location = New-Object System.Drawing.Point(296, 47); $btnPmStart.Size = New-Object System.Drawing.Size(80, 28)
$btnPmStart.BackColor = [System.Drawing.Color]::FromArgb(39, 121, 78); $btnPmStart.ForeColor = [System.Drawing.Color]::White; $btnPmStart.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmStart)
$btnPmStop = New-Object System.Windows.Forms.Button
$btnPmStop.Text = "Stop"; $btnPmStop.Location = New-Object System.Drawing.Point(382, 47); $btnPmStop.Size = New-Object System.Drawing.Size(80, 28); $btnPmStop.Enabled = $false; $btnPmStop.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmStop)
$btnPmSave = New-Object System.Windows.Forms.Button
$btnPmSave.Text = "Save output..."; $btnPmSave.Location = New-Object System.Drawing.Point(470, 47); $btnPmSave.Size = New-Object System.Drawing.Size(104, 28); $btnPmSave.FlatStyle = 'Flat'
$pmonTop.Controls.Add($btnPmSave)
$lblPmStatus = New-Object System.Windows.Forms.Label
$lblPmStatus.Location = New-Object System.Drawing.Point(584, 52); $lblPmStatus.Size = New-Object System.Drawing.Size(540, 18); $lblPmStatus.ForeColor = [System.Drawing.Color]::FromArgb(86, 101, 115)
$lblPmStatus.Text = "Pick a mode, choose a process (Refresh), set the interval / duration, then Start."
$pmonTop.Controls.Add($lblPmStatus)
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
    } else {
        $btnPmCap.BackColor = [System.Drawing.Color]::FromArgb(40, 116, 166); $btnPmCap.ForeColor = [System.Drawing.Color]::White
        $btnPmLive.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230); $btnPmLive.ForeColor = [System.Drawing.Color]::Black
        $lblPmNum.Text = "Capture duration (s, 0=until Stop):"; $numPmNum.Value = 20
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
    $ci = $null; try { $ci = Get-CimInstance Win32_Process -Filter "ProcessId=$($script:PmonPid)" -ErrorAction SilentlyContinue } catch {}
    $ppid = ''; $cmd = ''; if ($ci) { $ppid = "$($ci.ParentProcessId)"; $cmd = "$($ci.CommandLine)" }
    $owner = ''; try { if ($ci) { $ow = $ci | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue; if ($ow -and $ow.User) { $owner = "$($ow.Domain)\$($ow.User)" } } } catch {}
    $started = '(n/a)'; try { $started = $p.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}
    $prio = '(n/a)'; try { $prio = "$($p.PriorityClass)" } catch {}
    $sess = '?'; try { $sess = "$($p.SessionId)" } catch {}
    $wsMB = [Math]::Round($p.WorkingSet64 / 1MB, 1); $prvMB = [Math]::Round($p.PrivateMemorySize64 / 1MB, 1)
    $peakMB = [Math]::Round($p.PeakWorkingSet64 / 1MB, 1); $vmMB = [Math]::Round($p.VirtualMemorySize64 / 1MB, 1)
    $cpu = 0; try { $cpu = [Math]::Round($p.CPU, 1) } catch {}
    $mods = @(); try { $mods = @($p.Modules) } catch {}
    $conns = @(); try { $conns = @(Get-NetTCPConnection -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue) } catch {}
    $kids = @(); try { $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($script:PmonPid)" -ErrorAction SilentlyContinue) } catch {}

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
    $mflt = ''; try { $mflt = $txtPmonFilter.Text.Trim() } catch {}
    if ($mflt) {
        $fl = $mflt.ToLower()
        $mods = @($mods | Where-Object { $s = ''; try { $s = "$($_.ModuleName) $($_.FileName)".ToLower() } catch { try { $s = "$($_.ModuleName)".ToLower() } catch {} }; $s.Contains($fl) })
    }
    $modHdr = if ($mflt) { "$($mods.Count) of $($modsAll.Count), filter: $mflt" } else { "$($mods.Count)" }
    # Show ALL modules (a real .NET app has a few hundred). A high safety cap only guards
    # against a pathological runaway -- normal processes never hit it.
    $modCap = 5000
    [void]$r.Append('\par\cf1\b MODULES (' + (Get-PmonRtfText $modHdr) + ')\b0\par ')
    foreach ($m in ($mods | Select-Object -First $modCap)) {
        $mn = ''; $mf = ''; try { $mn = "$($m.ModuleName)" } catch {}; try { $mf = "$($m.FileName)" } catch {}
        # Always keep a 2-space gap: when the name is longer than the column, the path would
        # otherwise butt straight up against it. The trailing "  " is inside cf4 (invisible).
        [void]$r.Append('\cf4     ' + (Get-PmonRtfText $mn).PadRight(38) + '  \cf5 ' + (Get-PmonRtfText $mf) + '\par ')
    }
    if ($mods.Count -gt $modCap) { [void]$r.Append('\cf5     ... ' + ($mods.Count - $modCap) + ' more\par ') }
    [void]$r.Append('\par\cf1\b NETWORK -- TCP (' + $conns.Count + ')\b0\par ')
    foreach ($c in ($conns | Select-Object -First 500)) {
        $stc = if ("$($c.State)" -eq 'Established') { 4 } else { 2 }
        [void]$r.Append('\cf3     ' + (Get-PmonRtfText "$($c.LocalAddress):$($c.LocalPort)") + '\cf5  -> \cf7 ' + (Get-PmonRtfText "$($c.RemoteAddress):$($c.RemotePort)") + '\cf' + $stc + '    ' + (Get-PmonRtfText "$($c.State)") + '\par ')
    }
    if (-not $conns.Count) { [void]$r.Append('\cf5     (none)\par ') }
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
    try { foreach ($m in $p.Modules) { $k = "$($m.FileName)"; if ($k -and -not $script:PmonSeenMod.Contains($k)) { [void]$script:PmonSeenMod.Add($k); Write-IcptLine $txtPmon ("[{0}] MODULE  {1}`r`n" -f $ts, $k) $pmGreen } } } catch {}
    try { foreach ($c in (Get-NetTCPConnection -OwningProcess $script:PmonPid -ErrorAction SilentlyContinue)) { $k = "$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)"; if (-not $script:PmonSeenConn.Contains($k)) { [void]$script:PmonSeenConn.Add($k); Write-IcptLine $txtPmon ("[{0}] TCP     {1}:{2} -> {3}:{4} [{5}]`r`n" -f $ts, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State) $pmCyan } } } catch {}
    try { foreach ($ch in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($script:PmonPid)" -ErrorAction SilentlyContinue)) { $k = "$($ch.ProcessId)"; if (-not $script:PmonSeenChild.Contains($k)) { [void]$script:PmonSeenChild.Add($k); Write-IcptLine $txtPmon ("[{0}] CHILD   {1} (pid {2})`r`n" -f $ts, $ch.Name, $ch.ProcessId) $pmYellow } } } catch {}
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
        $script:PmonSeenMod = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenConn = New-Object 'System.Collections.Generic.HashSet[string]'
        $script:PmonSeenChild = New-Object 'System.Collections.Generic.HashSet[string]'
        try { foreach ($m in $p.Modules) { [void]$script:PmonSeenMod.Add("$($m.FileName)") } } catch {}
        try { foreach ($c in (Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenConn.Add("$($c.LocalAddress):$($c.LocalPort)->$($c.RemoteAddress):$($c.RemotePort)") } } catch {}
        try { foreach ($ch in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -ErrorAction SilentlyContinue)) { [void]$script:PmonSeenChild.Add("$($ch.ProcessId)") } } catch {}
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
        Write-IcptLine $txtPmon "(baseline taken; logging NEW modules / TCP connections / child processes)`r`n`r`n" $pmGrey
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
$form.Add_FormClosing({ try { $script:PmonTimer.Stop() } catch {} })
Set-PmonMode 'live'

$form.Controls.Add($tabs)
$tabs.BringToFront()

# Live log (left)
$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = "Live progress (each check fires as it runs)"
$logLabel.Dock = 'Top'
$logLabel.Height = 22
$logLabel.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
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

# Findings (right)
$findLabel = New-Object System.Windows.Forms.Label
$findLabel.Text = "Findings (live)"
$findLabel.Dock = 'Top'
$findLabel.Height = 22
$findLabel.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
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
$pbar.Location = New-Object System.Drawing.Point(466, 150)
$pbar.Size = New-Object System.Drawing.Size(200, 16)
$pbar.Minimum = 0; $pbar.Maximum = 100; $pbar.Value = 0
$pbar.Style = 'Continuous'   # solid fill (no chunk animation / value-set lag)
$pbar.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
$topPanel.Controls.Add($pbar)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Ready. Pick a target, then click Run Audit."
$lblStatus.Location = New-Object System.Drawing.Point(674, 149)
$lblStatus.Size = New-Object System.Drawing.Size(320, 18)
$lblStatus.TextAlign = 'MiddleLeft'
$lblStatus.Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$topPanel.Controls.Add($lblStatus)

# Footer -- shortcuts to the generated reports (enabled after an audit completes).
$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Dock = 'Bottom'
$bottomPanel.Height = 34
$bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$form.Controls.Add($bottomPanel)

$lblReports = New-Object System.Windows.Forms.Label
$lblReports.Text = "Generated reports:"
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
$bottomPanel.Controls.Add($btnOpenHtml)

$btnOpenExcel = New-Object System.Windows.Forms.Button
$btnOpenExcel.Text = "Open Excel report"
$btnOpenExcel.Dock = 'Right'
$btnOpenExcel.Width = 140
$btnOpenExcel.Enabled = $false
$bottomPanel.Controls.Add($btnOpenExcel)

$btnOpenMarkdown = New-Object System.Windows.Forms.Button
$btnOpenMarkdown.Text = "Open Markdown"
$btnOpenMarkdown.Dock = 'Right'
$btnOpenMarkdown.Width = 130
$btnOpenMarkdown.Enabled = $false
$bottomPanel.Controls.Add($btnOpenMarkdown)

$btnOpenFolder = New-Object System.Windows.Forms.Button
$btnOpenFolder.Text = "Open output folder"
$btnOpenFolder.Dock = 'Right'
$btnOpenFolder.Width = 140
$btnOpenFolder.Enabled = $false
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
    $name = "$($cmbFont.SelectedItem)"; if (-not $name) { $name = 'Consolas' }
    $size = try { [single]$cmbSize.SelectedItem } catch { 10 }
    if ($size -lt 7) { $size = 10 }
    $script:UiFontName = $name; $script:UiFontSize = $size
    try {
        $f  = New-Object System.Drawing.Font($name, $size)
        $lf = New-Object System.Drawing.Font($name, [single]([Math]::Max(8, $size - 1)))
        foreach ($c in @($txtLog, $txtRecon, $txtExpDetail, $txtLogs)) { if ($c) { $c.Font = $f } }
        foreach ($lv in @($lvFindings, $lvExp)) { if ($lv) { $lv.Font = $lf } }
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

    # Run as job so we can stream output
    $jobScript = {
        param($modulePath, $params)
        Import-Module $modulePath -Force
        Invoke-TcpkAudit @params 6>&1 |
            ForEach-Object {
                if ($_ -is [string]) {
                    if ($_ -notmatch '^LOGX\t') { "LOG`t$_" }     # LOGX = verbose trace -> Logs/Runtime tab only
                }
                elseif ($_ -is [System.Management.Automation.InformationRecord]) {
                    $t = "$_"; if ($t -notmatch '^LOGX\t') { "LOG`t$t" }
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
        }
        Start-Sleep -Milliseconds 150
        [System.Windows.Forms.Application]::DoEvents()
    }
    # Drain remaining LOG messages from the job
    $remaining = Receive-Job -Job $job -Wait -AutoRemoveJob
    foreach ($line in $remaining) {
        if ($line -match '^LOG\t(.+)$') {
            $dmsg = $matches[1]
            Write-LogLine $dmsg
            Step-ProgressFromLog $dmsg
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
