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
$topPanel.Height = 180
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

$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = '  Audit  '
$tabAudit.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
[void]$tabs.TabPages.Add($tabAudit)

$tabRecon = New-Object System.Windows.Forms.TabPage
$tabRecon.Text = '  Recon / Target  '
$tabRecon.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
[void]$tabs.TabPages.Add($tabRecon)

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

# --- Dynamic / Active (gated) tools toolbar (top of the output panel) ----------
Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue

function Write-ExpLine([string]$text, [System.Drawing.Color]$color) {
    $txtExpDetail.SelectionStart = $txtExpDetail.TextLength
    $txtExpDetail.SelectionLength = 0
    $txtExpDetail.SelectionColor = $color
    $txtExpDetail.AppendText($text)
    try { $txtExpDetail.ScrollToCaret() } catch {}
}
function Get-DynProc {
    $p = $txtDynProc.Text.Trim()
    if (-not $p) { $p = $txtProc.Text.Trim() }
    return $p
}
function Test-DynGate {
    if (-not $chkExpEnable.Checked) {
        Write-ExpLine "`r`n[gate] Tick the authorization box above to enable active (modifying) tools.`r`n" ([System.Drawing.Color]::FromArgb(255,180,180))
        return $false
    }
    try { Enable-TcpkExploit -Acknowledge | Out-Null } catch {}
    return $true
}
function Invoke-DynTool([string]$title, [scriptblock]$call) {
    $proc = Get-DynProc
    Write-ExpLine "`r`n== $title ==`r`n" ([System.Drawing.Color]::FromArgb(102,217,239))
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $res = & $call
        $n = 0
        foreach ($f in @($res)) {
            if (-not $f) { continue }
            $n++
            $c = $script:SevColour[[string]$f.Severity]; if (-not $c) { $c = [System.Drawing.Color]::White }
            Write-ExpLine ("[{0}] {1}`r`n" -f $f.Severity, $f.Title) $c
            if ($f.Evidence) { Write-ExpLine ("      {0}`r`n" -f $f.Evidence) ([System.Drawing.Color]::FromArgb(150,150,150)) }
        }
        if ($n -eq 0) { Write-ExpLine "(no results)`r`n" ([System.Drawing.Color]::FromArgb(150,150,150)) }
        else { Write-ExpLine ("-> {0} result(s)`r`n" -f $n) ([System.Drawing.Color]::FromArgb(166,226,46)) }
    } catch {
        Write-ExpLine ("ERROR: {0}`r`n" -f $_.Exception.Message) ([System.Drawing.Color]::FromArgb(249,38,114))
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

$dynBar = New-Object System.Windows.Forms.Panel
$dynBar.Dock = 'Top'; $dynBar.Height = 84; $dynBar.BackColor = [System.Drawing.Color]::FromArgb(43,43,43)
$lblDyn = New-Object System.Windows.Forms.Label
$lblDyn.Text = 'Dynamic / Active tools (target app must be running):'
$lblDyn.ForeColor = [System.Drawing.Color]::FromArgb(200,205,210)
$lblDyn.Location = New-Object System.Drawing.Point(10,8); $lblDyn.AutoSize = $true
$dynBar.Controls.Add($lblDyn)
$lblDynProc = New-Object System.Windows.Forms.Label
$lblDynProc.Text = 'ProcessName:'; $lblDynProc.ForeColor = [System.Drawing.Color]::FromArgb(200,205,210)
$lblDynProc.Location = New-Object System.Drawing.Point(330,8); $lblDynProc.AutoSize = $true
$dynBar.Controls.Add($lblDynProc)
$txtDynProc = New-Object System.Windows.Forms.TextBox
$txtDynProc.Location = New-Object System.Drawing.Point(412,6); $txtDynProc.Size = New-Object System.Drawing.Size(170,22)
$dynBar.Controls.Add($txtDynProc)

$dynDefs = @(
    @{ T='Mem Secrets';  A={ Invoke-DynTool 'Live memory secret scan (read-only)' { Test-TcpkMemorySecrets -ProcessName (Get-DynProc) -MaxScanMB 48 } } }
    @{ T='Proc DACL';    A={ Invoke-DynTool 'Process DACL (read-only)' { Test-TcpkProcessDacl -ProcessName (Get-DynProc) } } }
    @{ T='Env Secrets';  A={ Invoke-DynTool 'Process environment secrets (read-only)' { Test-TcpkProcessEnvSecrets -ProcessName (Get-DynProc) } } }
    @{ T='GUI Unlock';   A={ if (Test-DynGate) { Invoke-DynTool 'GUI unlock (dry-run)' { Invoke-TcpkGuiUnlock -ProcessName (Get-DynProc) } } } }
    @{ T='Pipe Probe';   A={ if (Test-DynGate) { $pn=[Microsoft.VisualBasic.Interaction]::InputBox('Pipe name (no \\.\pipe\ prefix):','TCPK Pipe Probe',''); if ($pn) { Invoke-DynTool "Pipe probe: $pn" { Invoke-TcpkPipeProbe -PipeName $pn } } } } }
    @{ T='Flag-Flip';    A={ if (Test-DynGate) { $pat=[Microsoft.VisualBasic.Interaction]::InputBox('ASCII/byte pattern to locate (DRY-RUN, no write):','TCPK Memory Flag-Flip',''); if ($pat) { Invoke-DynTool "Flag-flip dry-run: $pat" { Invoke-TcpkMemoryFlagFlip -ProcessName (Get-DynProc) -Pattern $pat -NewBytesHex '01' } } } } }
    @{ T='Input Fuzz...';  A={ Write-ExpLine "`r`n[Input fuzz] Intrusive -- run from a console (it launches the target repeatedly):`r`n" ([System.Drawing.Color]::FromArgb(102,217,239)); Write-ExpLine "Enable-TcpkExploit -Acknowledge`r`nInvoke-TcpkInputFuzz -TargetExe '<app.exe>' -SeedFile '<sample.ext>' -ArgTemplate '{FUZZ}' -Iterations 25`r`n" ([System.Drawing.Color]::White) } }
)
$dxi = 10
foreach ($d in $dynDefs) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $d.T; $b.Size = New-Object System.Drawing.Size(104,30)
    $b.Location = New-Object System.Drawing.Point($dxi,42)
    $b.BackColor = [System.Drawing.Color]::FromArgb(230,230,230)
    $b.FlatStyle = 'Flat'
    $b.Add_Click($d.A)
    $dynBar.Controls.Add($b)
    $dxi += 110
}
$expSplit.Panel2.Controls.Add($dynBar)
$dynBar.BringToFront()

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
$script:Accent     = [System.Drawing.Color]::FromArgb(78, 201, 176)   # teal accent
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
    foreach ($b in @($btnRun, $btnPause, $btnOpenHtml, $btnOpenExcel, $btnOpenFolder, $btnTestAi, $btnBrowse, $btnAutoDetect, $btnExpRun)) {
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
    foreach ($b in @($btnBrowse, $btnAutoDetect, $btnTestAi, $btnTheme, $btnPause, $btnOpenHtml, $btnOpenExcel, $btnOpenFolder)) {
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
        # High-contrast layered dark (VS Code / GitHub-dark style). Distinct layers:
        # window (#1E1E1E) < panel (#2D2D30) < input fields (#3C3C3C, lifted so they
        # stand out) ; text areas are deep (#181818) for log readability. Text is
        # near-white for strong contrast (the old muted blue-grey was the visibility issue).
        @{ FormBg =[System.Drawing.Color]::FromArgb(30,30,30);   PanelBg=[System.Drawing.Color]::FromArgb(45,45,48)
           InputBg=[System.Drawing.Color]::FromArgb(60,60,60);   TextBg =[System.Drawing.Color]::FromArgb(24,24,24)
           TextFg =[System.Drawing.Color]::FromArgb(236,236,236)
           ListBg =[System.Drawing.Color]::FromArgb(37,37,38);   ListFg =[System.Drawing.Color]::FromArgb(236,236,236)
           LabelFg=[System.Drawing.Color]::FromArgb(242,242,242) }
    } else {
        @{ FormBg =[System.Drawing.Color]::FromArgb(248,249,250); PanelBg=[System.Drawing.Color]::FromArgb(238,240,242)
           InputBg=[System.Drawing.Color]::White;                 TextBg =[System.Drawing.Color]::White
           TextFg =[System.Drawing.Color]::FromArgb(24,24,24)
           ListBg =[System.Drawing.Color]::White;                 ListFg =[System.Drawing.Color]::FromArgb(24,24,24)
           LabelFg=[System.Drawing.Color]::FromArgb(28,28,28) }
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
            'TextBox'        { $c.BackColor = $pal.InputBg; $c.ForeColor = $pal.TextFg }
            'RichTextBox'    { $c.BackColor = $pal.TextBg;  $c.ForeColor = $pal.TextFg }
            'ListView'       { $c.BackColor = $pal.ListBg;  $c.ForeColor = $pal.ListFg }
            'ComboBox'       { $c.BackColor = $pal.InputBg; $c.ForeColor = $pal.TextFg }
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

    $btnRun.Enabled = $false
    $btnOpenHtml.Enabled = $false
    $btnOpenExcel.Enabled = $false
    $btnOpenFolder.Enabled = $false
    # pause/resume: clear any stale signal, then enable Pause for this run
    Remove-Item -LiteralPath $script:PauseFlag -Force -ErrorAction SilentlyContinue
    $btnPause.Text = "Pause"; $btnPause.Enabled = $true
    $txtLog.Clear()
    $lvFindings.Items.Clear()

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
    $btnRun.Enabled = $true
    # pause/resume: audit finished -> disable Pause and clear any signal
    $btnPause.Enabled = $false; $btnPause.Text = "Pause"
    Remove-Item -LiteralPath $script:PauseFlag -Force -ErrorAction SilentlyContinue
    $btnOpenHtml.Enabled = (Test-Path (Join-Path $outDir 'index.html'))
    $btnOpenExcel.Enabled = (Test-Path (Join-Path $outDir 'report.xlsx'))
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

# Show
[void]$form.ShowDialog()
