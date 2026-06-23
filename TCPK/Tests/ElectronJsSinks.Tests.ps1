#requires -Version 5.1
# A41 Test-TcpkElectronJs -- Electron/JS vulnerable-code-pattern scan (the "not covered yet"
# coverage from the CODE BLUE 2023 "Pwning Electron" analysis). Findings are Inferred LEADS;
# the clean fixture proves the context guards suppress false positives.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ejs-" + [guid]::NewGuid().ToString('N'))
    function New-ElectronApp { param($Dir, $Js)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Dir 'ffmpeg.dll'), 'MZ')   # Electron marker
        [IO.File]::WriteAllText((Join-Path $Dir 'app.asar'), $Js)
    }
    $script:vuln = Join-Path $script:work 'vuln'
    New-ElectronApp $script:vuln @'
const { shell, BrowserWindow, protocol } = require("electron");
const cp = require("child_process"); cp.exec(userCmd);
el.innerHTML = userInput;
function o1(u){ shell.openExternal(u); }
function o2(){ shell.openExternal("file:///Applications/Calculator.app"); }
function o3(){ shell.openExternal("https://safe.example.com"); }
const md = require("marked"); render(md(note));
protocol.registerFileProtocol("app", (req, cb) => { cb({ path: req.url }); });
const win = new BrowserWindow({});
obj.__proto__ = evil;
location.href = nextPage;
window.open(targetUrl);
el.style.cssText = userStyle;
setTimeout("runIt()", 50);
session.defaultSession.webRequest.onHeadersReceived((d, cb) => cb({ responseHeaders: { "Content-Security-Policy": ["default-src 'self'; script-src 'unsafe-inline'"] } }));
const csp2 = "Content-Security-Policy: script-src 'nonce-AbC123dEf456'";
const wv = '<webview src="https://x" nodeintegration></webview>';
frame.postMessage(payload, "*");
app.commandLine.appendSwitch("disable-web-security");
wc.executeJavaScript(userSuppliedCode);
ses.setPermissionRequestHandler((wc, perm, cb) => cb(true));
wc.insertCSS(userSuppliedCss);
'@
    $script:clean = Join-Path $script:work 'clean'
    New-ElectronApp $script:clean @'
const { shell, BrowserWindow, protocol } = require("electron");
const DOMPurify = require("dompurify"); const marked = require("marked");
function safe(n){ return DOMPurify.sanitize(marked(n)); }
function help(){ shell.openExternal("https://help.example.com"); }
const path = require("path");
protocol.registerFileProtocol("app", (req, cb) => { const p = path.resolve(ROOT, req.url); if (p.startsWith(ROOT)) cb({ path: p }); });
const win = new BrowserWindow({ webPreferences: { contextIsolation: true } });
win.webContents.on("will-navigate", (e) => e.preventDefault());
'@
    $script:plain = Join-Path $script:work 'plain'
    New-Item -ItemType Directory -Path $script:plain -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $script:plain 'main.js'), 'el.innerHTML = x; require("child_process").exec(c);')

    $script:v = @(Test-TcpkElectronJs -Path $script:vuln)
    $script:c = @(Test-TcpkElectronJs -Path $script:clean)
    $script:n = @(Test-TcpkElectronJs -Path $script:plain)
}
AfterAll { if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) } }

Describe 'Electron/JS sinks (vulnerable app)' {
    It 'flags the exec sink (child_process / eval)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.exec-sink').Count | Should -BeGreaterThan 0
    }
    It 'flags the DOM XSS sink (innerHTML)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.dom-xss-sink').Count | Should -BeGreaterThan 0
    }
    It 'flags openExternal: file:// as HIGH and a variable as MEDIUM, but NOT a literal https' {
        $oe = @($script:v | Where-Object RuleId -eq 'electronjs.open-external-untrusted')
        @($oe).Count | Should -Be 2
        @($oe | Where-Object Severity -eq 'HIGH').Count   | Should -BeGreaterThan 0
        @($oe | Where-Object Severity -eq 'MEDIUM').Count | Should -BeGreaterThan 0
    }
    It 'flags markdown-unsanitized, resource traversal, missing nav guard, proto pollution' {
        @($script:v | Where-Object RuleId -eq 'electronjs.markdown-unsanitized').Count   | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.resource-path-traversal').Count | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.missing-nav-guard').Count       | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.proto-pollution-sink').Count    | Should -BeGreaterThan 0
    }
    It 'flags navigation-injection, CSS-injection, and weak CSP (NDSS DOM-tree-type round)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.nav-injection-sink').Count | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.css-injection-sink').Count | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.csp-unsafe').Count         | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.csp-hardcoded-nonce').Count | Should -BeGreaterThan 0
    }
    It 'flags unsafe <webview> tag and wildcard postMessage (EQST report round)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.webview-tag-unsafe').Count     | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.postmessage-star-origin').Count | Should -BeGreaterThan 0
    }
    It 'flags dangerous command-line switch and dynamic executeJavaScript (Inspectron round)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.cmdline-switch-unsafe').Count | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.execute-js-dynamic').Count    | Should -BeGreaterThan 0
    }
    It 'flags always-allow permission handler and insertCSS (Electronegativity round)' {
        @($script:v | Where-Object RuleId -eq 'electronjs.permission-allow-all').Count | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'electronjs.css-injection-sink').Count   | Should -BeGreaterThan 0
    }
}

Describe 'Electron/JS sinks (clean app -- FP guard)' {
    It 'produces no electronjs.* findings when guards are present' {
        @($script:c | Where-Object { $_.RuleId -like 'electronjs.*' }).Count | Should -Be 0
    }
}

Describe 'Electron/JS sinks (gate)' {
    It 'does not run on a non-Electron directory' {
        @($script:n | Where-Object { $_.RuleId -like 'electronjs.*' }).Count | Should -Be 0
    }
}
