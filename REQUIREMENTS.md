# TCPK -- Requirements & Setup

## TL;DR

**To run a full audit you need NOTHING third-party.** Just Windows + Windows
PowerShell 5.1 (already on every Windows 10/11 box). Drop the folder anywhere,
double-click `TCPK.bat`, and run.

Everything below the "Required" section is **optional** and only adds
convenience (AI triage, exploit execution).

Some GUI tabs need an external tool before they do anything: the **Pcap tab
needs Wireshark's `tshark`**, Intercept needs `mitmdump`, and the runtime hook
checks need `frida`. None of them affect the static audit. For install commands,
the portable `tools\` layout, and PATH setup, see **[docs/INSTALL.md](docs/INSTALL.md)**.

---

## 1. Required (to run TCPK and produce a full report)

| Requirement | Notes | Already present? |
|-------------|-------|------------------|
| **Windows 10 / 11** (or Server 2016+) | Thick-client targets are Windows | Yes |
| **Windows PowerShell 5.1** (`powershell.exe`) | Ships with Windows | Yes |
| The `TCPK\` module folder + `Start-TCPKGui.ps1` / `TCPK.bat` | The tool itself | Yes |

That's it. No installs. All 259 cmdlets (174 detection checks across 19 buckets),
recon, reports, and exploit-PoC **generation** run on pure PowerShell + built-in
Windows tools (`reg.exe`, `schtasks.exe`, `.NET` BCL), so the static audit works
**fully offline / air-gapped**.

The one exception is **CVE matching**, which queries OSV and NVD over the network
and is the only feature that needs internet at audit time. TCPK ships no offline
CVE database, so on an air-gapped run it performs no CVE matching and the report
says the dependency surface was not tested rather than showing it clean.

### How to run

- **GUI:** double-click `TCPK.bat`, or:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\Start-TCPKGui.ps1
  ```
- **Command line:**
  ```powershell
  Import-Module .\TCPK\TCPK.psd1 -Force
  Invoke-TcpkAudit -Target 'C:\Path\To\App' -PackageName 'AppPkg' -Acknowledge
  ```

> If you get an execution-policy error, the `-ExecutionPolicy Bypass` flag above
> handles it (no system change needed).

---

## 2. Optional -- AI verification (auto-triages "Inferred" findings)

Off by default. The deterministic scan finds everything without it; AI just
accelerates triage.

### 2a. Ollama (local AI -- recommended, private, offline after setup)

1. Download & install from **https://ollama.com/download**
2. Pull a model (one-time download):
   ```powershell
   ollama pull qwen2.5-coder:7b
   ```
3. Ollama runs automatically at `http://localhost:11434`. In TCPK: tick
   **AI-verify findings**, pick **ollama (local)**, model `qwen2.5-coder:7b`.

No API key. After the model is pulled, it runs **offline**.

### 2b. Cloud AI (Claude / OpenAI / Gemini / Grok / DeepSeek -- needs internet + API key)

Get an API key from the provider, then in TCPK pick the provider and paste the key.
The **model field is free-text** -- type any model the provider exposes, or click
**Test AI** to pull the live list. Need something not listed? Pick **custom** and set
its `baseUrl` in `Data\llm-config.json` (any OpenAI-compatible endpoint works).

| Provider | Get a key at |
|----------|--------------|
| Claude (Anthropic) | https://console.anthropic.com |
| OpenAI | https://platform.openai.com/api-keys |
| Gemini (Google) | https://aistudio.google.com/apikey |
| Grok (xAI) | https://console.x.ai |
| DeepSeek | https://platform.deepseek.com |

(Cloud is opt-in behind a gate; local Ollama is the default.)

### 2b-i. GitHub Copilot (for orgs with Copilot licences but no model API key)

Many organisations issue Copilot seats but no direct Anthropic/OpenAI API key.
[copilot-api](https://github.com/ericc-ch/copilot-api) re-exposes your existing Copilot
entitlement as an OpenAI- and Anthropic-compatible server, and TCPK ships a preset for it.

1. Start the proxy (it authenticates to GitHub itself, so TCPK needs no key):

   ```powershell
   npx copilot-api@latest start
   ```

   It listens on `http://localhost:4141` by default.

2. In TCPK, tick **AI-verify findings**, pick **copilot (proxy)**, and leave the API-key
   box empty. Click **Test AI** to load the live model list from the proxy.

To use a non-default port, pick **custom** instead and set `baseUrl` to
`http://localhost:<port>/v1` in `Data\llm-config.json`.

**This is still a cloud path.** The endpoint is localhost, but the proxy forwards every
request to GitHub, so decompiled IL leaves the machine exactly as it would with any
hosted provider. TCPK gates it behind the same confirmation as Claude or OpenAI, and the
prompt says so. Do not use it on material you are under NDA for. Check your Copilot
subscription terms cover this use; that is between you and GitHub, and TCPK takes no
position on it.

For fully offline AI, use Ollama.

### 2c. Mono.Cecil (lets the AI read .NET IL -- sharper verdicts)

**Already included. Nothing to install.** TCPK ships Mono.Cecil 0.11.5 at
`<TCPK folder>\tools\ILSpy\`, taken unmodified from the official NuGet package.
It is used by AI-verify on **.NET** targets to read method IL, and by the IL
verifiers in `TCPK\Public\Verify\`. If the files are missing, AI-verify still
runs and just skips the IL step.

Licensing: Mono.Cecil is MIT. Its copyright notice, the full license text, and
the SHA256 of each shipped assembly are recorded in [NOTICE](NOTICE).

TCPK does **not** run ILSpy or dnSpy. The folder is named `tools\ILSpy\` for
historical reasons; only the Mono.Cecil assemblies are present.

---

## 3. Optional -- to EXECUTE a generated exploit PoC

TCPK always **generates** the PoC files. You only need these to actually *fire*
them against your authorized target:

| To run... | Install |
|-----------|---------|
| The **Frida** TLS-bypass script (`*.js`) | Python + Frida: `pip install frida-tools` (https://frida.re) |
| The **proxy-DLL** hijack (`dllmain.c`) | A C compiler: **Visual Studio Build Tools** (`cl.exe`, https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) or **MinGW-w64** (`gcc`) |
| The **COM-hijack** `.reg` | `reg.exe import file.reg` (built into Windows) |
| The **poisoned-update** manifest | Any local web server you control |

---

## 4. Optional -- live memory dump

| Feature | Install |
|---------|---------|
| `Test-TcpkMemoryDump` (full process dump) | **ProcDump** (Sysinternals): https://learn.microsoft.com/sysinternals/downloads/procdump -- put `procdump.exe` on `PATH`. Skips cleanly if absent. |

---

## 5. Optional -- building your own launcher EXE

TCPK does **not** ship a compiled `.exe`, deliberately:

- A ps2exe binary **embeds** the GUI script, so it silently goes stale the
  moment `Start-TCPKGui.ps1` changes. A shipped exe is a second, older copy
  of the tool that looks current.
- ps2exe output is 32-bit by default. On 64-bit Windows a 32-bit process hits
  the WOW64 **file-system and registry redirectors**, so `System32` resolves to
  `SysWOW64` and `HKLM\Software` resolves to the `WOW6432Node` view. Several
  checks read those paths directly and will report wrong results.
- Reputation-based AV commonly quarantines ps2exe binaries, and an unsigned,
  unreproducible binary in a security tool is not reviewable by the people
  running it.

`TCPK.bat` gives the same double-click, no-install, USB-portable behaviour
without any of that.

If you still want a branded launcher for internal use, build it yourself and
force 64-bit:

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile .\Start-TCPKGui.ps1 -outputFile .\TCPK.exe -STA -noConsole -x64
```

Rebuild it on every change to `Start-TCPKGui.ps1`, and keep it beside the
`TCPK\` module folder. Do not commit it.

---

## 6. Optional -- coding fonts (cosmetic)

TCPK's Font dropdown shows the monospace/"hacker" fonts **installed on your
machine** (Cascadia Code ships with Windows Terminal). To add others:

1. Download the `.ttf` (e.g. **Fira Code** https://github.com/tonsky/FiraCode/releases,
   **JetBrains Mono** https://www.jetbrains.com/lp/mono/, **Hack**)
2. Select the `.ttf` files -> right-click -> **Install**
3. Restart TCPK -- the font appears in the dropdown automatically

---

## Summary

| You want to... | You need... |
|----------------|-------------|
| Scan + report a target (the core job) | **Nothing** -- just run it |
| AI auto-triage of findings | Ollama (free, local) (+ Mono.Cecil.dll for .NET IL) |
| Cloud AI | Provider API key |
| Run a generated exploit PoC | Frida and/or a C compiler |
| Analyse a .pcap (Pcap tab) | **Wireshark** (`tshark`) - see [docs/INSTALL.md](docs/INSTALL.md) |
| Capture live traffic | Wireshark with **Npcap** (`dumpcap`) |
| Intercept / tamper HTTP | **mitmproxy** (`mitmdump`) |
| Live memory dump | ProcDump |
| Rebuild the EXE | ps2exe |
| Extra coding fonts | Install the `.ttf` |

**Authorized testing only.** See `DISCLAIMER.txt`.
