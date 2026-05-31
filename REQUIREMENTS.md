# TCPK -- Requirements & Setup

## TL;DR

**To run a full audit you need NOTHING third-party.** Just Windows + Windows
PowerShell 5.1 (already on every Windows 10/11 box). Drop the folder anywhere,
double-click `TCPK.bat` (or `TCPK.exe`), and run.

Everything below the "Required" section is **optional** and only adds
convenience (AI triage, exploit execution, rebuilding the EXE).

---

## 1. Required (to run TCPK and produce a full report)

| Requirement | Notes | Already present? |
|-------------|-------|------------------|
| **Windows 10 / 11** (or Server 2016+) | Thick-client targets are Windows | Yes |
| **Windows PowerShell 5.1** (`powershell.exe`) | Ships with Windows | Yes |
| The `TCPK\` module folder + `Start-TCPKGui.ps1` / `TCPK.bat` / `TCPK.exe` | The tool itself | Yes |

That's it. No installs. All 115 checks, recon, CVE matching, reports, and
exploit-PoC **generation** run on pure PowerShell + built-in Windows tools
(`reg.exe`, `schtasks.exe`, `.NET` BCL). **Works fully offline / air-gapped.**

### How to run

- **GUI:** double-click `TCPK.exe`, or run `TCPK.bat`, or:
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

### 2b. Cloud AI (Claude / OpenAI / DeepSeek -- needs internet + API key)

Get an API key from the provider, then in TCPK pick the provider and paste the key:

| Provider | Get a key at |
|----------|--------------|
| Claude (Anthropic) | https://console.anthropic.com |
| OpenAI | https://platform.openai.com/api-keys |
| DeepSeek | https://platform.deepseek.com |

(Cloud is opt-in behind a gate; local Ollama is the default.)

### 2c. Mono.Cecil (lets the AI read .NET IL -- sharper verdicts)

Only used by AI-verify on **.NET** targets to read method IL. Without it, AI
still runs and just skips the IL step. To enable it, place **one DLL**:

- **Easiest:** install **ILSpy** (https://github.com/icsharpcode/ILSpy/releases) --
  it ships `Mono.Cecil.dll`. TCPK auto-detects it at
  `%LOCALAPPDATA%\Programs\ILSpy\Mono.Cecil.dll`.
- **No-install:** download the **Mono.Cecil** NuGet package
  (https://www.nuget.org/packages/Mono.Cecil), rename `.nupkg`-> `.zip`, extract
  `lib\net40\Mono.Cecil.dll`, and drop it at:
  ```
  <TCPK folder>\tools\ILSpy\Mono.Cecil.dll
  ```

TCPK does **not** run ILSpy/dnSpy -- it only loads this one MIT-licensed DLL.

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

## 5. Optional -- rebuild the portable EXE

Only if you edit `Start-TCPKGui.ps1` and want a fresh `TCPK.exe`:

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile .\Start-TCPKGui.ps1 -outputFile .\TCPK.exe -STA -noConsole
```

You can always run `TCPK.bat` / the `.ps1` directly without rebuilding.

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
| Live memory dump | ProcDump |
| Rebuild the EXE | ps2exe |
| Extra coding fonts | Install the `.ttf` |

**Authorized testing only.** See `DISCLAIMER.txt`.
