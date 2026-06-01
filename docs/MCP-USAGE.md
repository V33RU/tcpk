# TCPK MCP Server - Usage Guide

TCPK can act as a **Model Context Protocol (MCP) server**, exposing its
audit / recon / CVE / exploit capabilities as tools that any MCP client
(Claude Code, Claude Desktop, Cursor, or any MCP host) can call.

This lets an LLM **drive TCPK conversationally** and **compose it with any other
MCP server you have connected** (filesystem, Burp, ticketing, etc.) - e.g.
*"profile this app, match CVEs, then open a ticket for each CRITICAL."*

> **Additive & safe:** the MCP server is a standalone script
> (`Start-TcpkMcpServer.ps1`) that only *imports* the TCPK module and calls its
> existing cmdlets. It changes nothing in the module or the GUI. If you never
> launch it, TCPK behaves exactly as before.

---

## 1. Requirements

- Windows **PowerShell 5.1** (`powershell.exe`) - already used by TCPK.
- The `TCPK\` module folder next to `Start-TcpkMcpServer.ps1` (default layout).
- An MCP client (Claude Code / Claude Desktop / etc.).
- **No internet required** - transport is local stdio. (Only the optional cloud
  LLM features of TCPK would need network, and they are off by default.)

The server speaks **newline-delimited JSON-RPC 2.0 over stdio**. `stdout` carries
only protocol messages; TCPK's own output is suppressed so the channel stays
clean. Diagnostics go to `stderr`.

---

## 2. Add it to your MCP client

### Claude Code (CLI)

One-liner:

```bash
claude mcp add tcpk -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\admin\Desktop\TCPK\Start-TcpkMcpServer.ps1"
```

...or drop a `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "tcpk": {
      "command": "powershell.exe",
      "args": [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "C:\\Users\\admin\\Desktop\\TCPK\\Start-TcpkMcpServer.ps1"
      ]
    }
  }
}
```

### Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tcpk": {
      "command": "powershell.exe",
      "args": [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "C:\\Users\\admin\\Desktop\\TCPK\\Start-TcpkMcpServer.ps1"
      ]
    }
  }
}
```

Restart the client. You should see **8 `tcpk_*` tools** become available.

> Adjust the path if you moved the tool. Use double backslashes in JSON.

---

## 3. Tools exposed

| Tool | What it does | Key arguments |
|------|--------------|---------------|
| `tcpk_info` | TCPK version + implemented bucket counts | *(none)* |
| `tcpk_recon_profile` | Fingerprint the target (type, version, publisher, runtime, UI frameworks, SDKs, signing, attack-surface counts) - no full audit | `target` |
| `tcpk_strings` | Extract categorized literals (URLs, paths, registry keys, IPs, emails, command refs, secret-ish) | `target` |
| `tcpk_cve_match` | Match shipped components vs the offline CVE catalog | `target`, `includePatched?` |
| `tcpk_audit` | **Full audit** - writes HTML/JSON/MD reports + sidecars; returns a summary with `outDir` (takes ~1-3 min) | `target`, `packageName?`, `processName?`, `outDir?` |
| `tcpk_get_findings` | Read findings from a completed audit, filter by severity / ruleId | `outDir`, `severity?`, `ruleId?`, `limit?` |
| `tcpk_exploit_plan` | Read the actionable CVE + exploitable-finding plan | `outDir` |
| `tcpk_generate_poc` | **GATED** - generate a PoC artifact (Frida / proxy DLL / poisoned manifest / COM-hijack). Generates files only; never attacks | `module`, `authorized=true`, ... |

---

## 4. Example workflows

**Quick recon (no full audit):**
> "Use tcpk_recon_profile on `C:\Program Files\WindowsApps\YourApp_1.2.3.0_x64__xxxxxxxxxxxxx` and summarize the tech stack and signing."

**Full audit + triage:**
> "Run tcpk_audit on that path with packageName `YourApp`. Then tcpk_get_findings for severity CRITICAL and HIGH, and explain each."

**Supply-chain check:**
> "tcpk_cve_match the target with includePatched true - list which bundled libraries are vulnerable vs already patched."

**Authorized PoC (gated):**
> "I'm authorized. Use tcpk_generate_poc with module New-TcpkFridaTlsBypass, authorized true, targetExe 'YourApp.exe' - then tell me how to run it."

**Compose with other MCP servers:**
> "Run tcpk_audit, then for every CRITICAL finding create an issue via my Jira MCP server."

---

## 5. Authorization & safety

- TCPK is for **authorized testing only**. The `tcpk_generate_poc` tool is gated:
  it refuses unless you pass `authorized: true`, which asserts you have written
  authorization to test the target.
- PoC tools **generate artifacts** (scripts, DLL scaffolds, manifests). They do
  **not** deploy or attack anything by themselves.
- The author(s) and community accept **no liability** for misuse. See
  `DISCLAIMER.txt`.

---

## 6. Troubleshooting

- **No tools appear:** confirm the path in the config, and that
  `powershell.exe` (not `pwsh`) is used. Check the client's MCP logs.
- **Module not found:** the server looks for `TCPK\TCPK.psd1` next to the
  script. Keep `Start-TcpkMcpServer.ps1` beside the `TCPK\` folder.
- **`tcpk_audit` seems to hang:** a full audit takes ~1-3 minutes; the client is
  just waiting. Use `tcpk_recon_profile` / `tcpk_cve_match` for quick answers.
- **Manual smoke test** (PowerShell):
  ```powershell
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' |
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-TcpkMcpServer.ps1
  ```
  You should get one JSON line back with `protocolVersion` and `serverInfo`.
