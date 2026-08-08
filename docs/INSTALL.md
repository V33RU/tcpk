# TCPK - installing the optional tools

TCPK runs a **full static audit with nothing installed**. PowerShell 5.1 and built-in
Windows tools (`reg.exe`, `schtasks.exe`, `sc.exe`, `logman.exe`, the .NET BCL) cover the
core, and Mono.Cecil ships in the repo so the decompiler and the IL provers work out of
the box.

Everything on this page is **optional**. Each tool unlocks one area. Without it, TCPK
reports that the area was not tested rather than reporting it clean.

---

## Two ways to install: portable or PATH

TCPK looks for every optional tool in **two places, in this order**:

1. a `tools\<name>\` folder inside the TCPK folder
2. the system `PATH`

**Portable (recommended).** Drop the binary into the matching `tools\` subfolder. Nothing
is installed, nothing touches the registry or PATH, and the tool travels with TCPK on a
stick. This matches how TCPK works everywhere else: everything it needs and everything it
produces lives in one folder you can delete.

**PATH.** Install normally and let the installer put it on PATH. Better if you already use
these tools day to day.

The exact folder names TCPK probes:

| Tool | Portable location |
|---|---|
| tshark, dumpcap | `tools\wireshark\` |
| frida | `tools\frida\` |
| mitmdump | `tools\mitmproxy\` |
| procdump | `tools\Procdump\` |
| ilspycmd | `tools\ilspycmd\` |
| Mono.Cecil | `tools\ILSpy\` (already shipped) |

Those names are matched exactly. `tools\Wireshark\` works on Windows because its file
system is case-insensitive, but keep to the casing above.

---

## What each tool unlocks

| Tool | Without it |
|---|---|
| **tshark** | the whole Pcap tab does nothing: no conversations, no TLS handshakes, no pcap findings |
| **dumpcap** | cannot capture live traffic (analysing an existing .pcap only needs tshark) |
| **frida** | no hook bypass, no runtime TLS-pinning bypass, no API tracing |
| **mitmdump** | no Intercept proxy or tamper mode |
| **procdump** | no memory-secret scanning |
| **ilspycmd** | IL still works; only C# reconstruction is unavailable |
| **upx** | UPX-packed binaries are detected but not auto-unpacked |
| **Ollama / API key** | no AI verification; every deterministic check is unaffected |

---

## Wireshark (tshark, dumpcap)

Unlocks the Pcap tab. The single highest-value tool on this page.

**Installed:**

```powershell
winget install WiresharkFoundation.Wireshark
```

Needs admin. The installer offers **Npcap**, which is required for live capture with
`dumpcap`. If you only analyse existing `.pcap` files you can decline it.

Wireshark does **not** add itself to PATH. TCPK handles that: it also checks
`C:\Program Files\Wireshark\` directly, so a default install is found without any PATH
change.

**Portable:** copy `tshark.exe` and `dumpcap.exe` plus their DLLs from an existing
Wireshark install into `tools\wireshark\`.

**Verify:**

```powershell
tshark -v
```

---

## frida

Unlocks hook bypass, runtime TLS-pinning bypass and API tracing. Needs Python first.

```powershell
winget install Python.Python.3.12
pip install frida-tools
```

**Portable:** put `frida.exe` in `tools\frida\`.

**Verify:**

```powershell
frida --version
```

---

## mitmproxy (mitmdump)

Unlocks Intercept proxy and tamper mode.

```powershell
winget install mitmproxy.mitmproxy
```

Or, if you already have Python:

```powershell
pip install mitmproxy
```

**Portable:** download the Windows binaries from <https://mitmproxy.org/downloads> and put
`mitmdump.exe` in `tools\mitmproxy\`.

**Verify:**

```powershell
mitmdump --version
```

---

## ProcDump (Sysinternals)

Unlocks memory-secret scanning. TCPK passes `-accepteula`, so there is no licence prompt
at run time.

```powershell
winget install Microsoft.Sysinternals.ProcDump
```

**Portable:** download <https://download.sysinternals.com/files/Procdump.zip>, extract, and
put `procdump.exe` in `tools\Procdump\`.

Taking a full memory dump needs **administrator**. TCPK writes the dump inside its own
`work\dump\` folder and deletes it as soon as the scan finishes.

**Verify:**

```powershell
procdump -accepteula -? 
```

---

## ilspycmd

Optional. Reconstructs C# in the Decompiler tab. IL disassembly always works without it,
because Mono.Cecil is bundled.

Needs the .NET SDK, not just the runtime:

```powershell
winget install Microsoft.DotNet.SDK.8
dotnet tool install -g ilspycmd
```

`dotnet tool install -g` puts it in `%USERPROFILE%\.dotnet\tools`, which the installer adds
to PATH. Open a new shell afterwards.

**Portable:** put `ilspycmd.exe` in `tools\ilspycmd\`.

**Verify:**

```powershell
ilspycmd --version
```

---

## UPX

Optional. Lets TCPK auto-unpack UPX-packed binaries with `Test-TcpkPacker -Unpack`.
Commercial protectors such as Themida and VMProtect are never touched.

```powershell
winget install UPX.UPX
```

Or download a release from <https://github.com/upx/upx/releases> and put `upx.exe` on PATH.

**Verify:**

```powershell
upx --version
```

---

## Ollama (optional local AI)

Only needed for AI-assisted verification. Every deterministic check works without it, and
no finding depends on it.

```powershell
winget install Ollama.Ollama
ollama pull qwen2.5-coder:7b
```

Runs locally on `http://localhost:11434`. Nothing leaves the machine. Cloud providers are
available in the GUI instead, but those send code to a third party, so do not use them on
material you are under NDA for.

---

## Adding a folder to PATH

Only needed if you install something manually and want it available everywhere. The
portable `tools\` approach avoids this entirely.

**Current user, permanent:**

```powershell
[Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\Program Files\Wireshark', 'User')
```

Open a new PowerShell window afterwards. An existing session does not pick up the change.

**Current session only:**

```powershell
$env:Path += ';C:\Program Files\Wireshark'
```

**Check what a shell can see:**

```powershell
Get-Command tshark, frida, mitmdump, procdump, ilspycmd, upx -ErrorAction SilentlyContinue |
    Select-Object Name, Source
```

Anything missing from that output is not on PATH. That is fine if you put it in `tools\`
instead: TCPK checks there first.

---

## Air-gapped and restricted networks

None of the above needs a network at audit time. Install what you need beforehand, or use
the portable `tools\` layout and copy the whole TCPK folder across.

The one feature that genuinely requires a network **during** the audit is CVE matching,
which queries `api.osv.dev` and `services.nvd.nist.gov`. TCPK ships no offline CVE
database. If the lookup cannot reach them, the report says the dependency surface was not
tested rather than showing a clean supply chain.

---

## Troubleshooting

**"tshark not found" but Wireshark is installed.** Wireshark does not add itself to PATH.
TCPK checks the standard install directories anyway, so confirm it landed in
`C:\Program Files\Wireshark\`. If it is somewhere else, either add that folder to PATH or
copy `tshark.exe` into `tools\wireshark\`.

**Installed it, TCPK still says it is missing.** Open a new PowerShell window. A running
process does not see PATH changes made after it started. If TCPK is running from the GUI,
close and relaunch it.

**pip installed frida but the command is not found.** The Python scripts directory is not
on PATH. Either re-run the Python installer with "Add Python to PATH" ticked, or copy
`frida.exe` from `%LOCALAPPDATA%\Programs\Python\Python3xx\Scripts\` into `tools\frida\`.

**Everything is installed but a whole tab is still empty.** Check the audit output for a
`scan.incomplete-coverage` finding. TCPK reports what it could not run, so an empty result
with no such finding means the checks ran and genuinely found nothing.
