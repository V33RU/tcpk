# TCPK + LLM Integration Roadmap

How to add an LLM reasoning layer to TCPK.

Design decisions (locked in):
- **Backend:** operator-selectable. Local Ollama is the default (offline, safe for
  secrets); cloud APIs (Claude / OpenAI / Azure OpenAI / corporate gateway) are
  opt-in for non-sensitive targets. Provider-agnostic chat-completions interface.
- **First feature:** decompiled-code judgment (feed IL / decompiled methods to the
  LLM, ask "is this exploitable?").

## Why an LLM fits TCPK

TCPK already produces structured `[TcpkFinding]` objects (severity, confidence,
evidence, file, byte offset, CWE). The mechanical layer (find candidates) is done.
The LLM adds the *judgment* layer that is currently the human's job during triage:
"is this a real bug or a false positive?", "does this decompiled lambda actually
disable TLS?", "which 3 of these 1000 findings matter?". This session is the proof
case -- every false positive we hand-triaged is a task an LLM can do.

## Security-first principles (non-negotiable for a pentest tool)

1. **Local by default.** Findings contain extracted secrets, internal URLs, and
   decompiled proprietary code. Default backend is local Ollama; nothing leaves
   the machine unless the operator explicitly opts into a cloud provider.
2. **Explicit opt-in for cloud.** Same pattern as the Exploit bucket
   (`Enable-TcpkExploit -Acknowledge`). Cloud LLM use requires
   `Enable-TcpkLlmCloud -Acknowledge` and prints what will be sent.
3. **Redaction before send.** Even for cloud, secret VALUES are redacted to
   prefix/suffix before any prompt is built (the evidence field is already
   redacted; enforce it at the LLM boundary too).
4. **No autonomous actions.** The LLM advises; it never runs cmdlets, writes
   files, or launches processes. Output is text/JSON the operator reads.
5. **Offline-capable.** The tool must fully function with the LLM layer disabled.
   LLM is an enhancement, never a dependency.

## Architecture

```
                  [TcpkFinding] objects
                          |
                          v
            +-----------------------------+
            |  Private\_Llm.ps1           |   provider-agnostic client
            |  Invoke-TcpkLlm             |   - builds prompt
            |   -SystemPrompt -UserPrompt |   - calls backend
            |   -Schema (optional JSON)   |   - parses response
            +--------------+--------------+
                           |
          +----------------+----------------+
          v                                 v
   Ollama (local)                  Cloud (opt-in, gated)
   POST /api/chat                  POST /v1/chat/completions
   http://localhost:11434          (Claude / OpenAI / Azure / gateway)
```

One internal function `Invoke-TcpkLlm` speaks the OpenAI-style
chat-completions shape. Ollama exposes an OpenAI-compatible endpoint at
`/v1/chat/completions`, so a single code path covers both -- only the base URL
and auth header differ, set via config.

### Config file: `TCPK\Data\llm-config.json`

```json
{
  "enabled": false,
  "backend": "ollama",
  "ollama":  { "baseUrl": "http://localhost:11434/v1", "model": "qwen2.5-coder:7b" },
  "cloud":   { "baseUrl": "", "model": "", "apiKeyEnvVar": "TCPK_LLM_KEY", "acknowledged": false },
  "maxFindingsPerBatch": 20,
  "redactSecrets": true
}
```

API keys come from an environment variable named in the config, never stored in
the file.

## Phased build

### Phase L0 -- Foundation (0.5 day)
- `Private\_Llm.ps1`: `Invoke-TcpkLlm` (provider-agnostic chat call, retry, JSON-schema
  validation), `Get-TcpkLlmConfig`, `Test-TcpkLlmAvailable` (ping the backend).
- `Public\Llm\Enable-TcpkLlmCloud.ps1` / `Disable-TcpkLlmCloud.ps1` (the cloud gate).
- `Data\llm-config.json` default (local, disabled).
- Connectivity test cmdlet: `Test-TcpkLlm` -> "backend reachable, model X responding".

### Phase L1 -- Decompiled-code judgment (FIRST FEATURE) (1.5 days)
- `Public\Llm\Invoke-TcpkLlmCodeJudgment.ps1`.
- Pipeline: for findings whose RuleId implies a code construct
  (`callsites.*`, `tls-bypass.*`, `deser.*`, `xxe.*`, `webview2.*`):
  1. Use the existing Mono.Cecil bridge to extract the relevant method's IL /
     decompiled C# (we already proved this works on the YourApp TLS callback).
  2. Build a prompt: "Here is a decompiled method flagged for <rule>. Does it
     actually exhibit the weakness? Answer real / not-real / uncertain with a
     one-line reason."
  3. Force structured JSON output: `{ verdict, confidence, reason }`.
  4. Update the finding's Confidence and append the LLM reason to Description.
- This automates exactly the TLS-callback verification we did by hand:
  `ldc.i4.1; ret` -> LLM says "returns true unconditionally -> real TLS bypass".

### Phase L2 -- Auto-triage / FP killer (1 day)
- `Public\Llm\Invoke-TcpkLlmTriage.ps1`.
- Batch findings (config `maxFindingsPerBatch`); for each: evidence + file + rule ->
  LLM verdict real/FP/verify with reason. Feeds the same Confidence field.
- Catches the FP classes we hand-fixed this session (HTML placeholders, System32
  DLLs, resource-only PEs) generically, without hardcoded rules.

### Phase L3 -- Report narrative + correlation (1 day)
- `Public\Llm\New-TcpkLlmSummary.ps1`: feed the full (triaged) finding set ->
  LLM writes the executive summary, the prioritized fix list, and identifies
  cross-finding attack chains (Azure key + unsigned update = supply chain).
- Injected into the top of the HTML report as an "Analyst summary" panel.

### Phase L4 -- Interactive Q&A (1 day)
- GUI: add a chat box bound to the loaded findings. Operator asks
  "what's network-exploitable?", "what do I fix first?" -> `Invoke-TcpkLlm`
  with the findings as context.

### Phase L5 -- Remediation generation (0.5 day)
- Per-finding "generate fix for my stack" -> tailored code, beyond the generic
  rule templates.

Total: ~5.5 days for the full LLM layer; ~2 days to ship L0 + L1 (the chosen
first feature).

## Recommended models (local Ollama)

| Model | Size | Best for |
|---|---|---|
| `qwen2.5-coder:7b` | ~4.5 GB | Code judgment (L1) -- strong on reading decompiled code |
| `qwen2.5-coder:14b` | ~9 GB | Better judgment if RAM/GPU allows |
| `llama3.1:8b` | ~4.7 GB | General triage / summary (L2/L3) |
| `phi4` | ~9 GB | Good reasoning-per-GB |

For L1 (code judgment) a coder-tuned model is the right pick.

## Risks / honest caveats

- **LLM hallucination on exploitability.** An LLM can confidently call a safe
  method exploitable or vice versa. Mitigation: LLM output is always labelled
  `Confidence = Inferred (LLM)`, never `Confirmed`. The byte/IL evidence stays in
  the finding so a human can check. The LLM augments triage, it does not replace
  the deterministic checks.
- **Local model quality.** A 7B model is weaker than frontier cloud models. For
  high-stakes findings the operator can opt into a cloud model for that finding.
- **Performance.** Local inference is seconds-per-finding. Batch + only run the
  LLM layer on MEDIUM+ findings by default (INFO inventory does not need it).
- **Determinism.** LLM verdicts vary run to run. Set temperature low (0-0.2) and
  record the model + version in the finding for reproducibility.

## First concrete deliverable

If you greenlight: build **L0 + L1**, then demo it by re-running the
YourApp TLS-callback finding through `Invoke-TcpkLlmCodeJudgment` and
showing the LLM independently concludes "returns true unconditionally -> real
TLS bypass" from the decompiled method -- matching our manual verdict.
