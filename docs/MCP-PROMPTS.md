# TCPK MCP Prompts - ready-to-use workflows

A curated set of prompts that drive TCPK through its [MCP server](MCP-USAGE.md). Type any
of them to an MCP client that has the `tcpk` server connected (Claude Code, Claude Desktop,
Cursor), filling in the bracketed arguments. Each one steers the model to call the right
`tcpk_*` tools in the right order and to report under TCPK's rules: recon first, proven
findings separated from leads, nothing invented that a tool did not return.

Every prompt uses only the tools the server actually exposes (see the tool table in
[MCP-USAGE.md](MCP-USAGE.md#3-tools-exposed)). They can also be registered as formal MCP
prompts in `Start-TcpkMcpServer.ps1` (the server's `prompts/list` is currently empty) so a
client surfaces them as one-click commands. Ask if you want that wired in.

| Prompt | Purpose | Arguments | Tools |
|---|---|---|---|
| `tcpk_full_assessment` | End-to-end audit of one target | `target`, `profile?` | recon_profile, audit, get_findings, exploit_plan |
| `tcpk_quick_recon` | Identify a target before scanning | `target` | info, recon_profile |
| `tcpk_triage_leads` | Turn pattern-match leads into proven bugs | `target` | get_findings, decompile |
| `tcpk_hunt_secrets` | Hardcoded creds, keys, connection strings | `target` | strings, embedded_blobs, byte_search, get_findings |
| `tcpk_decompile_review` | Read the real C# of a risky method | `target`, `symbol` | recon_profile, decompile |
| `tcpk_cve_report` | Bundled-library CVE exposure | `target` | recon_profile, cve_match |
| `tcpk_attack_path` | Chain findings into an exploit path | `target` | get_findings, exploit_plan |
| `tcpk_report_writeup` | The TCPK-format finding writeup | `target`, `rule_id?` | get_findings |
| `tcpk_compare_builds` | Supply-chain / tamper diff | `baseline`, `candidate` | file_structure, file_diff |
| `tcpk_poc_for_finding` | Gated, lab-only PoC for a confirmed finding | `target`, `rule_id` | get_findings, generate_poc |
| `tcpk_demo_walkthrough` | Guided Arsenal-style demo | `target` | recon_profile, audit, decompile, get_findings, exploit_plan |

---

## tcpk_full_assessment
End-to-end audit of one target. Arguments: `target` (path), `profile` (Quick or Full, default Full).

> Assess the thick client at `{target}`. First `tcpk_recon_profile` it and state app type,
> runtime, UI, and signing. Then run `tcpk_audit` (profile `{profile}`). Pull results with
> `tcpk_get_findings`. Report proven findings first, leads separately, never mixed. End with
> the one-line risk verdict (proven HIGH+ vs raw HIGH+). Do not invent findings the tools
> did not return.

## tcpk_quick_recon
Identify a target before committing to a scan. Arguments: `target`.

> Profile `{target}` with `tcpk_recon_profile` only. Report name, version, publisher, runtime
> (.NET / Electron / native), UI framework, architecture, signing status, and the discovered
> network endpoints / protocol handlers. Recommend which audit profile fits. Run no audit yet.

## tcpk_triage_leads
Turn pattern-match leads into proven bugs. Arguments: `target`.

> Fetch findings for `{target}` via `tcpk_get_findings`. Split them: Confirmed (proven) vs
> Inferred / Unverified (leads). For each lead, say exactly what deterministic step would
> confirm it (IL data-flow, decompile the method, a dynamic check). Where it is a managed
> callsite, use `tcpk_decompile` on the method to show the source path. Promote only what a
> tool actually proved; report the rest as leads to triage, not as bugs.

## tcpk_hunt_secrets
Hardcoded credentials, keys, connection strings. Arguments: `target`.

> Hunt secrets in `{target}`. Use `tcpk_strings` and `tcpk_embedded_blobs` for candidates,
> `tcpk_byte_search` to confirm a specific pattern, and `tcpk_get_findings` for the credential
> / crypto findings. For each hit give the format (JWT / API key / connection string / AES-IV),
> the file, and whether it is live or decryptable. No speculation - only what is present in
> the binary.

## tcpk_decompile_review
Read the actual C# of a risky method. Arguments: `target` (dll or exe), `symbol` (type or method name).

> Decompile `{symbol}` in `{target}` with `tcpk_decompile` (whole type). Walk the code: trace
> any external input to a dangerous sink (SQL, exec, file, deserialize, WebView). State whether
> it is reachable and injectable, or guarded. Quote the exact decompiled lines, not a paraphrase.

## tcpk_cve_report
Bundled-library CVE exposure. Arguments: `target`.

> List the third-party components TCPK sees in `{target}` and run `tcpk_cve_match`. Report each
> as Vulnerable / Patched / Unknown with the shipped version and the fixed-in floor. Call out
> anything with a public exploit. Do not claim a CVE the matcher did not return.

## tcpk_attack_path
Chain findings into an exploit path. Arguments: `target`.

> Build the attack path for `{target}` with `tcpk_exploit_plan` over the current findings. Show
> step 1 -> step 2 -> step 3, the attacker position each step needs, and what the attacker ends
> with. Only chain findings the tools proved; mark any inferred link as unproven.

## tcpk_report_writeup
The TCPK-format writeup. Arguments: `target`, `rule_id` (optional, a single finding).

> Write up the confirmed findings for `{target}` (or just `{rule_id}` if given) in TCPK's
> finding format: title + CWE, confidence, attacker position, location, root cause, data flow,
> trigger, confirmation, evidence, exploit chain, CVSS 4.0 vector, and the minimal fix.
> Confirmed only by default. Keep the evidence as captured, not paraphrased.

## tcpk_compare_builds
Supply-chain / tamper diff. Arguments: `baseline` (path), `candidate` (path).

> Compare `{baseline}` and `{candidate}` with `tcpk_file_structure` and `tcpk_file_diff`. Report
> added / removed / changed files, focus on binaries and configs, and flag any unsigned or
> newly-introduced executable or any changed update / endpoint config. State what a defender
> should verify.

## tcpk_poc_for_finding
Gated, lab-only PoC. Arguments: `target`, `rule_id`.

> For confirmed finding `{rule_id}` on `{target}`, draft a lab-safe PoC with `tcpk_generate_poc`.
> Authorized testing only. Include the header (target, version, prerequisites), the exact run
> command, and the observable effect. For memory corruption, stop at proof-of-control (crash
> with an ASAN / fault address, or PC = 0x41414141); no shellcode, ROP, or persistence. If the
> finding is only a lead, refuse and say what must be confirmed first.

## tcpk_demo_walkthrough
Guided Arsenal-style demo. Arguments: `target` (e.g. a DVTA path).

> Run a narrated demo on `{target}`: profile it, run the audit, show the proven-vs-leads split,
> decompile one juicy method (connection string or SQLi), then the attack path. Keep it tight
> and say what each step proves.

---

## Composing with other MCP servers

Because these are plain prompts, they compose with any other connected server:

> Run `tcpk_full_assessment` on `{target}`, then open a ticket on my Jira MCP server for every
> proven CRITICAL or HIGH.

> `tcpk_cve_report` the target, then post the vulnerable-library list to the right Slack channel.

## Authorization

All of these are for authorized testing only. `tcpk_poc_for_finding` maps to the gated
`tcpk_generate_poc` tool, which refuses unless you assert authorization and only ever generates
artifacts - it never deploys or attacks. See [MCP-USAGE.md](MCP-USAGE.md#5-authorization--safety).
