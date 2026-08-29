# Extending TCPK

Two ways to add detection without editing PowerShell.

## 1. User rules (`TCPK/Data/rules/*.json`)

Drop a JSON file into `TCPK/Data/rules/`. TCPK loads it at scan time and runs it alongside
the built-in checks. Rules are pure pattern-matches; they cannot execute anything, load a
DLL or reach the network. That is enforced by construction: the schema has no `script`,
`run`, `command` or `exec` field, and unknown fields are refused at load time.

### Minimum viable rule

```json
{
  "id": "user.hardcoded-slack-webhook",
  "title": "Hardcoded Slack incoming-webhook URL",
  "severity": "HIGH",
  "type": "file-regex",
  "cwe": ["CWE-798"],
  "description": "A Slack incoming-webhook URL is present in a shipped resource. Anyone with the URL can post to that channel until it is rotated.",
  "fix": "Rotate the webhook in the Slack app configuration, then load it at runtime from a secret store rather than a shipped file.",
  "match": {
    "glob": "**/*.config",
    "regex": "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
    "prefilter": ["hooks.slack.com"]
  }
}
```

Load it:

```powershell
Test-TcpkUserRules -Path 'C:\Program Files\Vendor\App'
```

### Fields

Top-level:

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Lowercase, contains a dot, 3-80 chars from `[a-z0-9_.-]`. Namespace it with a prefix like `user.` or your vendor name so it will not collide with a built-in id. |
| `title` | no | Shown in the report. Defaults to `id`. |
| `severity` | yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Grade honestly; a pattern match is `Inferred`, not `Confirmed`. |
| `type` | no | Only `file-regex` in Phase 1. Defaults to it. |
| `cwe` | no | Array of CWE ids, e.g. `["CWE-798"]`. |
| `description` | yes | One paragraph, tells the report reader what the finding means. |
| `fix` | yes | One paragraph, tells the report reader what to do about it. |
| `match` | yes | Type-specific match block. See below. |

`match` block for `file-regex`:

| Field | Required | Notes |
|---|---|---|
| `glob` | yes | Path glob relative to the target. Supports `**` (any depth including zero), `*` (single segment), `?` (single char). No brace expansion in Phase 1. |
| `regex` | yes | .NET regex over file contents. Compiled and validated at load time; a malformed regex fails to load rather than at scan time. |
| `ignoreCase` | no | Boolean, default `true`. |
| `maxHits` | no | Cap on match count reported per file, default 8. Bounds the noise a bad regex can produce. |
| `prefilter` | no | Array of literal strings. If given, at least one must appear in the file text before the regex runs. Same shape as `secrets.json`, purely a performance optimisation. |

### What is safe, what is not

- Rules can match. Rules cannot run.
- Unknown fields are refused at load time. Adding a new capability to the format takes a change to the loader; you cannot slip it in through a rule file.
- Duplicate rule ids are refused with a Skipped finding naming the duplicate.
- A malformed rule (bad JSON, missing field, bad regex) becomes a Skipped `rules.malformed` finding rather than being silently dropped.
- Regex is unbounded on complexity. Pathological patterns (e.g. `(a+)+$`) can be slow. Test yours against a real file before shipping.

### What is coming later, and what will not

Later phases (subject to demand): registry check type, PE-import check type, .NET IL call-site
check type, MSIX capability check type. Same JSON schema, additional `type` values.

**Not planned**: a `run` or `script` field. If you want a check that spawns a process, contribute
a PowerShell cmdlet under `TCPK/Public/` instead. The rule format is intentionally the constrained
extension surface.

## 2. Editing the shipped data files

The following files are already user-editable and TCPK re-reads them at run time. They cover
narrower classes than the general rule format but are the fastest way to add a specific pattern
in that class.

| File | Class | Example |
|---|---|---|
| `TCPK/Data/secrets.json` | Credential patterns in files, callsite tokens, deserialization markers | Add a new API-key format |
| `TCPK/Data/electron-js-sinks.json` | JS sinks the Electron detector looks for in bundled JS | Add a new `require('mymodule').exec` sink |
| `TCPK/Data/exploit-map.json` | Which findings feed which exploit-plan action | Wire a new rule id to an existing action |
| `TCPK/Data/patterns/*.json` | Byte-pattern layouts for `Get-TcpkFileStructure` | Add a new firmware header format |
| `TCPK/Data/checklist/thick-client-checklist.json` | The 55-case methodology sheet, and which rule ids feed each row | Add a rule id to an existing case |

Every one takes an in-place edit and a re-run. Test yours; a malformed JSON breaks the load.

## Contributing back

If a rule is useful across engagements, open a PR against `TCPK/Data/rules/`. Same discipline as
the built-in rules: real detection, honest confidence label, description that says what it means,
fix that says what to do.
