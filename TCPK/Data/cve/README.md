# TCPK CVE catalog

Offline, curated CVE database for libraries commonly bundled inside Windows
thick-client applications. Used by `Get-TcpkCveMatches` to flag shipped
components with known vulnerabilities, and by `Get-TcpkExploitPlan` to drive the
GUI **Exploit** tab.

## How matching works

- **ecosystem `nuget`** -- matched against `*.deps.json` packages and the recon
  SDK inventory by package **name** (case-insensitive). A shipped version
  `< below` (the first FIXED version) is reported vulnerable.
- **ecosystem `native`** -- matched against shipped DLL **filenames** and their
  `FileVersion`. Native libs are often statically linked into a larger DLL
  (e.g. libwebp inside Skia/WebView2), so a native match with no determinable
  version is reported at lower confidence with a "verify embedding" note.

## Adding an entry

Append to `catalog.json` -> `cves`:

```json
{
  "id": "CVE-YYYY-NNNNN",
  "ecosystem": "nuget",
  "packages": [{ "name": "PackageName", "below": "1.2.3" }],
  "area": "short component/area label",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cwe": ["CWE-xxx"],
  "title": "one-line",
  "summary": "what it is + how it is exploited",
  "exploit": { "type": "version-presence|construct-reachable", "rule": "optional finding ruleId prefix", "guide": "optional manual PoC steps" },
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN"]
}
```

## Important

- `below` is the first **fixed** version. Confirm exact branch ranges against
  the linked NVD/GHSA advisory -- many libraries fix the same CVE across several
  release lines (e.g. 2.1.7 / 3.1.5 / 5.1.3).
- This catalog enables **version-presence detection only**. It ships **no**
  weaponized exploits. Exploitability is verified locally, against an
  **authorized** target, via the gated Exploit bucket (`Enable-TcpkExploit`).
