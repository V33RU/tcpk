# User-authored TCPK rules

Drop `*.json` rule files here. TCPK loads them at scan time and runs them alongside the
built-in checks. See `docs/EXTENDING.md` for the schema and worked examples.

Phase 1 supports one check type: **file-regex**. File glob + regex over file contents.
More types (registry, PE-import, .NET IL call-site) land in later phases if this format
gets adoption.

Rules are sandboxed by construction: they can pattern-match, they cannot execute anything.
If you want a check that spawns a process or loads a DLL, contribute a PowerShell cmdlet
under `TCPK/Public/` instead.
