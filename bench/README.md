# TCPK Detection Benchmark

A small, curated corpus that measures TCPK's detection quality as **numbers**, not vibes:
how many planted vulnerabilities it catches (recall) and how much of what it flags is
real (precision). It exists to answer "is this tool actually finding bugs, or guessing?"
and to stop precision/recall from silently regressing.

## How it works

- `corpus/<case>/` -- a tiny fixture. Some plant a known vulnerability; some are clean or
  contain only obvious placeholders (to catch false positives).
- `expectations.json` -- for each case, the check to run plus:
  - `detect[]` -- rule-id regexes that **should** fire (the planted bug).
  - `forbid[]` -- rule-id regexes that must **not** fire (clean / placeholder).
- `Invoke-TcpkBenchmark.ps1` -- runs each check against its fixture and scores:

  | | flagged | not flagged |
  |---|---|---|
  | **planted bug** (`detect`) | TP | FN |
  | **should be quiet** (`forbid`) | FP | TN |

  `precision = TP / (TP + FP)` &middot; `recall = TP / (TP + FN)`

Every expected rule-id is **verified against the live check** before it goes in the
manifest -- no aspirational expectations.

## Run it

```powershell
.\bench\Invoke-TcpkBenchmark.ps1        # regenerates SCORECARD.md, returns a result object
```

The benchmark is also a CI gate: `TCPK/Tests/Benchmark.Tests.ps1` fails the suite if
precision or recall drops below threshold.

## Scope

The corpus currently covers the **text/JS-scanned** checks -- Electron renderer config +
TLS certificate validation, and secret scanning -- where a plain-text fixture faithfully
exercises the detector. Binary-scanned checks (crypto misuse, cleartext schemes, PE
hardening, IL callsite taint) require compiled fixtures and are a tracked follow-on; they
are deliberately **not** counted yet rather than scored against fixtures that don't
exercise them.

See [`SCORECARD.md`](SCORECARD.md) for the latest run.
