# Security policy

TCPK is a security tool. If you find a vulnerability IN THE TOOL itself, please
report it privately rather than filing a public issue.

## Reporting a vulnerability

Use one of the following, in this order of preference:

1. **GitHub security advisory** (preferred): open a private advisory at
   https://github.com/V33RU/tcpk/security/advisories/new
2. Email: `v33raiot [at] gmail [dot] com`, subject line beginning with `[TCPK
   SECURITY]`. PGP is not available.

Please include:

- TCPK version (`Get-Module TCPK -ListAvailable | Select Version`)
- Windows version and PowerShell version (5.1 or 7+)
- The specific cmdlet or path involved
- Minimum reproduction. A `.ps1` fragment or a `.msix` / `.exe` sample that shows the
  behaviour is more useful than a description
- Impact you assess

## What is in scope

- Command or path injection in a TCPK cmdlet
- Arbitrary read or write outside the tool folder on a normal audit
- Credential or token exposure from the AI-triage layer
- Bypass of the exploit-bucket gate (`Enable-TcpkExploit` + `-ConfirmActive`)
- Any behaviour that would run vendor-supplied code without an opt-in

## What is NOT a vulnerability

- A finding TCPK reports on a real target (that is the tool doing its job).
- Missing detection of a bug class. Please open a normal issue for that.
- Ability to use TCPK on unauthorized targets. Authorization is the operator's
  responsibility; the tool is dual-use by design.
- Findings against `msiexec /a` extraction that ran on YOUR OWN supplied target. This
  is documented; see `Test-TcpkMsiCustomActions`.

## Response

I aim to acknowledge within 3 business days and to give a fix or a decision within
14 days. Coordinated disclosure is preferred: I will ask before publishing details of
a reported issue.

## Third-party components

Bugs in Mono.Cecil, CFR, Pester, mitmproxy, frida, tshark or any other component TCPK
invokes are out of scope here. Report those upstream. TCPK's own use of them
(shell-injection into a tshark command line, an unbounded read from an
untrusted pcap) IS in scope.
