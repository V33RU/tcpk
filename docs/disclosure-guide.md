# Disclosure guide

What to do when TCPK surfaces a serious finding in software you tested.

## The three-question filter

For every CRITICAL or HIGH finding, before drafting anything:

1. **Did I authoritatively confirm the bug?** Static evidence is not exploit
   proof. Decompile (ILSpy) and read the actual code path. If you cannot
   confirm: report as "inferred candidate" and tell the vendor you have not
   exploited it.

2. **Does this affect only me or all customers?** A hardcoded credential
   shipped to every customer's machine is a P0 for the vendor. A weak ACL
   you set on your own machine is a P3.

3. **Is the vendor aware?** Check vendor advisories, CVE databases, and the
   product's release notes. You may be reporting a known issue.

## Picking the right channel

| Type of bug | Channel |
|---|---|
| Shipped hardcoded cloud credential | Vendor PSIRT, before anything else |
| Update mechanism flaw | Vendor PSIRT |
| Auth / cryptographic flaw | Vendor PSIRT |
| Local privesc / DLL hijack | Vendor PSIRT |
| Information disclosure of your own data | Vendor support |
| Hardening hygiene (PE flags, telemetry) | Vendor support |
| In-app prompt for "found a bug?" | Use it; cite TCPK output |

## How to write the report

### Subject line

`Security: <one-line summary>. Confidential, please ack.`

### Body sections

1. **Summary** -- one paragraph. What is the bug? What is the impact? What
   is the suggested fix?
2. **Affected versions** -- exact version string from the binary.
   `Get-AppxPackage *...* | Select Version` for MSIX.
3. **Reproduction steps** -- the actual TCPK command and the relevant
   excerpts from `findings.json`. If you decompiled, the method body.
4. **Impact** -- single-customer, multi-customer, or full supply chain.
5. **Suggested remediation** -- the fix text from the TCPK finding plus
   anything you'd add.
6. **Coordinated-disclosure timeline** -- propose a date (90 days is the
   industry standard; vendors with active triage often request 60).
7. **Attribution** -- "discovered with TCPK (https://...)" is fine if you
   want; not required.

### What to NOT include in writing

- The literal value of any extracted credential. Use prefix/suffix only
  (first 4 + last 4 characters). The full credential goes in a vendor
  secure-upload portal, if at all.
- Working exploit payloads. Describe the path, not the payload.
- Screenshots of decompiled vendor code if avoidable; describe in text.

## Specific guidance: hardcoded cloud credentials

This is the highest-impact finding class TCPK surfaces and the one most likely
to need fast action.

1. **Stop investigation immediately.** Do not authenticate against the cloud
   service with the credential.
2. **Pull the binary off your machine** if you can; do not share it.
3. **Contact PSIRT same day.** Subject line: "Security: shipped cloud
   credential, request urgent triage". Include version, file, byte offset,
   and the prefix/suffix (8 chars each end). Nothing more in writing.
4. **Offer to rotate-test.** Ask the vendor to confirm the new key works in
   the next build, but do not test it yourself.
5. **Public disclosure timeline.** 90 days from vendor confirmation; reduce
   to 30 days if the vendor will not engage. Coordinate publication with
   them.

## Specific guidance: supply-chain primitives

When TCPK finds "hardcoded credential + update flow + no signature
verification" -- the supply-chain primitive pattern:

1. **Same as above for the credential.** Plus:
2. **Request expedited coordination** -- this affects all customers.
3. **Offer to assist with the fix design.** Most vendors do not have an
   in-house designer of secure update flows; sharing a sketch is helpful.
4. **Do not publish until the vendor has rotated and shipped the fix.**
   Customers cannot patch until the new build is available.

## When the vendor doesn't respond

- 30 days no response: escalate via CERT/CC or a regional CERT.
- 60 days no response: notify any major distributors (Microsoft Store team
  for MSIX, GitHub Security Advisory if open-source dep affected).
- 90 days no response: public disclosure is appropriate. Coordinate with a
  defender / journalist who can amplify pressure.

## When you are wrong

- Apologize promptly.
- Ask the vendor to suggest how to test better next time.
- Update TCPK's rules if the false-positive pattern is generalizable.
- Do not delete the report thread -- future researchers benefit from the
  paper trail.

## Templates

### Initial disclosure

```
To: psirt@vendor.com
Subject: Security: shipped Azure Storage credential in <Product> v<X.Y.Z>. Confidential.

Hello,

We've identified a hardcoded Azure Storage account-level shared key
shipped in <Product> v<X.Y.Z>. The credential format matches Azure's
canonical pattern (88-char base64 in a DefaultEndpointsProtocol=...
connection string), and we believe it grants account-level read/write to
the storage account named "<account-name>".

We have not exercised the credential and will not. Suggesting urgent
triage given the credential is in every customer's install.

Affected file: YourApp.Services.dll (UTF-16LE byte offset ~163k)
Credential prefix/suffix: LKue...yJiw==

We can transfer the full credential value via a secure channel of your
choice (PSIRT portal, encrypted email). We will not share it elsewhere.

Proposed timeline: 90 days from your acknowledgment to public disclosure,
which we would coordinate with you in advance.

<your name / org>
```

### Follow-up reminder (after 7 days no ack)

```
Bumping the thread below. Please confirm receipt; we have a 90-day
disclosure clock running per industry norms. Happy to extend if you tell
us why and when you can engage.
```
