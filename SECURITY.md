# Security Policy

bawbel-gate is enforcement software. A vulnerability in it can mean an agent bypasses
a control it should have been denied. Report privately, and report anything that
looks like an effect resolving more permissively than DESIGN.md says it should.

## Scope

**In scope:** this repository (`bawbel-gate`), including the policy engine, taint
tracker, trifecta invariant, MCP multiplexer, argument guards, audit chain,
integrity pinning, learning mode, and the Console API (once shipped).

**Out of scope, report to the relevant repo instead:**
- AVE record content or the AVE schema: [aveproject/ave](https://github.com/aveproject/ave),
  an independent project. Contact: aveproject.org@gmail.com.
- bawbel-scanner detection rules: [bawbel/scanner](https://github.com/bawbel/scanner).
- PiranhaDB API availability or data correctness: the `piranha-api` repository.

**Explicitly in scope even though they may look like "just a bug":**
- Any input that makes an `allow`/`approve`/`deny` decision resolve more
  permissively than DESIGN.md §5 specifies.
- Any way to reach `EXECUTED` from `PENDING_APPROVAL` without a granted decision.
- Any way to disable, skip, or narrow the trifecta invariant (DESIGN.md §5.2 step
  6) through manifest content, configuration, or timing.
- Any way to falsify, reorder, or gap the audit chain without detection by
  `bawbel-gate audit verify`, other than the limits listed under
  "Limits of the audit chain" below.
- Any way to make `tools/list` expose a tool that should be denied and hidden.
- Argument-guard bypasses that let a secret or over-length payload reach an
  upstream call undetected.

## Limits of the audit chain

`bawbel-gate audit verify` shows that, in the file it is given, no record was edited,
deleted, inserted, or reordered without every hash after it being recomputed. It does not
show:

- **Records removed from the end.** The remaining chain is still valid. A head recorded
  outside the log catches this.
- **A log rewritten from the first record.** The chain uses no key, so whoever can write the
  file can rebuild every hash and `audit verify` passes. A head recorded outside the log
  before the rewrite catches this too. See
  [docs/adr/0001-audit-chain-construction.md](docs/adr/0001-audit-chain-construction.md).
- **That the gate was running correctly when the records were written.** A record is what the
  gate wrote. It does not show that the decision it records was right, or that the gate was
  running between two records.
- **Non-repudiation.** A compromised gate can write any record, correctly chained. Tying
  records to one gate needs asymmetric signing, which is not implemented.

How to record a head, and how to check a log against it, is in the README under
"Verifying a log you did not write".

## Reporting a vulnerability

**Do not open a public issue.** Report privately using either:

- GitHub Security Advisories: use the "Report a vulnerability" button under this
  repository's Security tab.
- Email: **bawbel.io@gmail.com**. PGP is not required; if you want to encrypt,
  ask for a key first and we will provide one.

Include, as far as you have it:

- The invariant or behavior violated (cite a DESIGN.md section if you can).
- A manifest, session sequence, or config that reproduces it.
- Impact: what an attacker gains (effect escalation, audit tampering, secret
  exfiltration, drift detection bypass, etc).
- Whether you have a proposed fix.

You do not need to have a full exploit. A convincing argument that an invariant in
`references/invariants.md` can be violated is enough to open a report.

## Response targets

We are a small team; these are targets, not contractual SLAs.

| Step | Target |
|---|---|
| Acknowledgment | 3 business days |
| Initial severity assessment | 7 calendar days |
| Status update cadence while open | at least every 14 days |
| Fix or mitigation for confirmed Critical/High | 30 days from confirmation |
| Fix or mitigation for confirmed Medium/Low | 90 days from confirmation |
| Coordinated public disclosure | 90 days from confirmation, or on fix release,
whichever is sooner, by mutual agreement with the reporter |

Severity follows CVSS with agentic-context judgment: a bypass of the trifecta
invariant or an audit-chain forgery is treated as Critical regardless of how
narrow the reproduction steps are, because the invariant's entire purpose is to
hold under adversarial input.

If we miss a target, you will hear that directly and get a reason, not silence.

## Coordinated disclosure

We follow standard coordinated disclosure: the report stays private between the
reporter and maintainers until a fix is available or the response-target window
lapses, whichever comes first. Extensions past 90 days happen only by mutual
agreement, typically because a fix requires a breaking manifest-schema change that
needs its own review cycle (DESIGN.md interface freeze rules apply to fixes too).

Reporters are credited in the advisory and release notes unless they ask not to
be. We do not require exclusivity or an embargo on the reporter's own writeup past
the agreed disclosure date.

## Safe harbor

Good-faith security research against this repository's code, run against your own
local install or a test instance you control, is authorized. We will not pursue
legal action for research conducted consistently with this policy: no accessing
data that is not yours, no service disruption to others, and a private report
before public disclosure.

## Supported versions

Pre-1.0: only the latest tagged release receives fixes. From 1.0 onward, the
current and immediately prior minor version receive security fixes; this table
will be updated at the 1.0 release.

| Version | Supported |
|---|---|
| Latest release (0.1.x) | yes |
| Earlier releases | no; upgrade to the latest release |
| `main`, `develop` (unreleased) | best effort |

## CVE assignment

bawbel-gate is not yet a CVE Numbering Authority. Until it is, confirmed
vulnerabilities are requested through MITRE's CVE Request form
(<https://cveform.mitre.org>) or a partner CNA, and the CVE ID is added to the
advisory once assigned. This section will be updated with our CNA scope once
onboarding completes.

## Dependencies

We track upstream advisories for direct dependencies via Dependabot and
OpenSSF Scorecard. A vulnerability in a dependency that is reachable through
bawbel-gate's attack surface (not merely present in the tree) is in scope for
this policy; report it the same way.
