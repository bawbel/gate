---
status: proposed
date: 2026-11-22
---

# 0002. Hub per-gate credential: a hashed secret behind an operator TLS proxy now, mTLS later

Status is proposed because this was drafted for the maintainer's review. The decision it
records is the maintainer's, taken on 2026-11-22.

The hub identifies a gate by a per-gate secret that it stores hashed, takes the `gate_id`
from that credential, and leaves TLS to a reverse proxy the operator runs. A per-gate mTLS
client certificate from a hub-run CA, which DESIGN.md 14.3 specified before, comes later
and gets its own ADR. The property that matters is that `gate_id` comes from the
credential and not from the URL, and it holds under either model.

## Context

DESIGN.md 14.3 and 13.2 specified a per-gate mTLS client certificate issued by the hub,
with the certificate CN as the `gate_id`. The code has none of it: ingest accepts the
hub's admin token and takes `gate_id` from the request path, `hub serve` listens on plain
HTTP, and the hub does not check that an id was ever issued (DESIGN.md 14.3, "Implementation
status"). Running a certificate authority is real operating work for a solo maintainer.

## Decision

- Enrollment returns a per-gate secret and a `gate_id`, once. The hub stores a hash of the
  secret.
- Ingest requires the secret. The hub takes `gate_id` from the credential and refuses a
  request whose path names a different one.
- The hub does not terminate TLS. The operator terminates it at a reverse proxy. The hub
  binds to loopback by default and refuses another address unless it is started with the
  explicit option `--tls-terminated-by-proxy`.
- A per-gate secret is revoked by a revoke command, immediately: ingest then returns 403,
  stored records stay, and re-enrolling the gate issues a new secret.
- mTLS with a hub-issued certificate is deferred to its own ADR.

The hub keeps no write path toward gates and stays self-hosted (DESIGN.md 14.6 and 13.4
hold). Nothing in this decision adds a licence check, an entitlement check or a feature
flag.

## Considered options

- **A. Implement as specified.** A hub CA, a per-gate certificate at enrollment, mTLS on
  ingest. It binds the identity to a key that stays on the machine. It needs a CA, issuance,
  renewal and revocation, which is the most work and the longest time before any attribution
  exists.
- **B. A per-gate secret and operator TLS, with no later step.** The same as the chosen
  option without the commitment to revisit.
- **C. B now, A later.** Chosen. It ships the property that matters in days and keeps the
  certificate model open.

## Consequences

- A per-gate secret identifies whoever holds it. A copied secret lets its holder post as
  that gate until the secret is revoked. A client certificate bound to a key that does not
  leave the machine would narrow that, which is the reason for the later step.
- Without a TLS proxy the secret and the admin credentials cross the network in clear text.
  The refusal to bind a non-loopback address unless TLS in front is declared makes that a
  declared choice and not a default.
- DESIGN.md 14.3 also sets token lifetimes, two roles, hashed admin and enrollment tokens,
  a cookie session for the console, and the removal of credentials from URLs. Those do not
  depend on this choice and are in the same change.
- Revocation needs no list: a revoked secret stops working at once, and a gate that is
  re-enrolled gets a new one.

## Revisit when

The maintainer decides to take the mTLS step. That decision gets its own ADR.
