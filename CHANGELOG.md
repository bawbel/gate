# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

0.1.0 is the first release. The M0-M7 build (project scaffold through policy
engine, integrity pinning, operations layer, embedded console, and bawbel-hub)
is documented as milestones in README's "What is built" table rather than
itemized here; this file picks up from that baseline.

## [Unreleased]

## [0.1.1] - 2026-10-12

README and metadata fixes for the PyPI project page. No code changes.

### Added

- `Changelog` project URL in package metadata.

### Fixed

- README links, the console image, and in-page anchors were relative, so none
  of them resolved on the PyPI project page, which renders README.md. They are
  now absolute GitHub URLs, and the #27 and #28 references are links.

## [0.1.0] - 2026-10-11

First release on PyPI: `pip install bawbel-gate`.

### Added

- MCP multiplexer request loop (`mux/proxy.py`): `bawbel-gate serve` and
  `serve --console` previously did nothing -- the enforce/learn loop was a
  stub. Now spawns upstream servers, merges/namespaces `tools/list`, routes
  every `tools/call` through the policy engine, forwards on allow/approve,
  denies without touching upstream, and writes the hash-chained audit trail.
- Real console dashboard (sessions/servers tables, pending-approvals panel,
  live audit feed via SSE), replacing a bare JSON dump.
- Minimal browser UI for `bawbel-hub` (`/` route, `?t=` query-token auth),
  per DESIGN.md 14.4.
- `GOVERNANCE.md` and `CODE_OF_CONDUCT.md`.
- Full PyPI packaging: complete metadata, trusted-publishing workflow
  (auto to TestPyPI, manual-approval gate to production PyPI).
- CI security pipeline on every PR and push to `develop`/`main`: CodeQL
  (code-scan.yml), Dependency Review + pip-audit (dependency-scan.yml),
  Gitleaks (secret-scan.yml). Repo-level secret scanning, push protection,
  and Dependabot security updates enabled.
- OpenSSF Scorecard workflow and badge.
- Issue forms, PR template, and CODEOWNERS; CONTRIBUTING.md requires an issue
  before a PR and a property test committed before the implementation (#17).

### Fixed

- The proxy returned whatever message an upstream wrote next as the response
  to a `tools/call`. An upstream notification or server-to-client request
  written first replaced the result and shifted every later result from that
  server. Responses are now matched by `id`; upstream notifications are
  dropped and server-to-client requests refused with `-32601` (#21).
- `bawbel-hub`'s `/v1/enroll` required the admin bearer token an unenrolled
  gate doesn't have yet -- the single-use enrollment token is itself the
  credential (DESIGN.md 14.3). The documented enroll flow was unreachable.
- `ConsoleServer` used a plain `http.server.HTTPServer` (one request at a
  time), so a single open `/v1/events` SSE connection starved every other
  request, including the page itself. Switched to `ThreadingHTTPServer`.
- `_schemas.py` located `schemas/` via a repo-root-relative path that only
  resolves inside an editable/source checkout. A real `pip install
  bawbel-gate` wheel would have raised `FileNotFoundError` on every
  schema-dependent command. Schemas are now bundled into the wheel and
  `_schemas.py` prefers the packaged copy.
- sdist `include` only adds to hatchling's default "everything not
  gitignored" file set rather than replacing it, so untracked working-tree
  files (`.agents/`, ~150K of unrelated content) were leaking into every
  build. Switched to `only-include`, a strict allowlist.

### Security

- Documented (`SECURITY.md`, `.gitleaks.toml`) and enforced (branch
  ruleset: required signed commits, required PR review) hygiene that was
  previously either aspirational or entirely absent.

[Unreleased]: https://github.com/bawbel/gate/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/bawbel/gate/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bawbel/gate/releases/tag/v0.1.0
