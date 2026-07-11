# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

No version has been tagged or released yet. The M0-M7 build (project scaffold
through policy engine, integrity pinning, operations layer, embedded console,
and bawbel-hub) is documented as milestones in README's "What is built" table
rather than itemized here; this file picks up from that baseline.

## [Unreleased]

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

### Fixed

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
