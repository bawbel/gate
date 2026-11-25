# Token exchange (RFC 8693) and MCP authorization: what they give a gate

Research report, 2026-11-25, for [#203](https://github.com/bawbel/gate/issues/203). Report only:
no code, no design, and no claim that any integration works. Nothing here was tested against an
identity provider, an MCP server or an agent framework.

Every claim carries a tag. **SOURCED**: the page and section, read on 2026-11-25. **VERIFIED**: a
command was run, with the date. **UNVERIFIED**: stated without either, and said so.

## How the sources were read

The pages were fetched on 2026-11-25 by a fetch tool, which reported each page's text with its
section names. The quotations below are copied from those reports and are short. Where a fetch was
cut off, the page is named in "Sources" and the claim that depends on the missing part is tagged
UNVERIFIED. The MCP specification pages show no date or revision label of their own. The revision is
the URL path (`2026-07-28`), and the `latest` URL served the same text on the day. I did not confirm
that revision's release date from an official changelog. In quotations, a keyword the source shows in
bold is written in capitals.

## Summary

1. RFC 8693 defines how a client asks an authorization server for a new token in exchange for
   another. It describes delegation (A acts for B and keeps its own identity) and impersonation
   (A is B within the token's rights), and defines the JWT claims `act` and `may_act` for
   delegation. Whether an exchange is allowed is the authorization server's policy.
2. The MCP authorization page (2026-07-28 path) does not mention token exchange, RFC 8693,
   delegation, impersonation, `act`, `may_act`, or the identity of an agent or end user. It makes
   authorization optional, says STDIO implementations should not follow it, and requires tokens
   bound to the server they are for.
3. The one MCP route that uses RFC 8693 is the Enterprise-Managed Authorization extension. The
   exchange happens at the enterprise identity provider, and the result is presented to the MCP
   authorization server under the jwt-bearer grant. The Python SDK page says the SDK does not make
   the RFC 8693 step itself.
4. Of the identity provider and agent framework pages read (Keycloak, Microsoft Entra, OpenAI,
   LangChain, Google), only Keycloak names RFC 8693. In Keycloak's standard exchange only
   client-to-client exchange in one realm is supported, impersonation is not implemented yet, and
   delegation is experimental. None of the three agent framework pages mentions token exchange.
5. The gate today reads and records no caller identity and handles no credential. It speaks stdio
   to the host and to every upstream. A gate could verify an assertion handed to it at start-up. It
   could not verify who is behind the host, whether a human approved an action, or what a downstream
   system did.

## RFC 8693

RFC 8693, "OAuth 2.0 Token Exchange", January 2020, Standards Track. SOURCED, read 2026-11-25 at
`https://www.rfc-editor.org/rfc/rfc8693.html`. The text was read in full across two fetches.

**Delegation and impersonation (section 1.1).** The RFC describes both and gives no one-sentence
formal definition of either.

| Term | The RFC's words |
|---|---|
| Delegation | "With delegation semantics, principal A still has its own identity separate from B," ... "any actions taken are being taken by A representing B." |
| Impersonation | "For all intents and purposes, when A is impersonating B, A is B within the context of the rights authorized by the token." |
| Chain of delegation | "the JWT `act` claim can provide a representation of a chain of delegation." |
| No actor, no delegation | Appendix A.1.1: "delegation is impossible with only a `subject_token` and no `actor_token`." |

**The request (section 2.1).** A POST to the token endpoint. `grant_type` is
`urn:ietf:params:oauth:grant-type:token-exchange`.

| Parameter | Status | The RFC's words |
|---|---|---|
| `subject_token` | REQUIRED | "A security token that represents the identity of the party on behalf of whom the request is being made." |
| `subject_token_type` | REQUIRED | "An identifier, as described in Section 3, that indicates the type of the security token in the `subject_token` parameter." |
| `actor_token` | OPTIONAL | "A security token that represents the identity of the acting party." |
| `actor_token_type` | REQUIRED when `actor_token` is present, and MUST NOT be included otherwise | |
| `resource` | OPTIONAL | "A URI that indicates the target service or resource where the client intends to use the requested security token." |
| `audience` | OPTIONAL | "The logical name of the target service where the client intends to use the requested security token." |
| `scope` | OPTIONAL | a space-delimited list, "to specify the desired scope of the requested security token" |
| `requested_token_type` | OPTIONAL | "An identifier, as described in Section 3, for the type of the requested security token." |

**The response (section 2.2.1).** `access_token`, `issued_token_type` and `token_type` are REQUIRED.
`expires_in` is RECOMMENDED. `scope` is REQUIRED unless it equals the scope requested.
`refresh_token` is OPTIONAL.

**The claims (section 4).**

- `act` (4.1): "The `act` claim value is a JSON object, and members in the JSON object are claims
  that identify the actor." The RFC also says: "the consumer of a token MUST only consider the
  token's top-level claims and the party identified as the current actor by the `act` claim." So
  earlier actors in a nested `act` are information, and not what a consumer acts on.
- `may_act` (4.4): "The `may_act` claim makes a statement that one party is authorized to become
  the actor and act on behalf of another party."

**What the RFC leaves to the authorization server.** Whether and when an exchange is allowed is
"at the discretion of the authorization server" (1.1, 2.1), and a request that is "unacceptable
based on policy" gets an error response (2.2.2). The validity criteria of a token "are beyond the
scope of this document" (2.1). The RFC does not say how a resource server, such as an MCP server,
should check an `act` chain beyond the JWT rules.

**Security and privacy (sections 5 and 6).** "In addition, both delegation and impersonation
introduce unique security issues." Tokens may carry privacy-sensitive information and "MUST only be
transmitted over encrypted channels, such as Transport Layer Security (TLS)." Deployments "SHOULD
determine the minimally necessary amount of data and only include such information in issued
tokens."

## MCP authorization, 2026-07-28 path

SOURCED, read 2026-11-25, `https://modelcontextprotocol.io/specification/latest/basic/authorization.md`
and `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization.md`. Both returned
the same 26104 characters. Read in full.

| Topic | What the page says |
|---|---|
| Optional | "Authorization is OPTIONAL for MCP implementations." HTTP-based transports "SHOULD conform to this specification." |
| STDIO | "Implementations using an STDIO transport SHOULD NOT follow this specification, and instead retrieve credentials from the environment." |
| Roles | An MCP server "acts as an OAuth 2.1 resource server". A client "acts as an OAuth 2.1 client, making protected resource requests on behalf of a resource owner." |
| Resource indicators | "MCP clients MUST implement Resource Indicators for OAuth 2.0 as defined in RFC 8707". The `resource` parameter "MUST be included in both authorization requests and token requests." |
| Audience | "MCP servers MUST validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2." and "MCP servers MUST NOT accept or transit any other tokens." |
| Registration | Client ID Metadata Documents SHOULD be supported. Dynamic Client Registration "is deprecated and retained for backwards compatibility". |
| Scopes | A server that gets an insufficient-scope token SHOULD answer `403`. Clients acting on behalf of a user "SHOULD attempt the step-up authorization flow." |

**Not mentioned on this page:** token exchange, RFC 8693, delegation, impersonation, an `act` or
`may_act` claim, the identity of an AI agent, the identity of the end user behind a client, the
word "passthrough", what a server may log, and how access tokens are stored. "On behalf of" appears
only for the client and resource owner relationship. Not read: the pages it links to
(client registration, authorization server discovery, security considerations).

## MCP security best practices, 2026-07-28 and 2025-11-25

SOURCED, read 2026-11-25, `.../specification/2026-07-28/basic/security_best_practices.md` (43643
characters) and `.../specification/2025-11-25/basic/security_best_practices.md` (37573 characters),
both read in full.

- **Confused deputy.** It concerns MCP proxy servers in front of third-party APIs that use a static
  client ID. "To prevent confused deputy attacks, MCP proxy servers MUST implement per-client
  consent and proper security controls as detailed below."
- **Token passthrough.** "MCP servers MUST NOT accept any tokens that were not explicitly issued for
  the MCP server." The page lists "Accountability and Audit Trail Issues" among the risks and says
  the problem makes "incident investigation, controls, and auditing more difficult."
- **Scope minimization.** A broad token obtained by log leakage or interception enables lateral
  access. The mitigation is a progressive, least-privilege scope model.
- **Changed since 2025-11-25.** "Session Hijacking" was replaced by "State Handle Hijacking", and
  the rule on session identifiers went from MUST to SHOULD. Confused deputy, token passthrough and
  SSRF rules are unchanged.
- **Not mentioned on the 2026-07-28 page:** token exchange, RFC 8693, on-behalf-of, an `act` claim.

## What servers, providers and frameworks support

Everything in this section is SOURCED from the page named, read on 2026-11-25. Nothing was run
against any of them. The pages say what each product documents. They do not show that it works.

| Source | Token exchange or delegation | Audience | Note |
|---|---|---|---|
| MCP Enterprise-Managed Authorization extension, and the Python SDK page | Yes. "This is a Token Exchange (RFC 8693) request with these parameters." The client trades an ID token for an ID-JAG at the enterprise identity provider, then presents it to the MCP authorization server under `urn:ietf:params:oauth:grant-type:jwt-bearer`. | The ID-JAG "may reach *this MCP server*"; the authorization server checks `aud`, `client_id` and `resource` | The SDK page: the RFC 8693 step "is entirely your IdP's API, and the SDK does not make it." The extension page: "Extensions are opt-in and never active by default." and "Implementations track different draft revisions". No "on behalf of", impersonation, `act` or `may_act` on either page. STDIO not mentioned. |
| Keycloak 26.7 (archived guide, page cut off) | Standard exchange "implements the Token exchange specification". "The standard token exchange supports only use-case (1)", exchange for another client in the same realm. | Subject token "must have the requester client set as an audience" | Subject impersonation "Not implemented yet". Delegation: "Experimental support via Token Exchange Delegation", using `may_act`, and "Do not use this feature in production environments." The `resource` parameter is "Not supported yet". The older exchange is "Preview and Deprecated". |
| Microsoft Entra on-behalf-of flow | Does not name RFC 8693 or "token exchange". "Referred to as delegation in OAuth, the intent is to pass a user's identity and permissions through the request chain." Uses `urn:ietf:params:oauth:grant-type:jwt-bearer` with `requested_token_use` set to `on_behalf_of`. | The assertion "must have an audience (`aud`) claim of the app making this OBO request" | "the OBO flow only works for user principals." Warning: "DO NOT send access tokens that were issued to the middle tier to anywhere except the intended audience for the token." |
| OpenAI Agents API, MCP connections | Not mentioned. | Not mentioned | A bearer token in `transport.authorization` or `headers`, or credentials in a vault. "Keep secrets out of reusable agent definitions, plugin archives, and logs." For stdio: "These values can be read by code running in the environment." |
| LangChain JavaScript, MCP authentication (`@langchain/mcp-adapters` 2.0 or later) | Not mentioned. | Not mentioned | A bearer header, or OAuth 2.1 handled by the SDK with storage supplied by the application. "each run should reach the MCP server as the user who started it, not with one shared credential." "The SDK does not validate `state`." |
| Google Cloud Agent Identity, 3-legged OAuth (v2 page) | Not named. "the agent accesses resources on behalf of the user." | Not mentioned | Tokens are kept in "a Google-managed credential vault". The page marks the IAM Connectors API as Preview. |

**Not read, so UNVERIFIED:** other identity providers, other agent frameworks, the normative text of
the extension specification, and the IETF draft that defines the ID-JAG. Keycloak: about 22500 of
62475 characters of the page came back as a summary, so legacy-mode details and its security notes
beyond those quoted are UNVERIFIED.

## What the gate does today

| Fact | Where | Tag |
|---|---|---|
| The host side speaks stdio | `src/bawbel_gate/mux/proxy.py` (`sys.stdin`, `sys.stdout`) | SOURCED |
| Every upstream is a stdio subprocess started with `Popen` | `mux/transport.py`, `spawn_server` | SOURCED |
| No import of an HTTP or socket library under `mux/` | `git grep` for an import of `urllib`, `http.client`, `http.server`, `requests`, `httpx`, `aiohttp`, `socket` or `ssl` under `src/bawbel_gate/mux`: no match | VERIFIED 2026-11-25 |
| The manifest schema allows `transport: http` as a declaration. No code opens one. | `schemas/capability-manifest-v1.json` | SOURCED |
| The gate reads no caller identity. The only `clientInfo` in `src/` is the gate's own name, sent upstream. | `mux/proxy.py` | SOURCED |
| The gate handles no credential. A JWT-shaped pattern is one entry of the argument secret scan (`_SECRET_PATTERNS`, DESIGN.md 5.3). | `policy/manifest.py` | SOURCED |
| An upstream inherits the gate's whole environment, because `Popen` is called with no `env` argument. | `mux/transport.py` | SOURCED |
| Records written by a real `serve` session hold no principal, agent, delegation or approver member. `SESSION_START`: `seq`, `ts`, `session`, `event`, `manifest_hashes`, `prev`, `hash`. `CALL_DECIDED`: `seq`, `ts`, `session`, `event`, `server`, `tool`, `effect`, `reason`, `taint`, `args_sha256`, `manifest_sha256`, `ave`, `prev`, `hash`. `SESSION_END`: `seq`, `ts`, `session`, `event`, `prev`, `hash`. | 5 records written by `bawbel-gate serve` 0.1.1, members read with a script | VERIFIED 2026-11-25 |

## Where a gate could verify a delegated identity, and where it cannot

None of this is built. "Could" means the sources above do not rule it out. Whether it is feasible
is UNVERIFIED.

| Where | What a gate could check | What that would show | What it would not show |
|---|---|---|---|
| A delegation declared in a reviewed manifest | That the manifest is the reviewed one, by its hash | That an operator wrote the declaration | That anyone delegated anything at run time |
| An assertion handed to the gate at start-up (the MCP page's STDIO route: "retrieve credentials from the environment") | Offline: signature against keys the operator supplies, `iss`, `aud`, `exp`, and the `sub` and `act` the issuer asserted | A token was valid when the gate was started, and who the issuer said the subject and actor were | That the host or agent process is the holder of the token. That a human approved any action. Revocation after issue, offline. |
| A token on every call | Nothing defined: the MCP authorization page does not cover STDIO and names no field for it. A gate-defined field would be a convention. | Only what a signed per-call value could show | Anything, if the field is not signed per call: a caller can write any value |
| An HTTP transport | The MCP authorization rules would apply: accept only tokens issued for the gate, never pass one on, and obtain a separate token for each upstream, which is where RFC 8693 would sit | The audience and subject of a token the gate validated | That the request came from the person the token names. The gate has no HTTP transport today. |
| The downstream system | Nothing | Nothing | What the downstream system did. The gate sees the call it decided and the reply. |
| Human approval | Local approval channels (DESIGN.md 13.4) | That a local channel answered | That a human approved this action. A token or an exchange does not carry that fact |

## Risks

- **Token passthrough.** The MCP page forbids a server to "accept or transit" tokens not issued for
  it. A gate in front of HTTP upstreams that forwarded the host's token would be doing exactly that.
  With stdio the gate forwards nothing, but an upstream inherits its environment, so any credential
  in the gate's environment reaches every upstream.
- **Confused deputy.** It applies to a proxy that fronts a third-party API under one static client
  identity. The gate is not an OAuth proxy today. Adding one would need the per-client consent the
  page lists.
- **Impersonation hides the actor.** When A impersonates B, "A is B", so a record built from such a
  token names only B. Delegation keeps both, and a nested `act` keeps the chain, but a consumer
  "MUST only consider" the current actor.
- **An exchange can widen what a token can do.** Keycloak's guide: "By default, token exchange can
  be used to request extra scopes and audiences that are not present in the initial
  `subject_token`." Narrowing is the authorization server's policy, not the gate's.
- **Tokens in logs.** The RFC says tokens may carry privacy-sensitive information. The MCP page
  requires refresh tokens kept confidential. A record that held a raw token would be a credential
  store. A design should hold a reference to a token or a hash of it, and never the token.
- **Revocation and lifetime.** An offline check cannot see revocation. Keycloak's guide says the
  administrator "must ensure that access tokens are short-lived and are revoked automatically after
  some time."
- **Uneven and draft-based support.** The extension page says implementations "track different draft
  revisions". Several pages carry Preview, Experimental or Deprecated labels.

## Decisions this report does not take

All open. None is decided here.

1. Whether delegation is declared in a reviewed manifest, or comes from a token exchange at run
   time. This report is the input the maintainer asked for before deciding.
2. Whether approvals are owned by the gate, through its local channels, with the Hub read-only, or
   brokered by the Hub, which would change the rule that the Hub has no write path back to gates.
3. Whether a multi-tenant hosted control plane, with tenants, users, single sign-on and role-based
   access in the product, is in scope for the open-source Hub.

## What was not done

- No code. No design change. No test.
- No provider, server or framework was run, so no claim is made that OAuth or identity propagation
  works with any of them.
- Pages not read: the linked MCP pages (client registration, authorization server discovery,
  security considerations), the normative text of the extension specification, the IETF drafts
  behind the ID-JAG, other identity providers and other agent frameworks.
- The release date of the MCP 2026-07-28 revision was not checked against an official changelog.

## Sources

All read 2026-11-25.

- RFC 8693, OAuth 2.0 Token Exchange, `https://www.rfc-editor.org/rfc/rfc8693.html`. Read in full.
- MCP specification, Authorization, `https://modelcontextprotocol.io/specification/latest/basic/authorization.md`
  and `.../specification/2026-07-28/basic/authorization.md`. Read in full, same text.
- MCP specification, Security Best Practices, `.../specification/2026-07-28/basic/security_best_practices.md`
  and `.../specification/2025-11-25/basic/security_best_practices.md`. Read in full.
- MCP, Enterprise-Managed Authorization, `https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization.md`,
  and Authorization Extensions overview, `.../extensions/auth/overview.md`. Read in full.
- MCP Python SDK, Identity assertion, `https://py.sdk.modelcontextprotocol.io/client/identity-assertion/index.md`. Read in full.
- Keycloak, Configuring and using token exchange (archived 26.7 guide),
  `https://www.keycloak.org/26.7/securing-apps/token-exchange`. About 39900 of 62475 characters verbatim.
- Microsoft, Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow,
  `https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow`. Read in full.
- OpenAI, MCP connections, `https://developers.openai.com/api/docs/guides/agents-api/tools/mcp.md`. Read in full.
- LangChain, Authentication for MCP (JavaScript), `https://docs.langchain.com/oss/javascript/langchain/mcp/auth`. Read in full.
- Google Cloud, Authenticate using 3-legged OAuth with auth manager, `https://docs.cloud.google.com/iam/docs/auth-with-3lo-v2`. Read in full.
- This repository, `develop` at `92ea9d3`: the files named in "What the gate does today".
