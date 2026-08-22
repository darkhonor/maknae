# ADR-0006: Client authentication (AuthN) model — sole trust-plane door; boundary-native factors; uniform short-lived sessions; X.509 is machine identity only

- **Status:** Accepted (operator-ratified 2026-08-22; strategy selected after an objective threat assessment against the DoD Zero Trust Reference Architecture and NIST guidance — see §Alignment)
- **Date:** 2026-08-22
- **Deciders:** Alex Ackerman (operator)
- **Relates to:** ADR-0005 (enforcement locus & TCB boundary — `maknaed` is the sole PDP; *amends* its client-channel mutual-mTLS clause, see Consequences); ADR-0018 (local-plane authorization & deployment model — *amends* its operator-CLI standing-SecretID and its decision-1 client gate); ADR-0019 (audit record model — the authenticated principal is captured per request); ADR-0020 (access-control model — the **authorization** counterpart this AuthN model feeds). Issues: #66 (the gateway / remote-client boundary), #73 (el9 operator-CLI `0400` seal residual — OPEN; *superseded on session-path landing*, see Consequences), #89 (`--user` cannot use `--with-key=tpm2` — already **patched** via `--with-key=auto`, closed 2026-08-16), #19 (subject-context envelope — the session payload's implementing work).

> **Scope: authentication, not authorization.** This ADR fixes *who a client is and how it proves that* (the IA family). It does **not** decide what an authenticated client may do — that is the reference monitor's per-request call, deny-by-default (ADR-0020, the AC family). AuthN establishes identity and hands it to the PDP; establishing a session is never itself an authorization.

> **Number-reuse note.** Per the registry convention (2026-08-22) an ADR takes a number at authoring and freed numbers are reused; `0006` previously held the (unwritten, since-embodied-in-AGENTS.md) single-source-of-truth doctrine. The filename and registry topic are the identity — the bare number is a handle.

## Context

Today Maknae is a single host: the `maknae` CLI and `maknaed` daemon run on the same box, talking over an mTLS UDS (ADR-0005). In the shipped design the CLI authenticates to **Vault** directly (its own AppRole SecretID → mint a `cli`-plane leaf → mTLS to the daemon), which forced a per-platform at-rest seal for that standing SecretID — the `systemd-creds --user` / Keychain split, and the RHEL-9 residual gap (#73, #89).

Two forces make that model wrong going forward. First, **the client is untrusted by design, and will become *remote*** — the daemon will grow a network listener; the target is controlling Maknae from an iOS app over 5G/VPN. A remote, untrusted client must not be assumed to have — or need — a network path to Vault; punching Vault out toward untrusted networks, and issuing every client a Vault identity, is the opposite of the reference-monitor posture. Second, **the current design handed a *human operator* a *machine credential*** (a standing AppRole SecretID). AppRole+SecretID is for machines; humans authenticate via a human method and receive short-lived sessions.

An earlier draft of this ADR fixed the symptom (no standing SecretID) but kept the client credential as a Vault-issued X.509 leaf, brokered by the daemon — which required granting the trust plane a `cli`-signing capability ADR-0005 deliberately withholds (custody-by-secret-absence), and made local and remote clients mechanically asymmetric. The operator directed a ground-up threat assessment of the authentication strategy (2026-08-22); three candidate strategies were evaluated against the trust assumptions and threat model below and against DoD ZT RA v2.0 / NIST SP 800-207 / SP 800-63. The selected strategy (this ADR) removes the client X.509 requirement instead of working around it.

## Trust assumptions (operator-ratified, 2026-08-22)

1. **The OS host posture is STIG'd and access is limited to authorized individuals.** Host login is a trustworthy authentication event; Maknae *inherits* OS authentication (PE-2/AC-2 done by the platform that owns them) rather than re-implementing it. This is an explicit, documented external authority, not implicit trust — see §Alignment.
2. **`maknae`-group membership is a root-gated administrative act.** Nobody drifts into the trust boundary; an administrator deliberately enrolled them.
3. **An *externally achieved* OS compromise (root obtained by non-Maknae means) is outside Maknae's threat model** — root owns the daemon's memory, sealed secrets, and socket; no scheme Maknae runs on that host survives its own root. These are things the platform (STIG, access control, scanning) handles and Maknae never can.
4. **Maknae as the escalation *vector* is squarely inside the threat model — it is threat #1.** A user authenticated *to Maknae* must never be able to escalate to *host-level* access through any Maknae component. Direction matters: host→Maknae compromise is the OS's failure; Maknae→host escalation is *our* failure and must be impossible. (This is a primary reason the kernel is Rust — ADR-0002.)

## Threat model

| # | Threat | Boundary | Defeated by |
|---|---|---|---|
| T0 | **A Maknae-authenticated client escalates to host-level access through a Maknae component** | Both | Decision 8: the daemon never acts beyond the client's own authority; memory-safe TCB (ADR-0002); no setuid-like surface; per-request PDP (ADR-0020) |
| T1 | Mis-attribution between two authorized admins | Local | Per-connection, kernel-attested principal (`SO_PEERCRED` uid) — never a shared artifact |
| T2 | Credential exfiltrated from the host, used elsewhere | Local | No client credential at rest; the local session is uid-bound and re-verified against live peer-cred each connection — dead off-host and dead cross-user |
| T3 | Unauthorized local user connects | Local | `0660` socket + root-gated group + fail-closed deny + AU-3 audit (ADR-0018/0019) |
| T4 | Authorized user's account compromised (non-root) | Local | Unwinnable at AuthN; contained by exact attribution (AU-3) + per-request PDP limits |
| T5 | Compromised daemon *also* gains identity-minting power | Local | **Structural:** the daemon holds no signing capability for client identities — nothing new to abuse (800-207 §5.1, PDP-subversion minimization) |
| T6 | Network MITM / fake endpoint | Remote | TLS 1.3, server-authenticated gateway |
| T7 | Lost / stolen / seized device | Remote | Short-TTL, sender-constrained, gateway-revocable sessions; nothing durable on device |
| T8 | Token theft / replay from a legitimate device | Remote | Channel-binding (DPoP / TLS-exporter / holder-of-key) — the session is useless off its channel |
| T9 | Valid IdP identity that is not *authorized* (any GitHub account ≠ an operator) | Remote | Explicit subject enrollment — an administrative act mirroring the root-gated group add |
| T10 | Gateway compromise | Remote | Gateway holds its own machine identity + own scoped policy; the PDP still adjudicates every request; the gateway can never mint a kernel identity |

## Decision

**The strategy in one sentence:** *every client, local or remote, is an admin-enrolled principal, authenticated at its boundary's door by that boundary's native factor, and carried in a bound, short-lived session to the sole PDP on every request.*

1. **The trust plane is the sole client-facing authentication endpoint.** A client — local or remote — authenticates to and transacts only with the trust plane (`maknaed` over the UDS locally; the **gateway**, #66, remotely). Clients **never** reach Vault, the lake, model endpoints, or any other trust infrastructure directly. This is the reference-monitor principle (ADR-0005, AC-25) projected onto the network boundary: one authenticated door per boundary, everything trusted behind it.

2. **X.509 / Vault PKI is machine identity only; client authentication is a session, never a certificate.** Plane leaves (ADR-0005) identify *workloads* — the daemon, and later the gateway's internal channel. Humans and client apps never hold a Maknae certificate or any Vault credential. A client's credential is a **short-TTL session** minted by its boundary's door after the boundary-native factor authenticates. This dissolves the prior draft's central defect: no client leaf exists, so no issuance bootstrap exists, and **no new Vault signing capability is granted to anyone** — ADR-0005's per-plane policy scoping and custody-by-secret-absence are untouched, byte for byte. Sessions are daemon-local state (or daemon-MAC'd tokens); Vault PKI is not in the client-authentication path at all.

3. **Enrollment precedes authentication, on both boundaries, as an explicit administrative act.** Locally, root adds the user to the `maknae` group (assumption 2). Remotely, the Maknae Admin **enrolls the OIDC subject** — a merely *valid* IdP identity is refused (T9). Nobody can authenticate whom an administrator did not first ratify. Symmetric on purpose: authorization-to-authenticate is never implicit.

4. **Local (on-host) authentication = OS host-login + `maknae`-group + kernel-attested peer-cred, with the session bound to the uid.** The STIG'd OS is the local identity provider (assumption 1); `SO_PEERCRED` re-attests the uid on **every connection** — a kernel-attested, non-replayable, non-exfiltratable factor. The channel is TLS 1.3 over the `0660` UDS with `maknaed` server-authenticated (`plane/kernel` cert); the client presents no certificate. The session is bound to the authenticated uid and the daemon verifies **live peer-cred uid == session uid on every connection** (T2): a copied session is dead off-host and dead cross-user. The on-server CLI (the Maknae Admin's surface for admin functions, troubleshooting, and AI-harness testing) therefore holds no credential at rest and needs no separate `maknae login` — the OS session is the login. There is no bootstrap problem: the first connection authenticates exactly like every other, by peer-cred; no credential is presupposed.

5. **Remote authentication = OIDC federation through the gateway, hardened.** The remote client authenticates natively to an external IdP (e.g. GitHub, Azure AD) and presents the token to the **gateway** (#66) over TLS; the gateway validates it (IA-8, 800-63C federation) against the **enrolled-subject list** (Decision 3) and mints a **short-TTL, channel-bound session**. REQUIREd properties: (a) the IdP MUST enforce MFA / conditional access (AAL2, SP 800-63B) — Maknae delegates the factor, not the requirement; (b) device-retained IdP credentials MUST be **sender-constrained** (DPoP / mTLS-bound — the SP 800-63C holder-of-key / FAL3 direction) and **gateway-revocable**; long-lived bearer refresh tokens MUST NOT be relied on; (c) the gateway MUST be able to revoke a device's sessions on report of loss (T7). The gateway presents its **own** machine identity (never the daemon's `plane/kernel` key), reaches `maknaed` over a **separate internal mutual-mTLS machine channel**, and the remote client **never reaches `maknaed`** — its session is `client↔gateway`. A lost, stolen, or seized device forfeits an expiring, revocable, channel-bound session — no standing Maknae credential exists on any client.

6. **The client stays untrusted across the boundary.** A client is authenticated **per session** and authorized **per request** by the sole PDP (deny-by-default, ADR-0020). A valid session is identity, never entitlement.

7. **The authenticated principal is carried into every PDP decision.** Locally the principal is the live `SO_PEERCRED` uid — present on every connection, captured in every AU-3 record (ADR-0019). Remotely the validated OIDC principal (and its claims → subject attributes) rides the channel-bound session through the gateway into each request to the sole PDP — never inferred from channel or plane membership. The session is the **carrier** of identity and subject context (the concrete envelope is the subject-context work, issue #19 — an *issue*, not a reserved ADR number, per the registry's number-at-creation rule); the *requirement* that the principal reach every PDP call is fixed here. This is also the designed insertion point for later attribute enrichment — device posture, DCS clearance — without changing the model.

8. **Maknae is never the privilege-escalation vector (T0).** No Maknae component performs an action on a client's behalf that exceeds that client's own authority on the host or in the policy model: the daemon does not proxy host access, exposes no setuid-like surface, and a Maknae session confers exactly zero host-level rights. Any design change that would have the trust plane act with its own privileges *for* a client is a security decision requiring an ADR, not a convenience (AGENTS.md core principle 3).

## Alignment — DoD Zero Trust RA & NIST (strengths and honest gaps)

Assessed 2026-08-22 against **NIST SP 800-207** (*Zero Trust Architecture*), the **DoD Zero Trust Reference Architecture v2.0**, and **NIST SP 800-63-3/-63B/-63C**. Strengths first, then the gaps an assessor would write up — kept here deliberately so they are owed work, not surprises.

**Where this model is strong (the load-bearing ZT properties):**

- **Per-session access, exceeded.** 800-207 Tenet 3: *"Access to individual enterprise resources is granted on a per-session basis."* This model authenticates per session **and authorizes per request** at the sole PDP (Decision 6) — stricter than the tenet demands.
- **Strict pre-access enforcement.** Tenet 6: *"All resource authentication and authorization are dynamic and strictly enforced before access is allowed."* Deny-by-default, fail-closed, enrolled-principals-only (Decision 3), per-request PDP (ADR-0020).
- **All resources behind the door.** Tenet 1 (all data sources and services are resources) — the trust plane fronts Vault, the lake, and model endpoints; no client touches a resource directly (Decision 1). PDP/PEP separation per 800-207 §3: `maknaed` is the policy engine + enforcement point; the gateway is the remote PEP.
- **Identity-based, not location-based, trust.** Tenet 2 (*"all communication is secured regardless of network location"*): TLS on both boundaries, including over the local UDS. Being local grants nothing — it only selects *which factor* authenticates you (peer-cred vs. OIDC); the `0660` socket is segmentation defense-in-depth, never the access decision.
- **Dynamic policy with an attribute conduit.** Tenet 4 (access decided by dynamic policy including client identity and environmental attributes): the session-as-subject-context-carrier (Decision 7) is precisely the conduit for RBAC→ABAC enrichment (ADR-0020, DCS) — the carrier exists even where today's attributes are minimal.
- **PDP-subversion minimization.** 800-207 §5.1 names subversion of the ZT decision process as a principal threat; this model keeps the PDP *minimal* — no CA capability, no new Vault grants (Decision 2, T5). Least privilege for the crown jewel.
- **Assurance mapping (800-63).** Local: AAL inherited from the STIG'd host's login policy (CAC/smartcard on a DoD host → AAL2/3), then re-attested per connection by the kernel. Remote: OIDC signed assertions → FAL2 baseline; the REQUIREd sender-constrained tokens are the holder-of-key / FAL3 direction (SP 800-63C).

**Honest gaps (deliberate MVP deferrals, owed as future work — this is an AI-agent platform and will grow against them):**

- **Device posture (DoD ZT RA Device pillar; 800-207 Tenet 5** — *"the enterprise monitors and measures the integrity and security posture of all owned and associated assets"*)**.** Channel-binding proves device *identity* (a key), not device *health/compliance*. Locally, "STIG'd host" is a governed platform assumption, not a signal Maknae measures. **Deferral rationale:** single-host MVP; the platform owns host posture. **Insertion point when built:** device-posture claims enter as session subject-context attributes (Decision 7) — the model has a socket for the missing piece.
- **Visibility & Analytics pillar (Tenet 7).** AU-3 per-request with the exact principal (ADR-0019) is the foundation; SIEM export / analytics on top is future work.
- **Automation & Orchestration pillar.** Revocation-on-report and fail-closed exist; SOAR-class orchestration is out of scope for a local platform at MVP.
- **MFA and conditional access are delegated**, not owned — to the STIG'd host's login policy locally and to the IdP remotely. Both delegations are stated as explicit REQUIREs with the trust boundary named (assumption 1; Decision 5a) rather than left for an assessor to discover.

## Consequences

- **The per-platform CLI-seal problem is superseded — once the local session path lands.** In the target model the on-server CLI holds no credential at rest at all, so there is nothing to seal. This **supersedes** the CLI-seal requirement rather than patching it — but the change is prospective, not accomplished: **#73 (the RHEL-9 `0400` plaintext CLI-SecretID residual) is OPEN and resolves *by removal* only when the session path lands.** Until then the shipped model (CLI SecretID + self-minted leaf, per ADR-0005/0018) **remains in force** — do not close #73 or strip the residual before the session path replaces it. **#89** was already patched (`--with-key=auto`, closed 2026-08-16); this model removes the seal *class* it lived in going forward.
- **No new Vault capabilities, no signing-grant decision.** The prior draft's owed decision (grant `maknaed` `pki/sign/cli-role`, or stand up a broker identity) is **dissolved, not deferred** — sessions need no PKI. Custody-by-secret-absence (ADR-0005) is preserved unchanged; the daemon's machine identity (ADR-0018: standing AppRole SecretID, HRoT-sealed, periodic token) is untouched.
- **ADR-0005 is amended (append-only):** the *client* channel's mutual-mTLS requirement is superseded in target model — the local client channel becomes server-authenticated TLS 1.3 + kernel-attested peer-cred + uid-bound session; mutual mTLS remains for **machine (plane-to-plane) channels** (daemon↔Vault today; gateway↔daemon later). The `cli` PKI role is **retired as a client credential**; its disposition (reuse as the gateway's internal machine identity, or removal) is decided with #66.
- **ADR-0018 is amended (append-only):** decision 1's gate for local clients becomes *(b) `maknae`-group membership + live peer-cred + uid-bound session*; clause (a) (verified `cli`-plane leaf) is superseded in target model for clients, retained for machine planes. The "mTLS plane cert is the real per-user credential" phrase is superseded: the per-user credential is the OS login attested by peer-cred.
- **Local and remote are one model** — same enrollment discipline, same session artifact, same principal-to-PDP contract, differing only in the boundary-native factor. The local implementation built now is the pattern the gateway (#66) instantiates, not a throwaway.
- **Owed work:** the local session path in `maknaed` + CLI (resolves #73 by removal); the gateway (#66); the subject-context envelope (#19); device-posture attributes and audit export/analytics (future issues, filed when scheduled — not reserved ADR numbers).

## Security control mapping (informative; per ADR-0001)

| Property | NIST SP 800-53 rev 5 |
|---|---|
| Sole authenticated client-facing door; trust infra behind it | AC-25 (reference monitor); SC-7 (boundary protection — Vault private) |
| Enrollment precedes authentication (root-gated group; enrolled OIDC subjects) | AC-2 (account management); IA-8 (federated identity) |
| Identify & authenticate the operator (local uid; remote OIDC) | IA-2; IA-8 |
| MFA delegated with stated boundary (host login policy; IdP conditional access) | IA-2(1)/(2) (inherited/delegated) |
| No client authenticator at rest; short-lived, bound, revocable sessions | IA-5, IA-5(2); AC-12 (session termination) |
| Authenticated principal captured on every request | AU-3 (audit content); IA-2 |
| Session is identity, not entitlement — per-request authorization | AC-3, AC-3(3) (deny-by-default via ADR-0020) |
| Principal carried into every PDP call — never inferred from channel/plane | IA-2; AC-3(3); AU-3 |
| No identity-minting capability in the PDP; no new signing grants | AC-6 (least privilege); CM-7 (least functionality) |
| Maknae is never the escalation vector (T0) | AC-6; SC-2 (application partitioning); SI-16 (memory protection, ADR-0002) |

## Scope boundary

Fixes the **authentication strategy**: the sole-door principle, the machine-vs-human credential split (X.509 vs. sessions), enrollment-precedes-authentication, the boundary-native factors (peer-cred local; OIDC remote), session binding/lifetime properties, and the principal-to-PDP contract. It does **not** specify: the concrete session wire format or the subject-context envelope (#19, implementing spec); the gateway mechanism (#66); OIDC integration detail (providers, validation, claim mapping); or **authorization** (ADR-0020). The daemon's own machine authentication (ADR-0018) is out of scope and unchanged.

## References

Internal: ADR-0002 (Rust kernel — the T0 memory-safety substrate), ADR-0005 (enforcement locus / sole PDP / plane PKI — amended), ADR-0018 (local-plane authz & daemon machine identity — amended), ADR-0019 (audit / principal attribution), ADR-0020 (authorization model — the AC-family counterpart). Issues: #66 (gateway), #73 (el9 CLI-seal residual — OPEN; superseded-by-removal when the session path lands), #89 (patched, closed 2026-08-16), #19 (subject-context envelope). External: **NIST SP 800-207**, *Zero Trust Architecture* (tenets §2.1, deployment models §3, threats §5.1); **DoD Zero Trust Reference Architecture v2.0** (seven pillars; PE/PEP separation; single authenticated policy-enforcement door); **NIST SP 800-63-3 / 800-63B / 800-63C** (AAL2, FAL2/FAL3 holder-of-key, federation assurance); **NIST SP 800-53 rev 5**. Vault AppRole (machine) vs. OIDC (human) authentication patterns.
