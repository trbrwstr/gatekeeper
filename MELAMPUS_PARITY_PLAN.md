# Gatekeeper — Melampus Parity Plan

Status: proposed execution plan  
Primary motion: security infrastructure IP/license and implementation services  
Initial wedge: policy-enforcing reverse proxy for one reference environment

Gatekeeper has a strong Rust engineering core: reverse proxying, policy, authentication/authorization, rate limiting, WASM rules, audit logs, metrics, and multi-node ambitions. Melampus parity requires narrowing the initial buyer/use case, proving performance and security under adversarial conditions, and packaging reproducible deployment, upgrades, rollback, SBOM, and diligence evidence.

## Project Charter

### Agent execution contract

- Read `README.md`, `Cargo.toml`, `.github/workflows/ci.yml`, configuration schema, policy/auth/proxy/WASM/audit modules, and deployment assets before editing.
- Execute GK-001 before adding integrations or policy features. One reference environment is authoritative for the MVP.
- Preserve fail-closed behavior for authorization and policy loading unless an explicit, documented availability decision says otherwise.
- Keep request-path code bounded and observable. Benchmark performance-sensitive changes against a committed methodology.
- Security fixes require regression tests; unsafe Rust requires a documented necessity, invariant, and targeted tests.
- Treat threat feeds and WASM modules as untrusted inputs. External fetches need authentication, signature/integrity, SSRF controls, timeouts, size limits, and rollback.
- Work one task ID per PR and update the threat model when a trust boundary changes.
- PRs must include tasks, commands, benchmarks, attack/regression evidence, config compatibility, operational impact, and rollback.

### Product definition

### Problem, user, and buyer

Teams exposing internal or customer APIs need enforceable authentication, authorization, policy, rate limiting, audit, and emergency controls without embedding inconsistent logic in every service. The primary user is a platform/security engineer; the buyer is an organization with a concrete API protection or modernization need.

### Product thesis and sellable wedge

The wedge is one reference deployment, selected in GK-001, that protects a small service set with JWT validation, RBAC/policy decisions, rate limits, structured audit, metrics, safe configuration reload, and tested rollback. SecureFrame and Sift should become supporting policy/intelligence modules rather than parallel products.

### Ethics, data, and resilience

Gatekeeper increases security-team control and could also enable opaque surveillance or arbitrary access denial. Log only necessary security metadata, document retention/export, make decisions explainable, and exclude employee monitoring or content inspection unrelated to protection. Core enforcement remains deterministic and local; threat feeds and optional intelligence cannot bypass human-reviewed policy.

### Commercial proof and kill criteria

Sell a reference deployment, hardening engagement, or license. Measure deployment time, allowed/denied correctness, latency overhead, throughput, recovery, and operator comprehension. Narrow or park standalone ambitions if buyers consistently prefer embedding the engine in an existing gateway and no distinct deployment advantage emerges.

## Implementation plan

### Architecture and data

Retain the Rust proxy/policy architecture and existing CLI/metrics/audit boundaries. Define stable versioned contracts for configuration, identity/claims, request context, policy input/output, rate-limit key/result, WASM module metadata, threat-feed snapshot, audit event, node status, and release manifest. Keep control-plane mutation separate from the request data path.

### Ordered task backlog

| ID | Priority | Work | Acceptance evidence |
|---|---|---|---|
| GK-001 | P0 | Select the initial buyer/reference environment and freeze supported protocols, identity provider, topology, policy examples, SLO hypotheses, and exclusions. | ADR and demo deploy one realistic environment without generic “supports everything” claims. |
| GK-002 | P0 | Complete threat model for proxy, admin/config, JWT/JWKS, policy, WASM, feeds, audit, metrics, clustering, and supply chain. | Every trust boundary maps to code owners, controls, tests, and residual risks. |
| GK-003 | P0 | Add property/fuzz tests for HTTP parsing, config/policy parsing, claims, rate-limit keys, WASM inputs, and audit serialization. | Seed corpus is committed; sanitizer/fuzz runs find no unresolved crash or memory-safety issue within the documented budget. |
| GK-004 | P0 | Establish reproducible load/latency methodology with baseline proxy, representative policies, rate limits, logging, and failure modes. | CI or scheduled benchmark emits versioned percentiles/throughput/resource results without unverifiable marketing numbers. |
| GK-005 | P0 | Harden JWT/JWKS and authorization: algorithm pinning, issuer/audience/time validation, rotation/cache failure behavior, deny precedence, and explanation IDs. | Attack/regression tests cover confusion, stale keys, clock edges, malformed claims, and policy conflicts. |
| GK-006 | P0 | Harden config/policy hot reload with validation, atomic activation, signed/versioned snapshots, last-known-good rollback, and audit. | Invalid/partial config never becomes active; rollback is exercised under traffic. |
| GK-007 | P0 | Sandbox and govern WASM: capabilities, memory/fuel/time limits, deterministic host calls, signature/integrity, failure policy, and module audit. | Malicious/looping/oversized modules cannot crash or escape the proxy; failure mode is documented and tested. |
| GK-008 | P0 | Secure threat-feed ingestion against SSRF, spoofing, staleness, oversized content, and unsafe automatic activation. | Only authenticated/allowed sources load; stale/bad feeds preserve a visible last-known-good state. |
| GK-009 | P0 | Validate multi-node/rate-limit semantics, partition behavior, consistency tradeoffs, and degraded operation for the reference topology. | Integration/chaos tests prove documented behavior during node/network/store failures. |
| GK-010 | P0 | Extend CI with clippy/fmt/test, feature matrix, fuzz smoke, dependency/license review, SBOM, signed artifacts, container scan, and install smoke. | A tagged candidate is reproducible, verifiable, and deployable from documented artifacts. |
| GK-011 | P0 | Create deployment, health/readiness, secrets, upgrade, migration, rollback, backup/config recovery, and incident runbooks. | Reference environment survives failed upgrade, config loss, and credential rotation rehearsals. |
| GK-012 | P1 | Define privacy-minimized audit schema, integrity protection, retention/export, redaction, and operator queries. | Audit events explain decisions without tokens/secrets/body leakage and detect tampering. |
| GK-013 | P1 | Bundle SecureFrame/Sift capabilities only behind versioned interfaces and the same threat/release gates. | No second gateway/control plane is created; optional modules can be disabled cleanly. |
| GK-014 | P1 | Produce architecture/data-flow, security assessment, third-party licenses, performance report, claims ledger, demo runbook, and diligence index. | Buyer can reproduce core security/performance evidence and map ownership. |
| GK-015 | P1 | Run a reference deployment pilot and capture integration time, incidents, latency, policy correctness, and operator feedback. | Evidence distinguishes lab benchmark from observed deployment results. |
| GK-016 | P2 | Add another protocol, IdP, or topology only after pilot evidence identifies it as the buying blocker. | Extension preserves compatibility and passes all security/performance gates. |

### Security and operations

Threat-model request smuggling, parser ambiguity, JWT attacks, policy bypass, admin takeover, malicious WASM/feed content, SSRF, denial of service, audit tampering, secrets leakage, partitions, and compromised releases. Use strict parsers, least-privilege admin interfaces, authenticated config, bounded execution, signed artifacts, dependency review, safe logging, and explicit fail-open/fail-closed choices per dependency.

### Verification commands

Use the pinned Rust toolchain and existing CI. Minimum evidence includes `cargo fmt --check`, workspace/all-feature `cargo clippy` with warnings denied where configured, `cargo test`, feature/config compatibility, fuzz/property suites, load methodology, integration/chaos tests, SBOM/license generation, artifact verification, and reference deployment smoke/rollback.

## MVP milestones

### M0 — Reference and threat contract

- **Outcome:** one deployment and its security boundary are authoritative.
- **Deliverables:** GK-001 and GK-002.
- **Dependencies:** buyer/reference hypothesis.
- **Exit gate:** architecture, SLO hypotheses, threats, and exclusions are reviewable.
- **Deferred:** protocol and integration breadth.

### M1 — Adversarially tested data path

- **Outcome:** enforcement is correct, bounded, and measurable.
- **Deliverables:** GK-003 through GK-009.
- **Dependencies:** M0.
- **Exit gate:** fuzz, attack, performance, reload, sandbox, feed, and partition suites pass.
- **Deferred:** optional intelligence bundles.

### M2 — Releasable infrastructure asset

- **Outcome:** signed releases deploy, upgrade, recover, and produce defensible evidence.
- **Deliverables:** GK-010 through GK-014.
- **Dependencies:** M1.
- **Exit gate:** clean candidate plus rollback/recovery/security-diligence review passes.
- **Deferred:** managed multi-tenant control plane.

### M3 — Reference customer evidence

- **Outcome:** a real deployment validates the product and service motion.
- **Deliverables:** GK-015.
- **Dependencies:** M2.
- **Exit gate:** measured deployment evidence identifies whether GK-016 is necessary.
- **Deferred:** GK-016 until the gate passes.

### Next three actions

1. Execute GK-001 by selecting and documenting the reference deployment from actual buyer hypotheses.
2. Execute GK-002 by mapping all existing modules and external inputs into a threat model before hardening changes.
3. Capture current CI, release, and benchmark baselines and open focused issues for GK-003 through GK-011.
