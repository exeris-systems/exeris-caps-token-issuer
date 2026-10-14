---
title: "Review rules for exeris-caps-token-issuer"
type: reference
visibility: public
owning-repo: exeris-caps-token-issuer
status: active
last-verified: 2026-10-13
---

# Review rules for `exeris-caps-token-issuer`

The `repo-routine` extension of `exeris-systems/.github`'s `docs-guardrails-review.md`, applied
**after** its parts and under its severity tags, output format and verdict schema. It adds checks
and raises severities; it lowers nothing and skips nothing. One review, one verdict, one publisher.
A finding cites a rule of this file as `repo-review-rules.md#S<n>`.

**The criteria are not authored here.** They are stated by this repository's `AGENTS.md`,
`README.md`, `CONTRIBUTING.md` and `SECURITY.md`, and by the build that enforces them. This file names the
questions a reviewer must reach for and the severity each answer carries; where a rule restates a
sentence of those documents, the document is the one to read and to change.

## What this repository is answerable for

`exeris-caps-token-issuer` is a single-module Exeris capability: Layer 5 domain primitive (identity), licence community (Apache-2.0), a proof of concept with
no published artefact. Other capabilities and the SKUs that compose them compile against its
`@Provides` services, so a contract broken here breaks a composition elsewhere while this build stays
green. The shared `code` part judges whether a change is correct. What it cannot know is which of this
capability's surfaces and invariants its own documents promise, and that is what follows.

## Step S — rules of this repository

S1. **The cap-tier Wall holds** (ADR-055, ADR-006; `AGENTS.md` §2). Only what the build's Wall check
    enforces is asserted here: the check is `CapTierWall` in `exeris-tooling`, run by
    `exeris:verify-capabilities` at `process-classes` over the compiled main classes, and it rejects
    a reference to `org.springframework.*`, `io.netty.*`, `reactor.*` or `jakarta.servlet.*`, to
    kernel internals (`eu.exeris.kernel.**.internal.**`), and to a sibling capability's `internal`
    package; only `eu.exeris.kernel.spi.*` is the kernel this capability may name. In a diff: such
    an import in `src/main`; a dependency in `pom.xml` that brings one in; a rename of the package
    root `eu.exeris.caps.tokenissuer` or an extra segment in it, because the guard derives the
    capability's name from the segment after `eu.exeris.caps.`;
    `eu.exeris.caps.tokenissuer.internal` is private to this capability and
    `eu.exeris.caps.tokenissuer.api` is the cross-cap surface, and an `internal` type in a public
    signature → `[HARD BLOCK]`. A Spring, servlet, Netty or reactor import in `src/test` is outside
    what the guard scans and is still forbidden by `AGENTS.md` → `[CONTRACT]`. A `kernel-core` or
    `kernel-community` dependency outside `test` scope → `[HARD BLOCK]`.

S2. **The committed manifest is regenerated, never edited.**
    `src/main/generated/java/cap-manifest.json` is written by `exeris:generate`, and a clean
    `git status` after `mvn verify` shows it matches the declaration. A diff that edits it by hand,
    touches the module class (`@CapabilityModule`, `@Provides`, `@Requires`) without carrying the
    regenerated manifest, carries a manifest change with no declaration change, or leaves a manifest
    that disagrees with the annotations (a `@Provides` version, a `@Requires` range or `optional`
    flag, an `initOrder`) → `[HARD BLOCK]`. A manifest whose `stamp.validated` is not `true` →
    `[HARD BLOCK]`.

S3. **Service contracts are `0.1.0` while the capability is unreleased**
    (`standards/capability-conventions.md` rule 9). While no artefact of this capability has been
    published, every `@Provides` declares `version = "0.1.0"` and every `@Requires` on an unreleased
    contract declares `[0.1.0,0.2.0)`; a declaration at `1.0.0` or higher, or a range that is not
    `[0.1.0,0.2.0)`, → `[CONTRACT]`. A pre-release breaking change does not bump the version: it
    keeps `0.1.0` and its Compatibility impact line is `breaking (ADR-099)` (accepted 2026-10-07),
    or `breaking (ADR-NNN)` of the accepted ADR that governs this capability. **An unreleased
    capability keeps no `accepted-api-changes.json`; the first released version starts it.** The
    reviewer therefore does not ask for that file, an entry in it, or a japicmp baseline on a
    pre-release pull request, and does not read the absence of a version bump as a finding. A pull
    request that publishes the first release is the one in which the register starts, and rule 24 of
    the shared routine then applies in full.

S4. **A community capability registers no entitlement.** This capability is `community` (Apache-2.0,
    ADR-023), so it ships no
    `META-INF/services/eu.exeris.kernel.spi.contract.EntitlementRequirement` and no
    `EntitlementRequirement` class; one added → `[HARD BLOCK]`. `LICENSE`, the POM `<licenses>`
    block and the README claim move together; a change to one alone → `[CONTRACT]`.

S5. **No dependency creep.** The runtime classpath stays what the POM declares:
    `exeris-sdk-annotations` at `provided` (every Exeris annotation is `@Retention(SOURCE)`), the
    kernel SPI, and the sibling capabilities the README lists. A new `compile`-scope dependency, a
    logging implementation such as Logback or Log4j (use `System.Logger`, ADR-060), or a new sibling
    capability with no matching `@Requires` or README line → `[CONTRACT]`. Reading an Exeris
    annotation at runtime → `[HARD BLOCK]`.

S6. **The build baseline and the test contract hold** (`AGENTS.md` §2, `CONTRIBUTING.md`).
    `maven.compiler.release` stays 25 and no `--enable-preview` appears in any scope →
    `[HARD BLOCK]`. Tests use JUnit 5 and AssertJ only, with hand-written doubles and no mocking
    framework (ADR-058) → `[CONTRACT]`. A bug fix lands with the test that fails without it →
    `[CONTRACT]` when absent.

S7. **Verification names what ran.** CI runs `mvn verify` on JDK 25 and 26 on every head, so the
    pull request's Verification need not repeat it. A local run may be cited as
    `target/surefire-reports` at `<sha>`, and the reviewer accepts that as the evidence of what ran
    locally. A Verification that claims a pass without a command, report path or sha → `[STYLE]`.

S8. **Signing is EdDSA over Ed25519, and nothing else.** The JOSE header is exactly
    `{"alg":"EdDSA","typ":"JWT","kid":…}`, and each JWK is exactly `kty=OKP`, `crv=Ed25519`,
    `alg=EdDSA`, `use=sig`, `kid` and `x`. A second algorithm, a header or JWK member added or
    removed, or an `alg` taken from a request → `[HARD BLOCK]`.

S9. **The claim set is fixed.** `iss` and `aud` come from configuration and a request cannot
    override them. Every token carries `sub`, `iat`, `nbf` (equal to `iat`), `exp` and a fresh
    `jti`; `tid`, `sid` and `roles` appear only when the request carries them; a custom claim cannot
    use any of those names. A claim that a request can override, a `jti` that repeats, or a reserved
    name accepted as custom → `[HARD BLOCK]`.

S10. **Lifetimes are bounded.** A request lifetime is capped by `EXERIS_TOKEN_ISSUER_MAX_TOKEN_TTL`,
    and a request naming none gets `EXERIS_TOKEN_ISSUER_TOKEN_TTL`. Issuance never signs with an
    expired key. A token that outlives the bound, or an expired key that signs → `[HARD BLOCK]`.

S11. **A retired key leaves the JWKS only when no token it signed can still be accepted.** A
    replaced key stays published until `MAX_TOKEN_TTL + CLOCK_SKEW` have passed. A shorter overlap →
    `[HARD BLOCK]`, because verifiers would reject live tokens; a key that never leaves the JWKS →
    `[CONTRACT]`.

S12. **A key-encryption keyring is required with PostgreSQL, and a private key is never stored
    unsealed.** Each private key is sealed as an AES-256-GCM envelope under a 32-byte KEK, exactly
    one of `EXERIS_TOKEN_ISSUER_KEKS` and `EXERIS_TOKEN_ISSUER_KEKS_FILE` is set, a passphrase is
    refused rather than hashed into a key, and a stored key that is unsealed, names an unknown KEK
    or fails authentication throws `SigningKeyCustodyException`. A fallback to plaintext, a KEK
    derived from a string, or a private key in a log line or exception message → `[HARD BLOCK]`.

S13. **Configuration fails at construction.** A missing or malformed required value throws
    `TokenIssuerConfigurationException` naming the key, so the deployment fails to boot. A silent
    default for `EXERIS_TOKEN_ISSUER_ISSUER` or `EXERIS_TOKEN_ISSUER_AUDIENCE` → `[HARD BLOCK]`. A
    configuration key added, renamed or re-defaulted with the README table unchanged → `[DOC DEBT]`.

## Where this does not apply, and what it costs

The shared `code` and `pr` parts judge correctness, scope, the pull request's body and its commits, and the rules above are not a second copy of them. Whether a change to `internal` is correct is the `code` part's; what this file adds is the list of invariants this capability's own documents state, which a generic review cannot know to look for. Not to the pull request's body and commits, which the shared `pr` part judges, nor to comments
and Javadoc, which the shared `code-docs` part and the Javadoc gate judge.

The cost is that these rules are prose a reviewer applies, not a program. This repository hands the review no `repo-checks` output, so the Wall scan, the manifest comparison and the tests named above are evidence only through the build checks on the pull request, which the reviewer cannot read. A rule the reviewer could only check by running the build is reported as unchecked, not as passing.
