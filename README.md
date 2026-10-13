# exeris-caps-token-issuer

Access-token issuance as an Exeris capability. It provides `AccessTokenIssuer` (short-lived JWT access tokens signed with EdDSA over Ed25519), `JwksPublisher` (a JWKS document with the active and retiring public keys, optionally registered as a route on `service-boundary-core`'s `ApiSurfaceRegistry`) and `SigningKeyRotation` (key generations, an overlap window and retirement).

Status: proof of concept, built against `exeris-kernel` 0.12.0. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 5 — Domain primitive (identity), in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle`, `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail`.
- **Provides** (`@Provides`, all version 1.0.0): `AccessTokenIssuer`, `JwksPublisher`, `SigningKeyRotation`.
- **Requires** (`@Requires`, each declared `optional = true`): `eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry`, `eu.exeris.kernel.spi.persistence.TransactionalExecutor`, `eu.exeris.kernel.spi.scheduling.JobScheduler`, `eu.exeris.caps.audittrail.api.AuditLogSink`.
- **Wall (ADR-055):** `eu.exeris.caps.tokenissuer.api` is the cross-cap surface; `eu.exeris.caps.tokenissuer.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

Behaviour worth knowing before composing it:

- Rotation can be scheduled through the kernel `JobScheduler` when one is supplied.
- Signing keys are held in memory unless a kernel `TransactionalExecutor` is supplied, in which case a PostgreSQL repository stores them. The DDL is `src/main/resources/schema/token-issuer-schema.sql`; nothing applies it automatically.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

The upstreams are not on Maven Central. `exeris-sdk` v0.12.0 and `exeris-tooling` v0.9.0 are built from source at those tags, and `exeris-kernel` 0.12.0 is resolved from GitHub Packages, which needs a token with `read:packages`; the sibling `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail` are built from source first. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). `exeris-caps-token-issuer` is a `community` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): free for any use, production included, with no entitlement required.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
