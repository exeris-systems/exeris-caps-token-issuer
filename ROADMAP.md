---
title: "Token issuer capability roadmap"
type: roadmap
visibility: public
owning-repo: exeris-caps-token-issuer
status: active
last-verified: 2026-10-15
---

# `exeris-caps-token-issuer` roadmap

`exeris-caps-token-issuer` is a proof of concept. This file records what it does not cover yet. It
is read together with the code and is updated by the change that closes a gap. What the capability does
today is in [`README.md`](README.md).

Milestones are versions, not dates. A gap that must close before the first `0.1.0` release has a
tracking issue in the `0.1.0` milestone and is linked here; a later gap is recorded here only.

## Before 0.1.0

### The in-memory keystore is on the public surface

`TokenIssuerModule.inMemoryForDevelopment(...)` is a public static method of the public module
class. It builds a module whose signing keys are unsealed, held in process memory, lost at restart
and not shared between nodes. The only guard is its name and a warning log line, so a production
composition can reach it by accident while the README states that there is no other in-memory path.
The wired constructor is fail-closed; the factory beside it is not. The fix is to remove it from the
public API or to put it behind an opt-in the wired constructor never reads. Code: `TokenIssuerModule.java` in the `tokenissuer` package. Tracking issue:
[#13](https://github.com/exeris-systems/exeris-caps-token-issuer/issues/13).

### A compromised key cannot be withdrawn quickly

No operation withdraws a key. `SigningKeyRotation.rotateKeys()` publishes a successor that signs only
after it has been published for `JWKS_MAX_AGE` (default five minutes), so the compromised key keeps
signing for that long, and the replaced key then stays in the JWKS until `MAX_TOKEN_TTL + CLOCK_SKEW` (default 61 minutes) has passed. Setting a key to `RETIRED` is possible only through the
internal repository, and the README has no operator procedure for this case. Code in
`DefaultSigningKeyRotation.java` and
`api/SigningKeyRotation.java`. Tracking issue:
[#14](https://github.com/exeris-systems/exeris-caps-token-issuer/issues/14).

### KEK rotation needs an internal class

The README procedure for replacing the key-encryption key calls
`PostgresSigningKeyRepository.resealWithActiveKek()`, a method of an `internal` type the module does
not expose. A consumer that stays on the public surface cannot follow it. The fix is a public
operation that re-seals stored keys under the active KEK and is audited. Code:
`internal/repository/PostgresSigningKeyRepository.java`.
Tracking issue: [#15](https://github.com/exeris-systems/exeris-caps-token-issuer/issues/15).

## Later

### The kernel transactional executor is declared optional

`@Requires(service = TransactionalExecutor.class, optional = true)` is optional only because the
capability graph cannot hold a kernel SPI type as a mandatory edge: the tooling reports a `@Requires`
on a kernel SPI type as a capability-graph error
([exeris-tooling#409](https://github.com/exeris-systems/exeris-tooling/issues/409), open). The wired
constructor refuses to build without an executor, so the cost today is that the manifest does not
show a mandatory edge that the constructor enforces. The kernel line `0.13` publishes
`KernelProviders.TRANSACTIONAL_EXECUTOR` (`exeris-kernel-spi`, `KernelProviders`), which lets the
module take the executor in `initialize()` instead of through a constructor argument. The capability is built
against kernel 0.12.0, so this waits on the move to 0.13 and on the tooling fix. Code:
`TokenIssuerModule.java`.

### Rotation atomicity depends on nested transactions

`PostgresSigningKeyRepository.rotateUnderClusterLock` takes the advisory lock and runs the rotation
inside one `executeManaged` call, and the rotation then calls repository methods that each open
`executeManaged` themselves. The rollback behaviour the rotation relies on (a pending key that is
rolled back with the rest) holds only if the kernel executor joins a nested call to the open
transaction. The kernel `TransactionalExecutor` documents no such contract, and the test executor
opens a connection per call, so no test shows it. A partial rotation fails closed (no active key) but
needs a manual repair. This waits on a documented nesting contract in the kernel SPI, then a test
against it. Code: `internal/repository/PostgresSigningKeyRepository.java`,
`internal/DefaultSigningKeyRotation.java`.

### The active private key is unsealed on every issuance

`DefaultAccessTokenIssuer` reads the active row, unseals the private key and rebuilds the `PrivateKey`
for each token. There is no key cache. That costs an AES-GCM open, a database read and a key parse per
token, and it bounds issuance throughput. A cache has to be dropped at rotation and withdrawal, so it
waits on the withdrawal operation of the `0.1.0` milestone. Code:
`internal/DefaultAccessTokenIssuer.java`,
`internal/repository/PostgresSigningKeyRepository.java`.

### Nothing applies the schema

The DDL lives in `src/main/resources/schema/token-issuer-schema.sql` and nothing runs it or checks the
table at boot, so a missing table surfaces at the first key read. The capability has no migration mechanism
and no schema version. This waits on a decision, for the capability family, about who owns schema
creation: the capability, the SKU or the operator.

### No published artefact and no compatibility gate

No artefact is published. The build resolves `exeris-kernel` from GitHub Packages and builds the
sibling capabilities `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail` from their
default branch (`.github/workflows/build.yml`), so a change there can turn this build red. There is no
release workflow and no japicmp gate, which needs a previous release as its baseline. This waits on
the sibling capabilities publishing an artefact and on the first release of this one.
