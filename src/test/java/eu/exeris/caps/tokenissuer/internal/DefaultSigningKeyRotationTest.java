package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultSigningKeyRotationTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    private InMemorySigningKeyRepository repository;
    private TokenIssuerConfig config;
    private MutableClock clock;
    private DefaultSigningKeyRotation rotation;
    private DefaultJwksPublisher jwks;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        config = TestSupport.config();
        clock = new MutableClock(T0);
        rotation = new DefaultSigningKeyRotation(repository, config, null, null, clock);
        jwks = new DefaultJwksPublisher(repository, clock);
    }

    private List<String> publishedKids() {
        return jwks.getJwksDocument().keys().stream().map(k -> k.get("kid")).toList();
    }

    @Test
    @DisplayName("ensureActiveKey creates one EdDSA key that expires after keyTtl")
    void ensureActiveKeyCreatesActiveKey() {
        SigningKeyInfo active = rotation.ensureActiveKey();
        assertThat(active.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(active.algorithm()).isEqualTo("EdDSA");
        assertThat(active.expiresAt()).isEqualTo(T0.plus(config.keyTtl()));
        assertThat(rotation.ensureActiveKey().kid()).isEqualTo(active.kid());
    }

    private SigningKeyInfo stateOf(String kid) {
        return rotation.listKeyGenerations().stream().filter(k -> k.kid().equals(kid)).findFirst().orElseThrow();
    }

    private List<SigningKeyInfo> inState(KeyState state) {
        return rotation.listKeyGenerations().stream().filter(k -> k.state() == state).toList();
    }

    @Test
    @DisplayName("the next key is generated and published publicationLead before the active key expires")
    void successorIsPublishedBeforeItSigns() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        Instant leadStart = first.expiresAt().minus(config.publicationLead());

        clock.set(leadStart.minusSeconds(1));
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(first.kid());
        assertThat(inState(KeyState.PENDING)).isEmpty();

        clock.set(leadStart);
        assertThat(rotation.rotateIfDue().kid()).as("still signing with the active key").isEqualTo(first.kid());
        SigningKeyInfo pending = inState(KeyState.PENDING).getFirst();
        assertThat(publishedKids()).containsExactlyInAnyOrder(first.kid(), pending.kid());
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(first.kid());
        assertThat(inState(KeyState.PENDING)).hasSize(1);
    }

    @Test
    @DisplayName("a key signs only after it has been published for the JWKS cache lifetime")
    void keySignsOnlyAfterPublicationLead() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        clock.set(first.expiresAt().minus(config.publicationLead()));
        rotation.rotateIfDue();
        SigningKeyInfo pending = inState(KeyState.PENDING).getFirst();

        clock.set(first.expiresAt().minusSeconds(1));
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(first.kid());

        clock.set(first.expiresAt());
        SigningKeyInfo second = rotation.rotateIfDue();
        assertThat(second.kid()).isEqualTo(pending.kid());
        assertThat(second.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(Duration.between(pending.createdAt(), clock.instant())).isGreaterThanOrEqualTo(config.jwksMaxAge());
        assertThat(stateOf(first.kid()).state()).isEqualTo(KeyState.RETIRING);
        assertThat(inState(KeyState.ACTIVE)).hasSize(1);
        assertThat(second.expiresAt()).isEqualTo(first.expiresAt().plus(config.keyTtl()));
    }

    @Test
    @DisplayName("an expired active key is replaced only once the published successor has matured; issuance fails closed meanwhile")
    void expiredActiveKeyWaitsForSuccessorToMature() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        clock.set(first.expiresAt().plusSeconds(1));

        assertThatThrownBy(rotation::rotateIfDue).isInstanceOf(NoActiveKeyException.class);
        SigningKeyInfo pending = inState(KeyState.PENDING).getFirst();
        assertThat(publishedKids()).contains(pending.kid());
        assertThatThrownBy(rotation::rotateIfDue).isInstanceOf(NoActiveKeyException.class);
        assertThat(inState(KeyState.PENDING)).as("the pending key survives the failed call").hasSize(1);

        clock.advance(config.jwksMaxAge());
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(pending.kid());
    }

    @Test
    @DisplayName("rotateKeys publishes a pending key and promotes it after the cache lifetime, with the old key overlapping")
    void forcedRotationPublishesThenPromotes() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        Instant requestedAt = T0.plus(Duration.ofHours(3));
        clock.set(requestedAt);

        SigningKeyInfo pending = rotation.rotateKeys();
        assertThat(pending.state()).isEqualTo(KeyState.PENDING);
        assertThat(rotation.rotateKeys().kid()).as("a second request returns the same pending key").isEqualTo(pending.kid());
        assertThat(rotation.activeKey().kid()).isEqualTo(first.kid());
        assertThat(publishedKids()).containsExactlyInAnyOrder(first.kid(), pending.kid());

        clock.set(requestedAt.plus(config.jwksMaxAge()).minusSeconds(1));
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(first.kid());

        Instant promotedAt = requestedAt.plus(config.jwksMaxAge());
        clock.set(promotedAt);
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(pending.kid());
        SigningKeyInfo retiring = stateOf(first.kid());
        assertThat(retiring.state()).isEqualTo(KeyState.RETIRING);
        assertThat(retiring.retiredAt()).isEqualTo(promotedAt.plus(config.maxTokenTtl()).plus(config.clockSkew()));
    }

    @Test
    @DisplayName("a replaced key stays in the JWKS for maxTokenTtl + clockSkew, then leaves it")
    void rotationOverlap() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        clock.set(T0.plus(Duration.ofHours(3)));
        SigningKeyInfo second = TestSupport.rotateAndActivate(rotation, clock, config);
        Instant windowEnd = clock.instant().plus(config.maxTokenTtl()).plus(config.clockSkew());

        assertThat(stateOf(first.kid()).retiredAt()).isEqualTo(windowEnd);
        assertThat(publishedKids()).containsExactlyInAnyOrder(first.kid(), second.kid());

        clock.set(windowEnd.minusMillis(1));
        assertThat(publishedKids()).containsExactlyInAnyOrder(first.kid(), second.kid());
        assertThat(rotation.retireExpiredKeys()).isZero();

        // Publication ends at the window's end even before the retirement job has run.
        clock.set(windowEnd);
        assertThat(publishedKids()).containsExactly(second.kid());

        assertThat(rotation.retireExpiredKeys()).isEqualTo(1);
        assertThat(repository.findByKid(first.kid()).orElseThrow().state()).isEqualTo(KeyState.RETIRED);
        assertThat(publishedKids()).containsExactly(second.kid());
    }

    @Test
    @DisplayName("a pending key that expired before it could activate never signs and is retired")
    void stalePendingKeyIsDiscarded() {
        rotation.ensureActiveKey();
        clock.set(T0.plus(Duration.ofHours(1)));
        SigningKeyInfo stale = rotation.rotateKeys();

        clock.set(stale.expiresAt().plusSeconds(1));
        assertThatThrownBy(rotation::rotateIfDue).isInstanceOf(NoActiveKeyException.class);

        assertThat(stateOf(stale.kid()).state()).isEqualTo(KeyState.RETIRED);
        assertThat(publishedKids()).doesNotContain(stale.kid());
    }

    @Test
    @DisplayName("the maintenance cycle publishes, promotes, retires, and deletes retired key material")
    void maintenanceCycle() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        clock.set(first.expiresAt().minus(config.publicationLead()));
        rotation.runMaintenanceCycle();
        assertThat(inState(KeyState.PENDING)).hasSize(1);

        clock.set(first.expiresAt());
        rotation.runMaintenanceCycle();
        SigningKeyInfo second = rotation.activeKey();
        assertThat(second.kid()).isNotEqualTo(first.kid());
        assertThat(repository.findByKid(first.kid()).orElseThrow().state()).isEqualTo(KeyState.RETIRING);

        clock.advance(config.publicationOverlap().plusSeconds(1));
        rotation.runMaintenanceCycle();
        assertThat(repository.findByKid(first.kid())).isEmpty();
        assertThat(publishedKids()).containsExactly(second.kid());
    }

    @Test
    @DisplayName("a promotion leaves exactly one ACTIVE key even if an earlier rotation left another active")
    void promotionRetiresEveryOtherActiveKey() {
        rotation.ensureActiveKey();
        // Simulate an interrupted rotation: a second ACTIVE record next to the first.
        var stray = repository.findActive().orElseThrow();
        repository.save(new eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord(
                "k-stray", stray.algorithm(), stray.publicKeyJwkJson(), stray.publicKeyRawBytes(),
                stray.privateKeyPkcs8Bytes(), KeyState.ACTIVE, T0.minusSeconds(10), T0.plus(config.keyTtl()), null));

        clock.advance(Duration.ofMinutes(1));
        TestSupport.rotateAndActivate(rotation, clock, config);
        assertThat(inState(KeyState.ACTIVE)).hasSize(1);
    }
}
