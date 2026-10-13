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

import static org.assertj.core.api.Assertions.assertThat;

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

    @Test
    @DisplayName("rotateIfDue keeps the active key until keyTtl has passed")
    void rotateIfDueHonoursKeyTtl() {
        SigningKeyInfo first = rotation.ensureActiveKey();

        clock.set(first.expiresAt().minusSeconds(1));
        assertThat(rotation.rotateIfDue().kid()).isEqualTo(first.kid());

        clock.set(first.expiresAt());
        SigningKeyInfo second = rotation.rotateIfDue();
        assertThat(second.kid()).isNotEqualTo(first.kid());
        assertThat(rotation.activeKey().kid()).isEqualTo(second.kid());
    }

    @Test
    @DisplayName("a replaced key stays in the JWKS for maxTokenTtl + clockSkew, then leaves it")
    void rotationOverlap() {
        SigningKeyInfo first = rotation.ensureActiveKey();
        Instant rotatedAt = T0.plus(Duration.ofHours(3));
        clock.set(rotatedAt);
        SigningKeyInfo second = rotation.rotateKeys();

        SigningKeyInfo retiring = rotation.listKeyGenerations().stream()
                .filter(k -> k.kid().equals(first.kid())).findFirst().orElseThrow();
        Instant windowEnd = rotatedAt.plus(config.maxTokenTtl()).plus(config.clockSkew());
        assertThat(retiring.state()).isEqualTo(KeyState.RETIRING);
        assertThat(retiring.retiredAt()).isEqualTo(windowEnd);

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
    @DisplayName("the maintenance cycle rotates when due, retires, and deletes retired key material")
    void maintenanceCycle() {
        SigningKeyInfo first = rotation.ensureActiveKey();
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
    @DisplayName("a rotation leaves exactly one ACTIVE key even if an earlier one was left active")
    void rotationRetiresEveryOtherActiveKey() {
        rotation.ensureActiveKey();
        // Simulate an interrupted rotation: a second ACTIVE record next to the first.
        var stray = repository.findActive().orElseThrow();
        repository.save(new eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord(
                "k-stray", stray.algorithm(), stray.publicKeyJwkJson(), stray.publicKeyRawBytes(),
                stray.privateKeyPkcs8Bytes(), KeyState.ACTIVE, T0.minusSeconds(10), T0.plus(config.keyTtl()), null));

        clock.advance(Duration.ofMinutes(1));
        rotation.rotateKeys();
        assertThat(rotation.listKeyGenerations().stream().filter(k -> k.state() == KeyState.ACTIVE)).hasSize(1);
    }
}
