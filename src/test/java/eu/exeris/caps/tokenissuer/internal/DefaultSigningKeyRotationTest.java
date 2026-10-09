package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultSigningKeyRotationTest {

    private InMemorySigningKeyRepository repository;
    private KeyRotationPolicy policy;
    private DefaultSigningKeyRotation rotation;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        policy = KeyRotationPolicy.defaults();
        rotation = new DefaultSigningKeyRotation(repository, policy, null);
    }

    @Test
    @DisplayName("ensureActiveKey creates active key on empty repository")
    void ensureActiveKeyCreatesActiveKey() {
        SigningKeyInfo active = rotation.ensureActiveKey();
        assertThat(active).isNotNull();
        assertThat(active.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(active.algorithm()).isEqualTo("EdDSA");

        SigningKeyInfo retrieved = rotation.activeKey();
        assertThat(retrieved.kid()).isEqualTo(active.kid());
    }

    @Test
    @DisplayName("rotateKeys transitions previous key to RETIRING and sets new ACTIVE key")
    void rotateKeysTransitionsPreviousKey() {
        SigningKeyInfo key1 = rotation.rotateKeys();
        assertThat(key1.state()).isEqualTo(KeyState.ACTIVE);

        SigningKeyInfo key2 = rotation.rotateKeys();
        assertThat(key2.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(key2.kid()).isNotEqualTo(key1.kid());

        List<SigningKeyInfo> history = rotation.listKeyGenerations();
        assertThat(history).hasSize(2);

        SigningKeyInfo oldKey = history.stream().filter(k -> k.kid().equals(key1.kid())).findFirst().orElseThrow();
        assertThat(oldKey.state()).isEqualTo(KeyState.RETIRING);
        assertThat(oldKey.retiredAt()).isNotNull();

        assertThat(rotation.activeKey().kid()).isEqualTo(key2.kid());
    }

    @Test
    @DisplayName("retireExpiredKeys marks keys past effectiveRetireAt as RETIRED")
    void retireExpiredKeysMarksPastKeysAsRetired() {
        KeyRotationPolicy shortPolicy = new KeyRotationPolicy(
                Duration.ofMillis(10),
                Duration.ofMillis(10),
                Duration.ofMinutes(15),
                Duration.ofDays(7),
                "https://auth.exeris.eu",
                "https://api.exeris.eu"
        );
        DefaultSigningKeyRotation shortRotation = new DefaultSigningKeyRotation(repository, shortPolicy, null);

        SigningKeyInfo key1 = shortRotation.rotateKeys();
        SigningKeyInfo key2 = shortRotation.rotateKeys();

        // Wait past overlap window
        try {
            Thread.sleep(30);
        } catch (InterruptedException ignored) {}

        int retired = shortRotation.retireExpiredKeys();
        assertThat(retired).isEqualTo(1);

        List<SigningKeyInfo> history = shortRotation.listKeyGenerations();
        SigningKeyInfo retiredKey = history.stream().filter(k -> k.kid().equals(key1.kid())).findFirst().orElseThrow();
        assertThat(retiredKey.state()).isEqualTo(KeyState.RETIRED);
    }
}
