package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySigningKeyRepositoryTest {

    private InMemorySigningKeyRepository repository;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
    }

    @Test
    @DisplayName("Saves and finds active key")
    void savesAndFindsActiveKey() {
        Instant now = Instant.now();
        SigningKeyRecord rec = new SigningKeyRecord(
                "k-1",
                "EdDSA",
                "{}",
                new byte[32],
                new byte[32],
                KeyState.ACTIVE,
                now,
                now.plus(Duration.ofDays(7)),
                null
        );
        repository.save(rec);

        Optional<SigningKeyRecord> active = repository.findActive();
        assertThat(active).isPresent();
        assertThat(active.get().kid()).isEqualTo("k-1");

        Optional<SigningKeyRecord> byKid = repository.findByKid("k-1");
        assertThat(byKid).isPresent();
    }

    @Test
    @DisplayName("Updates key state and deletes expired retired keys")
    void updatesStateAndDeletesRetired() {
        Instant now = Instant.now();
        SigningKeyRecord rec = new SigningKeyRecord(
                "k-1",
                "EdDSA",
                "{}",
                new byte[32],
                new byte[32],
                KeyState.ACTIVE,
                now.minus(Duration.ofDays(10)),
                now.minus(Duration.ofDays(3)),
                null
        );
        repository.save(rec);

        repository.updateState("k-1", KeyState.RETIRED, now.minus(Duration.ofDays(2)));
        SigningKeyRecord updated = repository.findByKid("k-1").orElseThrow();
        assertThat(updated.state()).isEqualTo(KeyState.RETIRED);

        int deleted = repository.deleteRetiredBefore(now.minus(Duration.ofDays(1)));
        assertThat(deleted).isEqualTo(1);
        assertThat(repository.findByKid("k-1")).isEmpty();
    }
}
