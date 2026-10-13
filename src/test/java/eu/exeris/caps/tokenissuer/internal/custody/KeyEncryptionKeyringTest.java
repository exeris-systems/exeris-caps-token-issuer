package eu.exeris.caps.tokenissuer.internal.custody;

import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyEncryptionKeyringTest {

    @Test
    @DisplayName("no keyring configured fails closed with a typed error naming the key")
    void missingKeyringFailsClosed() {
        assertThatThrownBy(() -> KeyEncryptionKeyring.fromEnvironment(Map.of()))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(KeyEncryptionKeyring.ENV_KEKS));
    }

    @Test
    @DisplayName("malformed entries fail without echoing key material")
    void malformedKeyringFailsClosed() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", "k1:" + shortKey))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .hasMessageContaining("32 bytes")
                .hasMessageNotContaining(shortKey);
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", "k1:not*base64"))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .hasMessageNotContaining("not*base64");
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", TestSupport.newKek()))
                .isInstanceOf(TokenIssuerConfigurationException.class);
        String kek = TestSupport.newKek();
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", "k1:" + kek + ",k1:" + TestSupport.newKek()))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .hasMessageContaining("twice");
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", "bad id:" + kek))
                .isInstanceOf(TokenIssuerConfigurationException.class);
        // A passphrase is not a key: nothing is derived from it.
        assertThatThrownBy(() -> KeyEncryptionKeyring.parse("SRC", "k1:correct-horse-battery-staple"))
                .isInstanceOf(TokenIssuerConfigurationException.class);
    }

    @Test
    @DisplayName("the first entry is active; inline and file sources are mutually exclusive")
    void activeEntryAndSources(@TempDir Path dir) throws Exception {
        String activeKek = TestSupport.newKek();
        String olderKek = TestSupport.newKek();
        KeyEncryptionKeyring ring = KeyEncryptionKeyring.parse("SRC",
                "kek-2026b:" + activeKek + ", kek-2026a:" + olderKek);
        assertThat(ring.activeId()).isEqualTo("kek-2026b");
        assertThat(ring.toString()).contains("kek-2026a").doesNotContain(activeKek).doesNotContain(olderKek);

        Path file = dir.resolve("keks");
        Files.writeString(file, "kek-file:" + TestSupport.newKek() + "\n");
        assertThat(KeyEncryptionKeyring.fromEnvironment(Map.of(KeyEncryptionKeyring.ENV_KEKS_FILE, file.toString()))
                .activeId()).isEqualTo("kek-file");

        assertThatThrownBy(() -> KeyEncryptionKeyring.fromEnvironment(Map.of(
                KeyEncryptionKeyring.ENV_KEKS, "k1:" + TestSupport.newKek(),
                KeyEncryptionKeyring.ENV_KEKS_FILE, file.toString())))
                .isInstanceOf(TokenIssuerConfigurationException.class);

        assertThatThrownBy(() -> KeyEncryptionKeyring.fromEnvironment(Map.of(
                KeyEncryptionKeyring.ENV_KEKS_FILE, dir.resolve("absent").toString())))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(KeyEncryptionKeyring.ENV_KEKS_FILE));
    }
}
