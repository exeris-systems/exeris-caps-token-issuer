package eu.exeris.caps.tokenissuer.internal.custody;

import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException;
import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException.Reason;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningKeyEnvelopeTest {

    private static final byte[] SECRET = "pkcs8-private-key-bytes".getBytes(StandardCharsets.UTF_8);

    private static SigningKeyEnvelope envelope(String spec) {
        return new SigningKeyEnvelope(KeyEncryptionKeyring.parse("TEST", spec));
    }

    @Test
    @DisplayName("seal and open round-trip; the envelope names its KEK and hides the plaintext")
    void roundTrip() {
        SigningKeyEnvelope env = envelope("k1:" + TestSupport.newKek());
        byte[] sealed = env.seal("kid-1", SECRET);
        assertThat(new String(sealed, StandardCharsets.ISO_8859_1)).doesNotContain("pkcs8-private-key-bytes");
        assertThat(SigningKeyEnvelope.kekIdOf(sealed)).isEqualTo("k1");
        assertThat(env.open("kid-1", sealed)).isEqualTo(SECRET);
    }

    @Test
    @DisplayName("the wrong KEK under the same id fails authentication, with no fallback")
    void wrongKekFails() {
        byte[] sealed = envelope("k1:" + TestSupport.newKek()).seal("kid-1", SECRET);
        assertThatThrownBy(() -> envelope("k1:" + TestSupport.newKek()).open("kid-1", sealed))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));
    }

    @Test
    @DisplayName("an unknown KEK id, plaintext bytes, a moved or tampered envelope are all refused")
    void refusals() {
        String kek = TestSupport.newKek();
        SigningKeyEnvelope env = envelope("k1:" + kek);
        byte[] sealed = env.seal("kid-1", SECRET);

        assertThatThrownBy(() -> envelope("k2:" + kek).open("kid-1", sealed))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.UNKNOWN_KEK));

        assertThatThrownBy(() -> env.open("kid-1", SECRET))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.NOT_SEALED));

        assertThatThrownBy(() -> env.open("kid-2", sealed))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));

        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertThatThrownBy(() -> env.open("kid-1", tampered))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));
    }

    @Test
    @DisplayName("KEK rotation: a new active KEK seals, the previous one still opens older envelopes")
    void kekRotation() {
        String oldKek = TestSupport.newKek();
        byte[] sealedUnderOld = envelope("k-old:" + oldKek).seal("kid-1", SECRET);

        SigningKeyEnvelope rotated = envelope("k-new:" + TestSupport.newKek() + ",k-old:" + oldKek);
        assertThat(rotated.open("kid-1", sealedUnderOld)).isEqualTo(SECRET);
        assertThat(SigningKeyEnvelope.kekIdOf(rotated.seal("kid-2", SECRET))).isEqualTo("k-new");
    }
}
