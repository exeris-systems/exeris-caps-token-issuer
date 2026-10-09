package eu.exeris.caps.tokenissuer.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Ed25519SignerTest {

    @Test
    @DisplayName("Generates valid Ed25519 keypair and extracts 32 raw bytes")
    void generatesValidKeyPair() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();

        byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
        assertThat(rawPub).hasSize(32);
    }

    @Test
    @DisplayName("Signs and verifies payload with Ed25519")
    void signsAndVerifiesPayload() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        byte[] data = "test-payload-to-sign".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Ed25519Signer.sign(data, keyPair.getPrivate());
        assertThat(signature).hasSize(64);

        boolean valid = Ed25519Signer.verify(data, signature, keyPair.getPublic());
        assertThat(valid).isTrue();

        byte[] tampered = "tampered-payload".getBytes(StandardCharsets.UTF_8);
        boolean invalid = Ed25519Signer.verify(tampered, signature, keyPair.getPublic());
        assertThat(invalid).isFalse();
    }

    @Test
    @DisplayName("Reconstructs public and private keys from bytes")
    void reconstructsKeysFromBytes() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
        byte[] privPkcs8 = keyPair.getPrivate().getEncoded();

        PublicKey reconstructedPub = Ed25519Signer.reconstructPublicKey(rawPub);
        PrivateKey reconstructedPriv = Ed25519Signer.reconstructPrivateKey(privPkcs8);

        byte[] data = "reconstruction-test".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Ed25519Signer.sign(data, reconstructedPriv);
        assertThat(Ed25519Signer.verify(data, signature, reconstructedPub)).isTrue();
    }

    @Test
    @DisplayName("Rejects raw public key with invalid length")
    void rejectsInvalidRawPublicKeyLength() {
        byte[] invalid = new byte[16];
        assertThatThrownBy(() -> Ed25519Signer.reconstructPublicKey(invalid))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
