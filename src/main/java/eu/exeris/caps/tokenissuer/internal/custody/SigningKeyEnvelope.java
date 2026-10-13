package eu.exeris.caps.tokenissuer.internal.custody;

import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException;
import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException.Reason;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerException;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Seals and opens signing-key material with AES-256-GCM under a {@link KeyEncryptionKeyring}.
 *
 * <p>Layout: {@code "EXK" 0x01 | kekIdLength (1 byte) | kekId (ASCII) | nonce (12) | ciphertext || tag (16)}.
 * The header and the signing key's {@code kid} are the associated data, so an envelope opens only
 * under the KEK it names and only for the record it was sealed for: copying one row's private key
 * into another row fails authentication. Opening never returns bytes it could not authenticate.
 */
public final class SigningKeyEnvelope {

    private static final byte[] MAGIC = {'E', 'X', 'K', 0x01};
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final KeyEncryptionKeyring keyring;
    private final SecureRandom random;

    public SigningKeyEnvelope(KeyEncryptionKeyring keyring) {
        this(keyring, new SecureRandom());
    }

    SigningKeyEnvelope(KeyEncryptionKeyring keyring, SecureRandom random) {
        this.keyring = Objects.requireNonNull(keyring, "keyring must not be null");
        this.random = Objects.requireNonNull(random, "random must not be null");
    }

    public String activeKekId() {
        return keyring.activeId();
    }

    /**
     * Seals {@code plaintext} under the active KEK, bound to {@code kid}.
     */
    public byte[] seal(String kid, byte[] plaintext) {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext must not be empty");
        }
        byte[] header = header(keyring.activeId());
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keyring.activeKey(), new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(associatedData(header, kid));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] sealed = new byte[header.length + NONCE_LENGTH + ciphertext.length];
            System.arraycopy(header, 0, sealed, 0, header.length);
            System.arraycopy(nonce, 0, sealed, header.length, NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, sealed, header.length + NONCE_LENGTH, ciphertext.length);
            return sealed;
        } catch (GeneralSecurityException e) {
            throw new TokenIssuerException("sealing signing key '" + kid + "' failed", e);
        }
    }

    /**
     * Opens an envelope sealed for {@code kid}.
     *
     * @throws SigningKeyCustodyException when the bytes are not an envelope, name an unknown KEK,
     *                                    or fail authentication
     */
    public byte[] open(String kid, byte[] sealed) {
        Objects.requireNonNull(kid, "kid must not be null");
        if (sealed == null || sealed.length < MAGIC.length + 1
                || !Arrays.equals(sealed, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw new SigningKeyCustodyException(Reason.NOT_SEALED, kid,
                    "signing key '" + kid + "' is not a sealed envelope; plaintext key material is refused");
        }
        int idLength = sealed[MAGIC.length] & 0xFF;
        int headerLength = MAGIC.length + 1 + idLength;
        if (idLength == 0 || sealed.length < headerLength + NONCE_LENGTH + TAG_LENGTH_BITS / 8 + 1) {
            throw new SigningKeyCustodyException(Reason.NOT_SEALED, kid,
                    "signing key '" + kid + "' has a truncated envelope");
        }
        String kekId = new String(sealed, MAGIC.length + 1, idLength, StandardCharsets.US_ASCII);
        SecretKey kek = keyring.key(kekId).orElseThrow(() -> new SigningKeyCustodyException(Reason.UNKNOWN_KEK, kid,
                "signing key '" + kid + "' is sealed under KEK '" + kekId + "', which the keyring does not hold"));
        byte[] header = Arrays.copyOfRange(sealed, 0, headerLength);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, kek,
                    new GCMParameterSpec(TAG_LENGTH_BITS, sealed, headerLength, NONCE_LENGTH));
            cipher.updateAAD(associatedData(header, kid));
            return cipher.doFinal(sealed, headerLength + NONCE_LENGTH, sealed.length - headerLength - NONCE_LENGTH);
        } catch (AEADBadTagException e) {
            throw new SigningKeyCustodyException(Reason.AUTHENTICATION_FAILED, kid,
                    "signing key '" + kid + "' failed authentication under KEK '" + kekId + "'", e);
        } catch (GeneralSecurityException e) {
            throw new SigningKeyCustodyException(Reason.AUTHENTICATION_FAILED, kid,
                    "signing key '" + kid + "' could not be opened under KEK '" + kekId + "'", e);
        }
    }

    /**
     * @return the KEK id an envelope names, or {@code null} when the bytes are not an envelope
     */
    public static String kekIdOf(byte[] sealed) {
        if (sealed == null || sealed.length < MAGIC.length + 1
                || !Arrays.equals(sealed, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            return null;
        }
        int idLength = sealed[MAGIC.length] & 0xFF;
        if (sealed.length < MAGIC.length + 1 + idLength) {
            return null;
        }
        return new String(sealed, MAGIC.length + 1, idLength, StandardCharsets.US_ASCII);
    }

    private static byte[] header(String kekId) {
        byte[] id = kekId.getBytes(StandardCharsets.US_ASCII);
        byte[] header = new byte[MAGIC.length + 1 + id.length];
        System.arraycopy(MAGIC, 0, header, 0, MAGIC.length);
        header[MAGIC.length] = (byte) id.length;
        System.arraycopy(id, 0, header, MAGIC.length + 1, id.length);
        return header;
    }

    private static byte[] associatedData(byte[] header, String kid) {
        byte[] kidBytes = kid.getBytes(StandardCharsets.UTF_8);
        byte[] aad = new byte[header.length + kidBytes.length];
        System.arraycopy(header, 0, aad, 0, header.length);
        System.arraycopy(kidBytes, 0, aad, header.length, kidBytes.length);
        return aad;
    }
}
