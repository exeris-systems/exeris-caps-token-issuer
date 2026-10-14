package eu.exeris.caps.tokenissuer.api.exception;

import java.util.Objects;

/**
 * A stored signing key could not be unwrapped with the configured key-encryption keyring.
 *
 * <p>There is no fallback: a record that is not a sealed envelope, names a key-encryption key the
 * keyring does not hold, or fails AEAD authentication is refused, and no token is signed with it.
 *
 * @since 0.1.0
 */
public class SigningKeyCustodyException extends TokenIssuerException {

    /**
     * Why the stored key was refused.
     */
    public enum Reason {
        /** The stored bytes are not a sealed envelope; plaintext key material is never accepted. */
        NOT_SEALED,
        /** The envelope names a key-encryption key id that is not in the configured keyring. */
        UNKNOWN_KEK,
        /** AEAD authentication failed: wrong key-encryption key, tampered bytes, or a different {@code kid}. */
        AUTHENTICATION_FAILED
    }

    private final Reason reason;
    private final String kid;

    public SigningKeyCustodyException(Reason reason, String kid, String message) {
        super(message);
        this.reason = Objects.requireNonNull(reason, "reason must not be null");
        this.kid = kid;
    }

    public SigningKeyCustodyException(Reason reason, String kid, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(reason, "reason must not be null");
        this.kid = kid;
    }

    public Reason reason() {
        return reason;
    }

    /**
     * Returns the signing key id of the refused record.
     *
     * @return the signing key id
     */
    public String kid() {
        return kid;
    }
}
