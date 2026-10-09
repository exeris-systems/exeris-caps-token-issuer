package eu.exeris.caps.tokenissuer.api.exception;

/**
 * Thrown when key rotation or retirement operations fail.
 *
 * @since 0.1.0
 */
public class KeyRotationException extends TokenIssuerException {

    public KeyRotationException(String message) {
        super(message);
    }

    public KeyRotationException(String message, Throwable cause) {
        super(message, cause);
    }
}
