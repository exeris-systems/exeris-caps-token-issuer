package eu.exeris.caps.tokenissuer.api.exception;

/**
 * Thrown when an operation requires an active signing key, but no active key is available in the repository.
 *
 * @since 0.1.0
 */
public class NoActiveKeyException extends TokenIssuerException {

    public NoActiveKeyException(String message) {
        super(message);
    }

    public NoActiveKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
