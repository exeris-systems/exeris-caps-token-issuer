package eu.exeris.caps.tokenissuer.api.exception;

/**
 * Base unchecked exception for all token-issuer capability operations.
 *
 * @since 0.1.0
 */
public class TokenIssuerException extends RuntimeException {

    public TokenIssuerException(String message) {
        super(message);
    }

    public TokenIssuerException(String message, Throwable cause) {
        super(message, cause);
    }
}
