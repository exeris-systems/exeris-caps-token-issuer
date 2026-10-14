package eu.exeris.caps.tokenissuer.api.exception;

import java.util.Objects;

/**
 * Required configuration of the token issuer is missing or malformed.
 *
 * <p>Thrown while the capability is constructed, so a deployment without a valid issuer, audience
 * or key-encryption keyring fails to boot instead of running on a substitute value. The message
 * names the configuration key and never contains the value that was supplied for it.
 *
 * @since 0.1.0
 */
public class TokenIssuerConfigurationException extends TokenIssuerException {

    private final String key;

    public TokenIssuerConfigurationException(String key, String message) {
        super(Objects.requireNonNull(key, "key must not be null") + ": " + message);
        this.key = key;
    }

    public TokenIssuerConfigurationException(String key, String message, Throwable cause) {
        super(Objects.requireNonNull(key, "key must not be null") + ": " + message, cause);
        this.key = key;
    }

    /**
     * @return the configuration key that is missing or malformed
     */
    public String key() {
        return key;
    }
}
