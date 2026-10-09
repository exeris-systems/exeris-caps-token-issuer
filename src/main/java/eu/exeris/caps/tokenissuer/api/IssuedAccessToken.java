package eu.exeris.caps.tokenissuer.api;

import java.time.Instant;
import java.util.Objects;

/**
 * Short-lived access token issued for an authenticated subject and session.
 *
 * @param token     signed access token string (Ed25519-signed compact JWT)
 * @param expiresAt token expiration timestamp
 * @param tokenType token scheme (defaults to {@code Bearer})
 * @since 0.1.0
 */
public record IssuedAccessToken(
        String token,
        Instant expiresAt,
        String tokenType
) {

    public IssuedAccessToken {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        tokenType = tokenType != null ? tokenType : "Bearer";
    }

    public IssuedAccessToken(String token, Instant expiresAt) {
        this(token, expiresAt, "Bearer");
    }
}
