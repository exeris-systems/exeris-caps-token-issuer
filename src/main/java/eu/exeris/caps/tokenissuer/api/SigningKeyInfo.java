package eu.exeris.caps.tokenissuer.api;

import java.time.Instant;
import java.util.Objects;

/**
 * Public metadata descriptor of a signing key generation.
 *
 * @param kid       key identifier; non-null
 * @param algorithm cryptographic algorithm (e.g. {@code EdDSA}); non-null
 * @param state     current lifecycle state; non-null
 * @param createdAt instant key was generated; non-null
 * @param expiresAt instant key is scheduled to cease active signing; non-null
 * @param retiredAt instant key transitions to fully retired (past overlap window); nullable
 * @since 0.1.0
 */
public record SigningKeyInfo(
        String kid,
        String algorithm,
        KeyState state,
        Instant createdAt,
        Instant expiresAt,
        Instant retiredAt
) {

    public SigningKeyInfo {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }
}
