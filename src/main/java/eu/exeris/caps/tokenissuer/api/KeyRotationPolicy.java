package eu.exeris.caps.tokenissuer.api;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration policy defining key lifecycles, rotation schedule, and default token claims.
 *
 * @param keyTtl           active duration of a signing key before rotation; non-null, positive
 * @param overlapWindow    grace duration during which a retired key remains published in JWKS; non-null, positive
 * @param defaultTokenTtl  default lifetime of issued access tokens; non-null, positive
 * @param rotationInterval interval between scheduled automated key rotation checks; non-null, positive
 * @param defaultIssuer    default issuer claim value (iss); non-null, non-blank
 * @param defaultAudience  default audience claim value (aud); non-null, non-blank
 * @since 0.1.0
 */
public record KeyRotationPolicy(
        Duration keyTtl,
        Duration overlapWindow,
        Duration defaultTokenTtl,
        Duration rotationInterval,
        String defaultIssuer,
        String defaultAudience
) {

    public KeyRotationPolicy {
        Objects.requireNonNull(keyTtl, "keyTtl must not be null");
        Objects.requireNonNull(overlapWindow, "overlapWindow must not be null");
        Objects.requireNonNull(defaultTokenTtl, "defaultTokenTtl must not be null");
        Objects.requireNonNull(rotationInterval, "rotationInterval must not be null");
        Objects.requireNonNull(defaultIssuer, "defaultIssuer must not be null");
        Objects.requireNonNull(defaultAudience, "defaultAudience must not be null");

        if (keyTtl.isNegative() || keyTtl.isZero()) {
            throw new IllegalArgumentException("keyTtl must be positive");
        }
        if (overlapWindow.isNegative() || overlapWindow.isZero()) {
            throw new IllegalArgumentException("overlapWindow must be positive");
        }
        if (defaultTokenTtl.isNegative() || defaultTokenTtl.isZero()) {
            throw new IllegalArgumentException("defaultTokenTtl must be positive");
        }
        if (rotationInterval.isNegative() || rotationInterval.isZero()) {
            throw new IllegalArgumentException("rotationInterval must be positive");
        }
        if (defaultIssuer.isBlank()) {
            throw new IllegalArgumentException("defaultIssuer must not be blank");
        }
        if (defaultAudience.isBlank()) {
            throw new IllegalArgumentException("defaultAudience must not be blank");
        }
    }

    /**
     * Standard policy defaults:
     * <ul>
     *   <li>keyTtl: 7 days</li>
     *   <li>overlapWindow: 24 hours</li>
     *   <li>defaultTokenTtl: 15 minutes</li>
     *   <li>rotationInterval: 7 days</li>
     *   <li>defaultIssuer: {@code "https://auth.exeris.eu"}</li>
     *   <li>defaultAudience: {@code "https://api.exeris.eu"}</li>
     * </ul>
     */
    public static KeyRotationPolicy defaults() {
        return new KeyRotationPolicy(
                Duration.ofDays(7),
                Duration.ofDays(1),
                Duration.ofMinutes(15),
                Duration.ofDays(7),
                "https://auth.exeris.eu",
                "https://api.exeris.eu"
        );
    }
}
