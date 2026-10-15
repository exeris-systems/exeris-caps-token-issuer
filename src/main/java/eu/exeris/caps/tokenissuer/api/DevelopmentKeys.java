package eu.exeris.caps.tokenissuer.api;

/**
 * Explicit acknowledgement for creating an in-memory development token issuer.
 *
 * <p>Signing keys are held unsealed in process memory, lost at restart, not shared across nodes,
 * and must never be used in production.
 *
 * @since 0.1.0
 */
public enum DevelopmentKeys {

    /**
     * Explicitly acknowledges that signing keys are unsealed and held in memory and must never be
     * used in production.
     */
    UNSEALED_ACKNOWLEDGED
}
