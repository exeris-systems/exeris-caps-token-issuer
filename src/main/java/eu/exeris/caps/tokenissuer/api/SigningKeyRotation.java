package eu.exeris.caps.tokenissuer.api;

import java.util.List;

/**
 * Service managing signing key lifecycles, key rotation, overlap window, and key retirement.
 *
 * @since 0.1.0
 */
public interface SigningKeyRotation {

    /**
     * Performs a key rotation: generates a new active Ed25519 key, transitions the existing
     * active key to retiring (with expiration based on the overlap window), and stores the changes.
     *
     * @return metadata descriptor of the newly generated active key
     */
    SigningKeyInfo rotateKeys();

    /**
     * Retires expired keys whose overlap window has elapsed.
     *
     * @return number of keys transitioned to retired
     */
    int retireExpiredKeys();

    /**
     * Lists all recorded signing key generations and their lifecycle states.
     *
     * @return list of signing key metadata
     */
    List<SigningKeyInfo> listKeyGenerations();

    /**
     * Returns the currently active signing key.
     *
     * @return metadata descriptor of the active key
     * @throws eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException if no active key exists
     */
    SigningKeyInfo activeKey();
}
