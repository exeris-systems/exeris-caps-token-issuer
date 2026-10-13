package eu.exeris.caps.tokenissuer.api;

import java.util.List;

/**
 * Service managing signing key lifecycles, key rotation, overlap window, and key retirement.
 *
 * @since 0.1.0
 */
public interface SigningKeyRotation {

    /**
     * Rotates now, whether or not the active key is due: generates a new active Ed25519 key and
     * moves the previous one to {@link KeyState#RETIRING}, published until
     * {@code now + maxTokenTtl + clockSkew}. This is the explicit operation for an unscheduled
     * rotation, such as a suspected key compromise.
     *
     * @return metadata descriptor of the newly generated active key
     */
    SigningKeyInfo rotateKeys();

    /**
     * Rotates only when there is no active key or the active key's {@code expiresAt} has passed.
     *
     * @return metadata descriptor of the active key after the call
     * @since 0.2.0
     */
    SigningKeyInfo rotateIfDue();

    /**
     * Moves every {@link KeyState#RETIRING} key whose publication window has ended to
     * {@link KeyState#RETIRED}.
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
