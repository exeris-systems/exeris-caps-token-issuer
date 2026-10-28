package eu.exeris.caps.tokenissuer.api;

import java.util.List;

/**
 * Service managing signing key lifecycles, key rotation, overlap window, and key retirement.
 *
 * <p>A key is published before it signs. The next key is generated as {@link KeyState#PENDING}
 * and appears in the JWKS at once; it becomes {@link KeyState#ACTIVE} only once it has been
 * published for the JWKS cache lifetime and the active key is due to be replaced. The key that is
 * replaced stays published as {@link KeyState#RETIRING} until no token it signed can still be
 * accepted.
 *
 * @since 0.1.0
 */
public interface SigningKeyRotation {

    /**
     * Starts a rotation now, whether or not the active key is due. The new Ed25519 key is generated
     * and published as {@link KeyState#PENDING}; it replaces the active key, which moves to
     * {@link KeyState#RETIRING} (published until {@code now + maxTokenTtl + clockSkew}), at the first
     * {@link #rotateIfDue()} after it has been published for the JWKS cache lifetime. A call while
     * a pending key exists returns that key. When there is no active key at all, no verifier has
     * trusted a key of this issuer yet and the new key is active immediately.
     *
     * @return metadata descriptor of the new key: {@link KeyState#PENDING}, or {@link KeyState#ACTIVE}
     *         when it was activated at once or a mature pending key was promoted
     */
    SigningKeyInfo rotateKeys();

    /**
     * Advances the key lifecycle: promotes a pending key that has been published long enough,
     * generates the next pending key shortly before the active key expires, and creates the first
     * key when none exists. Returns only an active key.
     *
     * @return metadata descriptor of the active key after the call
     * @throws eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException when the active key has
     *         expired and its successor has not yet been published for the JWKS cache lifetime;
     *         issuance never signs with an expired key, and the successor is already published
     * @since 0.1.0
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

    /**
     * Withdraws a named signing key immediately, whatever its current lifecycle state.
     *
     * <p>The key is transitioned to {@link KeyState#RETIRED} and removed from the JWKS at once,
     * ensuring it never signs new tokens and live tokens signed by it are rejected by verifiers
     * once they refetch the JWKS.
     *
     * <p>If the withdrawn key was {@link KeyState#ACTIVE}, this operation either activates an existing
     * replacement key that has already been published for at least the JWKS cache lifetime, or leaves
     * the issuer with no active key so that issuance fails closed with
     * {@link eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException}.
     *
     * @param kid identifier of the key to withdraw; non-null
     * @throws IllegalArgumentException if no key with the given identifier exists
     */
    void withdrawKey(String kid);
}
