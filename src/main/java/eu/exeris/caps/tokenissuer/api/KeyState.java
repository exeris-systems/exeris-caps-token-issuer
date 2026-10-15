package eu.exeris.caps.tokenissuer.api;

/**
 * Lifecycle state of a cryptographic signing key.
 *
 * <ul>
 *   <li>{@link #PENDING}: Generated and already published in the JWKS, but not yet signing. A key
 *       becomes {@link #ACTIVE} only after it has been published for the JWKS cache lifetime, so a
 *       verifier that cached the document before the key existed has refreshed it by the time the
 *       first token signed by the key arrives.</li>
 *   <li>{@link #ACTIVE}: Currently used to sign newly issued access tokens and published in JWKS.</li>
 *   <li>{@link #RETIRING}: No longer signs new tokens, but still published in JWKS during the overlap window to verify previously issued in-flight tokens.</li>
 *   <li>{@link #RETIRED}: Expired past the overlap window; omitted from JWKS publication.</li>
 * </ul>
 *
 * @since 0.1.0
 */
public enum KeyState {
    PENDING,
    ACTIVE,
    RETIRING,
    RETIRED
}
