package eu.exeris.caps.tokenissuer.api;

/**
 * Service responsible for publishing the JSON Web Key Set (JWKS) containing active
 * and retiring public keys.
 *
 * <p>The HTTP route is not part of this contract: it is registered through a
 * {@link eu.exeris.caps.tokenissuer.spi.JwksRouteRegistrar}, so this interface names no type of an
 * optional capability.
 *
 * @since 0.1.0
 */
public interface JwksPublisher {

    /**
     * Returns the serialized JWKS document containing active and retiring Ed25519 public keys.
     *
     * @return RFC 8037 compliant JSON string
     */
    String getJwksJson();

    /**
     * Returns the structured {@link JwksDocument} descriptor.
     *
     * @return structured JWKS document
     */
    JwksDocument getJwksDocument();
}
