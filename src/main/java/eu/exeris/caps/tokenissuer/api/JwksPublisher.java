package eu.exeris.caps.tokenissuer.api;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;

/**
 * Service responsible for publishing the JSON Web Key Set (JWKS) containing active
 * and retiring public keys.
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

    /**
     * Registers the HTTP route {@code GET /.well-known/jwks.json} with the given service boundary registry.
     *
     * @param registry service boundary API surface registry; non-null
     */
    void registerBoundaryRoute(ApiSurfaceRegistry registry);
}
