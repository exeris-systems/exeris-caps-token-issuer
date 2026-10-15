package eu.exeris.caps.tokenissuer.spi;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Publishes the JWKS document over HTTP at {@code GET /.well-known/jwks.json}.
 *
 * <p>The interface names no type of the service-boundary capability, so a composition without that
 * jar loads this capability unchanged; {@link ApiSurfaceRegistryRegistrar} adapts a service-boundary
 * registry for a composition that has it.
 *
 * @since 0.1.0
 */
@FunctionalInterface
public interface JwksRouteRegistrar {

    /**
     * Registers the route.
     *
     * @param jwksJson supplies the current JWKS document; called once per request
     * @param maxAge   the cache lifetime served to verifiers; the capability publishes a new key at
     *                 least this long before it signs
     */
    void registerJwksRoute(Supplier<String> jwksJson, Duration maxAge);
}
