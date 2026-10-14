package eu.exeris.caps.tokenissuer.spi;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.tokenissuer.internal.boundary.JwksHttpRoute;

import java.time.Duration;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Adapter from {@link JwksRouteRegistrar} to the service-boundary capability's
 * {@link ApiSurfaceRegistry}.
 *
 * <p>This is the only class of the capability that names a service-boundary type. A composition
 * without that jar never loads it.
 *
 * @since 0.1.0
 */
public final class ApiSurfaceRegistryRegistrar implements JwksRouteRegistrar {

    private final ApiSurfaceRegistry registry;

    /**
     * @param registry the registry to register the route with; required
     */
    public ApiSurfaceRegistryRegistrar(ApiSurfaceRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
    }

    @Override
    public void registerJwksRoute(Supplier<String> jwksJson, Duration maxAge) {
        registry.registerRoute(JwksHttpRoute.createRoute(jwksJson, maxAge));
    }
}
