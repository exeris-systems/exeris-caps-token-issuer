package eu.exeris.caps.tokenissuer;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TokenIssuerModuleTest {

    @Test
    @DisplayName("Lifecycle management and service exposure")
    void lifecycleAndServiceExposure() throws Exception {
        List<ApiSurfaceRoute> routes = new ArrayList<>();
        ApiSurfaceRegistry mockRegistry = new ApiSurfaceRegistry() {
            @Override
            public void registerRoute(ApiSurfaceRoute route) {
                routes.add(route);
            }

            @Override
            public boolean unregisterRoute(ApiSurfaceRoute route) {
                return routes.remove(route);
            }

            @Override
            public Optional<RouteMatch> matchRoute(HttpMethod method, String path) {
                return Optional.empty();
            }

            @Override
            public List<ApiSurfaceRoute> routes() {
                return List.copyOf(routes);
            }

            @Override
            public int routeCount() {
                return routes.size();
            }

            @Override
            public void clear() {
                routes.clear();
            }

            @Override
            public void handle(HttpExchange exchange) {}
        };

        TokenIssuerModule module = new TokenIssuerModule(null, null, mockRegistry, null);

        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();

        module.ready();
        assertThat(module.isReady()).isTrue();

        // 1. Verify route registered
        assertThat(routes).hasSize(1);
        assertThat(routes.get(0).pathPattern()).isEqualTo("/.well-known/jwks.json");

        // 2. Verify active key was bootstrapped
        SigningKeyInfo activeKey = module.signingKeyRotation().activeKey();
        assertThat(activeKey).isNotNull();

        // 3. Verify access token issuance works
        IssuedAccessToken token = module.accessTokenIssuer().issueAccessToken(UUID.randomUUID(), UUID.randomUUID());
        assertThat(token).isNotNull();
        assertThat(token.token()).isNotEmpty();

        // 4. Verify JWKS document contains the active key
        assertThat(module.jwksPublisher().getJwksJson()).contains(activeKey.kid());

        // 5. Drain and terminate
        module.drain(Duration.ofSeconds(1));
        assertThat(module.isReady()).isFalse();

        module.terminate();
        assertThat(module.isInitialized()).isFalse();
    }
}
