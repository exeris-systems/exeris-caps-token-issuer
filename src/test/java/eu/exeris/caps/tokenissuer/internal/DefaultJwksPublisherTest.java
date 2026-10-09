package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.caps.tokenissuer.api.JwksDocument;
import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.internal.boundary.JwksHttpRoute;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultJwksPublisherTest {

    private InMemorySigningKeyRepository repository;
    private KeyRotationPolicy policy;
    private DefaultSigningKeyRotation rotation;
    private DefaultJwksPublisher publisher;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        policy = KeyRotationPolicy.defaults();
        rotation = new DefaultSigningKeyRotation(repository, policy, null);
        publisher = new DefaultJwksPublisher(repository, policy);
    }

    @Test
    @DisplayName("Publishes active and retiring keys in JWKS format")
    void publishesActiveAndRetiringKeys() {
        rotation.rotateKeys();
        rotation.rotateKeys();

        JwksDocument doc = publisher.getJwksDocument();
        assertThat(doc.keys()).hasSize(2);
        assertThat(doc.rawJson()).contains("\"keys\":[");
        assertThat(publisher.getJwksJson()).isEqualTo(doc.rawJson());
    }

    @Test
    @DisplayName("Registers route with ApiSurfaceRegistry")
    void registersRouteWithApiSurfaceRegistry() {
        rotation.rotateKeys();

        List<ApiSurfaceRoute> registered = new ArrayList<>();
        ApiSurfaceRegistry mockRegistry = new ApiSurfaceRegistry() {
            @Override
            public void registerRoute(ApiSurfaceRoute route) {
                registered.add(route);
            }

            @Override
            public boolean unregisterRoute(ApiSurfaceRoute route) {
                return registered.remove(route);
            }

            @Override
            public Optional<RouteMatch> matchRoute(HttpMethod method, String path) {
                return Optional.empty();
            }

            @Override
            public List<ApiSurfaceRoute> routes() {
                return List.copyOf(registered);
            }

            @Override
            public int routeCount() {
                return registered.size();
            }

            @Override
            public void clear() {
                registered.clear();
            }

            @Override
            public void handle(HttpExchange exchange) {
            }
        };

        publisher.registerBoundaryRoute(mockRegistry);

        assertThat(registered).hasSize(1);
        ApiSurfaceRoute route = registered.get(0);
        assertThat(route.method()).isEqualTo(HttpMethod.GET);
        assertThat(route.pathPattern()).isEqualTo(JwksHttpRoute.PATH);
    }
}
