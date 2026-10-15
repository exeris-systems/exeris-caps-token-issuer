package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.serviceboundarycore.api.AdmissionFilter;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RequestFilterChain;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.internal.boundary.JwksHttpRoute;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultJwksPublisherTest {

    private InMemorySigningKeyRepository repository;
    private DefaultSigningKeyRotation rotation;
    private DefaultJwksPublisher publisher;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        rotation = new DefaultSigningKeyRotation(repository, TestSupport.config(), null, null, clock);
        publisher = new DefaultJwksPublisher(repository, clock);
    }

    @Test
    @DisplayName("every JWK is exactly kty=OKP, crv=Ed25519, alg=EdDSA, use=sig, kid, x (32 bytes) and nothing private")
    @SuppressWarnings("unchecked")
    void jwksShape() throws Exception {
        SigningKeyInfo first = rotation.rotateKeys();
        SigningKeyInfo second = rotation.rotateKeys();

        Map<String, Object> parsed = JsonUtil.parseJson(publisher.getJwksJson());
        assertThat(parsed).containsOnlyKeys("keys");
        List<Map<String, Object>> keys = (List<Map<String, Object>>) parsed.get("keys");
        assertThat(keys).hasSize(2);
        assertThat(keys).extracting(k -> k.get("kid")).containsExactlyInAnyOrder(first.kid(), second.kid());
        for (Map<String, Object> jwk : keys) {
            assertThat(jwk).containsOnlyKeys("kty", "crv", "alg", "use", "kid", "x")
                    .containsEntry("kty", "OKP")
                    .containsEntry("crv", "Ed25519")
                    .containsEntry("alg", "EdDSA")
                    .containsEntry("use", "sig");
            String x = (String) jwk.get("x");
            assertThat(x).doesNotContain("=").doesNotContain("+").doesNotContain("/");
            assertThat(Base64.getUrlDecoder().decode(x)).hasSize(32);
        }
        assertThat(publisher.getJwksDocument().rawJson()).isEqualTo(publisher.getJwksJson());
    }

    @Test
    @DisplayName("Registers route with ApiSurfaceRegistry")
    void registersRouteWithApiSurfaceRegistry() {
        rotation.rotateKeys();

        List<ApiSurfaceRoute> registered = new ArrayList<>();
        ApiSurfaceRegistry registry = new ApiSurfaceRegistry() {
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


            @Override

            public RequestFilterChain filterChain() {

                return RequestFilterChain.empty();

            }



            @Override


            public void registerFilter(AdmissionFilter filter) {


                filterChain().registerFilter(filter);


            }



            @Override


            public boolean unregisterFilter(AdmissionFilter filter) {


                return false;


            }



            @Override


            public List<AdmissionFilter> filters() {


                return List.of();


            }
        };

        new eu.exeris.caps.tokenissuer.spi.ApiSurfaceRegistryRegistrar(registry).registerJwksRoute(publisher::getJwksJson, java.time.Duration.ofMinutes(5));

        assertThat(registered).hasSize(1);
        ApiSurfaceRoute route = registered.get(0);
        assertThat(route.method()).isEqualTo(HttpMethod.GET);
        assertThat(route.pathPattern()).isEqualTo(JwksHttpRoute.PATH);
    }
}
