package eu.exeris.caps.tokenissuer;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import eu.exeris.caps.tokenissuer.spi.ApiSurfaceRegistryRegistrar;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.scheduling.JobDescriptor;
import eu.exeris.kernel.spi.scheduling.JobHandle;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.kernel.spi.scheduling.JobState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenIssuerModuleTest {

    private static final Map<String, String> ENV = Map.of(
            TokenIssuerConfig.ENV_ISSUER, TestSupport.ISSUER,
            TokenIssuerConfig.ENV_AUDIENCE, TestSupport.AUDIENCE);

    private static final Map<String, String> MANUAL_ENV = Map.of(
            TokenIssuerConfig.ENV_ISSUER, TestSupport.ISSUER,
            TokenIssuerConfig.ENV_AUDIENCE, TestSupport.AUDIENCE,
            TokenIssuerConfig.ENV_MANUAL_ROTATION, "true");

    private static final class RecordingScheduler implements JobScheduler {
        final List<JobDescriptor> submitted = new ArrayList<>();
        boolean cancelled;

        @Override
        public JobHandle submit(JobDescriptor descriptor) {
            submitted.add(descriptor);
            return new JobHandle() {
                @Override public String jobId() { return "job-1"; }
                @Override public String jobName() { return descriptor.jobName(); }
                @Override public JobState state() { return JobState.SCHEDULED; }
                @Override public boolean cancel() { cancelled = true; return true; }
            };
        }

        @Override public JobHandle handle(String jobName) { return null; }
        @Override public void close() { }
    }

    /** Present only so the module selects persistent storage; construction must fail before any use. */
    private static final TransactionalExecutor UNUSED_TX = new TransactionalExecutor() {
        @Override public void execute(TransactionalWork work) { throw new AssertionError("not reached"); }
        @Override public void executeManaged(TransactionalWork work) { throw new AssertionError("not reached"); }
        @Override public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            throw new AssertionError("not reached");
        }
        @Override public <T> T query(Function<PersistenceConnection, T> query) { throw new AssertionError("not reached"); }
    };

    @Test
    @DisplayName("persistent storage without a key-encryption keyring fails construction, typed and closed")
    void missingKekFailsBoot() {
        assertThatThrownBy(() -> new TokenIssuerModule(ENV, UNUSED_TX, new RecordingScheduler(), null, null))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo("EXERIS_TOKEN_ISSUER_KEKS"));

        Map<String, String> malformed = new HashMap<>(ENV);
        malformed.put("EXERIS_TOKEN_ISSUER_KEKS", "k1:c2hvcnQ=");
        assertThatThrownBy(() -> new TokenIssuerModule(malformed, UNUSED_TX, new RecordingScheduler(), null, null))
                .isInstanceOf(TokenIssuerConfigurationException.class);
    }

    @Test
    @DisplayName("a missing issuer or audience fails construction for in-memory storage too")
    void missingIssuerFailsBoot() {
        assertThatThrownBy(() -> TokenIssuerModule.inMemoryForDevelopment(
                Map.of(TokenIssuerConfig.ENV_AUDIENCE, TestSupport.AUDIENCE), null, null, null))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(TokenIssuerConfig.ENV_ISSUER));
    }

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

        TokenIssuerModule module = TokenIssuerModule.inMemoryForDevelopment(MANUAL_ENV, null, new ApiSurfaceRegistryRegistrar(mockRegistry), null);

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

    @Test
    @DisplayName("without a TransactionalExecutor construction fails: there is no silent in-memory plaintext store")
    void missingTransactionalExecutorFailsClosed() {
        assertThatThrownBy(() -> new TokenIssuerModule(MANUAL_ENV, null, null, null, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("TransactionalExecutor");
    }

    @Test
    @DisplayName("without a scheduler construction fails unless manual rotation is explicitly configured")
    void missingSchedulerFailsUnlessManual() {
        assertThatThrownBy(() -> TokenIssuerModule.inMemoryForDevelopment(ENV, null, null, null))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(TokenIssuerConfig.ENV_MANUAL_ROTATION));

        Map<String, String> withKek = new HashMap<>(ENV);
        withKek.put("EXERIS_TOKEN_ISSUER_KEKS", "k1:" + TestSupport.newKek());
        assertThatThrownBy(() -> new TokenIssuerModule(withKek, UNUSED_TX, null, null, null))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(TokenIssuerConfig.ENV_MANUAL_ROTATION));

        assertThat(TokenIssuerModule.inMemoryForDevelopment(MANUAL_ENV, null, null, null)).isNotNull();
    }

    @Test
    @DisplayName("with a scheduler, ready submits the rotation job and drain cancels it")
    void schedulerRunsTheRotationJob() throws Exception {
        RecordingScheduler scheduler = new RecordingScheduler();
        TokenIssuerModule module = TokenIssuerModule.inMemoryForDevelopment(ENV, scheduler, null, null);

        module.ready();
        assertThat(scheduler.submitted).hasSize(1);
        assertThat(scheduler.submitted.getFirst().jobName()).isEqualTo("exeris-token-issuer-key-rotation");
        scheduler.submitted.getFirst().body().run();
        assertThat(module.signingKeyRotation().activeKey()).isNotNull();

        module.drain(Duration.ofSeconds(1));
        assertThat(scheduler.cancelled).isTrue();
    }

    @Test
    @DisplayName("the no-arg instance is lifecycle-only: it reads no configuration and serves no service")
    void lifecycleOnlyInstance() throws Exception {
        TokenIssuerModule module = new TokenIssuerModule();
        module.initialize();
        module.ready();
        assertThat(module.isReady()).isTrue();
        assertThatThrownBy(module::accessTokenIssuer).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::jwksPublisher).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::signingKeyRotation).isInstanceOf(IllegalStateException.class);
        module.terminate();
    }
}
