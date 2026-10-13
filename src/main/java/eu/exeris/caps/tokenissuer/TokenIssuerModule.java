package eu.exeris.caps.tokenissuer;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.caps.tokenissuer.api.SigningKeyRotation;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import eu.exeris.caps.tokenissuer.internal.DefaultAccessTokenIssuer;
import eu.exeris.caps.tokenissuer.internal.DefaultJwksPublisher;
import eu.exeris.caps.tokenissuer.internal.DefaultSigningKeyRotation;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.custody.KeyEncryptionKeyring;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.PostgresSigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-token-issuer}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link AccessTokenIssuer} (short-lived JWT access tokens signed with EdDSA over Ed25519)</li>
 *   <li>{@link JwksPublisher} (JWKS document containing active and retiring public keys)</li>
 *   <li>{@link SigningKeyRotation} (key generations, publication window, retirement, and scheduler integration)</li>
 * </ul>
 *
 * <p>Construction reads {@link TokenIssuerConfig} from the environment and fails with a
 * {@link TokenIssuerConfigurationException} when the issuer or audience is missing. With a
 * {@link TransactionalExecutor} the signing keys are stored in PostgreSQL, sealed under the
 * key-encryption keyring of {@code EXERIS_TOKEN_ISSUER_KEKS} or {@code EXERIS_TOKEN_ISSUER_KEKS_FILE};
 * a missing or malformed keyring fails construction the same way. Without one the keys live in
 * process memory only and are never written anywhere.
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = AccessTokenIssuer.class, version = "2.0.0")
@Provides(service = JwksPublisher.class, version = "1.1.0")
@Provides(service = SigningKeyRotation.class, version = "1.1.0")
@Requires(service = ApiSurfaceRegistry.class, optional = true)
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = JobScheduler.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[1.0.0,2.0.0)", optional = true)
public final class TokenIssuerModule implements CapabilityLifecycleHooks {

    private final AccessTokenIssuer accessTokenIssuer;
    private final JwksPublisher jwksPublisher;
    private final DefaultSigningKeyRotation signingKeyRotation;
    private final ApiSurfaceRegistry apiSurfaceRegistry;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition conductor: in-memory
     * keys, configuration from {@code System.getenv()}.
     *
     * @throws TokenIssuerConfigurationException when required configuration is missing or malformed
     */
    public TokenIssuerModule() {
        this(System.getenv(), null, null, null, null);
    }

    /**
     * Wiring with kernel and capability SPIs, configuration from {@code System.getenv()}.
     *
     * @throws TokenIssuerConfigurationException when required configuration is missing or malformed
     */
    public TokenIssuerModule(
            TransactionalExecutor tx,
            JobScheduler scheduler,
            ApiSurfaceRegistry apiSurfaceRegistry,
            AuditLogSink auditLogSink
    ) {
        this(System.getenv(), tx, scheduler, apiSurfaceRegistry, auditLogSink);
    }

    /**
     * Wiring with kernel and capability SPIs and an explicit configuration source.
     *
     * @param environment environment-style configuration; non-null
     * @throws TokenIssuerConfigurationException when required configuration is missing or malformed
     */
    public TokenIssuerModule(
            Map<String, String> environment,
            TransactionalExecutor tx,
            JobScheduler scheduler,
            ApiSurfaceRegistry apiSurfaceRegistry,
            AuditLogSink auditLogSink
    ) {
        this(
                TokenIssuerConfig.fromEnvironment(Objects.requireNonNull(environment, "environment must not be null")),
                tx != null
                        ? new PostgresSigningKeyRepository(tx, KeyEncryptionKeyring.fromEnvironment(environment))
                        : new InMemorySigningKeyRepository(),
                apiSurfaceRegistry,
                scheduler,
                auditLogSink != null ? new TokenIssuerAuditBridge(auditLogSink) : null,
                Clock.systemUTC()
        );
    }

    TokenIssuerModule(
            TokenIssuerConfig config,
            SigningKeyRepository repository,
            ApiSurfaceRegistry apiSurfaceRegistry,
            JobScheduler jobScheduler,
            TokenIssuerAuditBridge auditBridge,
            Clock clock
    ) {
        Objects.requireNonNull(config, "config must not be null");
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(clock, "clock must not be null");

        this.apiSurfaceRegistry = apiSurfaceRegistry;
        this.signingKeyRotation = new DefaultSigningKeyRotation(repository, config, auditBridge, jobScheduler, clock);
        this.jwksPublisher = new DefaultJwksPublisher(repository, clock);
        this.accessTokenIssuer = new DefaultAccessTokenIssuer(repository, config, this.signingKeyRotation, auditBridge, clock);
    }

    public AccessTokenIssuer accessTokenIssuer() {
        return accessTokenIssuer;
    }

    public JwksPublisher jwksPublisher() {
        return jwksPublisher;
    }

    public SigningKeyRotation signingKeyRotation() {
        return signingKeyRotation;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        // 1. Ensure an unexpired active signing key exists
        signingKeyRotation.ensureActiveKey();

        // 2. Register HTTP route GET /.well-known/jwks.json if service-boundary-core is present
        if (apiSurfaceRegistry != null) {
            jwksPublisher.registerBoundaryRoute(apiSurfaceRegistry);
        }

        // 3. Start automated background key rotation if scheduler is present
        signingKeyRotation.startScheduledRotation();
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
        signingKeyRotation.stopScheduledRotation();
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
        signingKeyRotation.stopScheduledRotation();
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
