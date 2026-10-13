package eu.exeris.caps.tokenissuer;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.api.SigningKeyRotation;
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

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-token-issuer}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link AccessTokenIssuer} (short-lived JWT access tokens signed with EdDSA over Ed25519)</li>
 *   <li>{@link JwksPublisher} (JWKS document containing active and retiring public keys)</li>
 *   <li>{@link SigningKeyRotation} (key generations, overlap window, retirement, and scheduler integration)</li>
 * </ul>
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = AccessTokenIssuer.class, version = "1.0.0")
@Provides(service = JwksPublisher.class, version = "1.0.0")
@Provides(service = SigningKeyRotation.class, version = "1.0.0")
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
     * Public no-arg constructor for reflective instantiation by the composition conductor.
     */
    public TokenIssuerModule() {
        this(new InMemorySigningKeyRepository(), KeyRotationPolicy.defaults(), null, null, null);
    }

    /**
     * Constructor wiring with kernel and capability SPIs. With a {@link TransactionalExecutor} the
     * signing keys are stored in PostgreSQL, sealed under the key-encryption keyring of
     * {@code EXERIS_TOKEN_ISSUER_KEKS} or {@code EXERIS_TOKEN_ISSUER_KEKS_FILE}; a missing or
     * malformed keyring fails construction with a
     * {@link eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException}.
     */
    public TokenIssuerModule(
            TransactionalExecutor tx,
            JobScheduler scheduler,
            ApiSurfaceRegistry apiSurfaceRegistry,
            AuditLogSink auditLogSink
    ) {
        this(
                tx != null
                        ? new PostgresSigningKeyRepository(tx, KeyEncryptionKeyring.fromEnvironment(System.getenv()))
                        : new InMemorySigningKeyRepository(),
                KeyRotationPolicy.defaults(),
                apiSurfaceRegistry,
                scheduler,
                auditLogSink != null ? new TokenIssuerAuditBridge(auditLogSink) : null
        );
    }

    /**
     * Full constructor with explicit repository and policy.
     */
    public TokenIssuerModule(
            SigningKeyRepository repository,
            KeyRotationPolicy policy,
            ApiSurfaceRegistry apiSurfaceRegistry,
            JobScheduler jobScheduler,
            TokenIssuerAuditBridge auditBridge
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        this.apiSurfaceRegistry = apiSurfaceRegistry;
        this.signingKeyRotation = new DefaultSigningKeyRotation(repository, policy, auditBridge, jobScheduler);
        this.jwksPublisher = new DefaultJwksPublisher(repository, policy);
        this.accessTokenIssuer = new DefaultAccessTokenIssuer(repository, policy, this.signingKeyRotation, auditBridge);
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
        ready.set(true);
        // 1. Ensure at least one active signing key exists
        signingKeyRotation.ensureActiveKey();

        // 2. Register HTTP route GET /.well-known/jwks.json if service-boundary-core is present
        if (apiSurfaceRegistry != null) {
            jwksPublisher.registerBoundaryRoute(apiSurfaceRegistry);
        }

        // 3. Start automated background key rotation if scheduler is present
        signingKeyRotation.startScheduledRotation();
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
