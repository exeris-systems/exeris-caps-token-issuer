package eu.exeris.caps.tokenissuer;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.DevelopmentKeys;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.caps.tokenissuer.api.SigningKeyRotation;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import eu.exeris.caps.tokenissuer.internal.DefaultAccessTokenIssuer;
import eu.exeris.caps.tokenissuer.internal.DefaultJwksPublisher;
import eu.exeris.caps.tokenissuer.internal.DefaultSigningKeyRotation;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.custody.KeyEncryptionKeyring;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.PostgresSigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;
import eu.exeris.caps.tokenissuer.spi.AuditRecorder;
import eu.exeris.caps.tokenissuer.spi.JwksRouteRegistrar;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.net.URI;
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
 *   <li>{@link JwksPublisher} (JWKS document containing pending, active and retiring public keys)</li>
 *   <li>{@link SigningKeyRotation} (key generations, publication window, retirement, and scheduler integration)</li>
 * </ul>
 *
 * <p>The composition conductor instantiates this class through its no-arg constructor to run the
 * lifecycle hooks, and that instance carries no services: its accessors throw
 * {@link IllegalStateException}. The kernel SPIs this capability needs have no {@code ServiceLoader}
 * lifecycle, so the composing SKU builds the wired instance with
 * {@link #TokenIssuerModule(Map, TransactionalExecutor, JobScheduler, JwksRouteRegistrar, AuditRecorder)}.
 *
 * <p>The wired constructor fails at construction, and so the deployment fails to boot, when:
 * <ul>
 *   <li>the issuer or audience is missing, or another value is malformed
 *       ({@link TokenIssuerConfigurationException});</li>
 *   <li>the key-encryption keyring of {@code EXERIS_TOKEN_ISSUER_KEKS} or
 *       {@code EXERIS_TOKEN_ISSUER_KEKS_FILE} is missing or malformed;</li>
 *   <li>no {@link TransactionalExecutor} is supplied: signing keys are stored in PostgreSQL sealed
 *       under the keyring, and there is no fallback to unsealed in-memory keys;</li>
 *   <li>no {@link JobScheduler} is supplied while {@code EXERIS_TOKEN_ISSUER_MANUAL_ROTATION} is not
 *       {@code true}: without the scheduler nothing publishes, promotes or retires keys, so a
 *       deployment that runs those steps itself says so explicitly.</li>
 * </ul>
 * {@link #inMemoryForDevelopment(DevelopmentKeys, Map, JobScheduler, JwksRouteRegistrar, AuditRecorder)}
 * is the one way to hold keys in process memory, unsealed, and requires an explicit acknowledgement
 * and a development issuer.
 *
 * <p>No constructor or method signature of this class names a type of an optional capability: the
 * audit-trail sink and the service-boundary registry are adapted by
 * {@link eu.exeris.caps.tokenissuer.spi.AuditLogSinkRecorder} and
 * {@link eu.exeris.caps.tokenissuer.spi.ApiSurfaceRegistryRegistrar}, which a composition constructs
 * only when it carries those jars. The {@code @Requires} edges of those two are optional.
 *
 * <p>Every {@code @Requires} edge is declared {@code optional = true}, and the wired constructor is the
 * authority on what boot needs. The capability graph cannot hold a kernel SPI as a mandatory edge,
 * because no {@code @CapabilityModule} provides it, so the {@link TransactionalExecutor} edge is
 * optional in the graph although the constructor refuses to build without one. The {@link JobScheduler}
 * edge is optional in fact: {@code EXERIS_TOKEN_ISSUER_MANUAL_ROTATION=true} lets a deployment run
 * rotation itself, and the constructor then accepts a {@code null} scheduler.
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = AccessTokenIssuer.class, version = "0.1.0")
@Provides(service = JwksPublisher.class, version = "0.1.0")
@Provides(service = SigningKeyRotation.class, version = "0.1.0")
@Requires(service = ApiSurfaceRegistry.class, optional = true)
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = JobScheduler.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[0.1.0,0.2.0)", optional = true)
public final class TokenIssuerModule implements CapabilityLifecycleHooks {

    private static final System.Logger LOG = System.getLogger(TokenIssuerModule.class.getName());

    private final AccessTokenIssuer accessTokenIssuer;
    private final JwksPublisher jwksPublisher;
    private final DefaultSigningKeyRotation signingKeyRotation;
    private final JwksRouteRegistrar jwksRouteRegistrar;
    private final Duration jwksMaxAge;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Lifecycle-only instance for reflective instantiation by the composition conductor. It reads no
     * configuration and holds no key; its service accessors throw {@link IllegalStateException}.
     */
    public TokenIssuerModule() {
        this.accessTokenIssuer = null;
        this.jwksPublisher = null;
        this.signingKeyRotation = null;
        this.jwksRouteRegistrar = null;
        this.jwksMaxAge = null;
    }

    /**
     * Wired instance over PostgreSQL, configuration from {@code System.getenv()}.
     *
     * @throws TokenIssuerConfigurationException when configuration, the keyring or the scheduler is
     *                                           missing or malformed
     */
    public TokenIssuerModule(
            TransactionalExecutor tx,
            JobScheduler scheduler,
            JwksRouteRegistrar jwksRouteRegistrar,
            AuditRecorder auditRecorder
    ) {
        this(System.getenv(), tx, scheduler, jwksRouteRegistrar, auditRecorder);
    }

    /**
     * Wired instance over PostgreSQL with an explicit configuration source.
     *
     * @param environment        environment-style configuration; non-null
     * @param tx                 kernel transactional executor; required
     * @param scheduler          kernel job scheduler; required unless
     *                           {@code EXERIS_TOKEN_ISSUER_MANUAL_ROTATION} is {@code true}
     * @param jwksRouteRegistrar publishes {@code GET /.well-known/jwks.json}; {@code null} when the
     *                           composition serves the JWKS itself
     * @param auditRecorder      security audit receiver; {@code null} when the composition has none
     * @throws TokenIssuerConfigurationException when configuration, the keyring or the scheduler is
     *                                           missing or malformed
     */
    public TokenIssuerModule(
            Map<String, String> environment,
            TransactionalExecutor tx,
            JobScheduler scheduler,
            JwksRouteRegistrar jwksRouteRegistrar,
            AuditRecorder auditRecorder
    ) {
        this(
                TokenIssuerConfig.fromEnvironment(Objects.requireNonNull(environment, "environment must not be null")),
                new PostgresSigningKeyRepository(
                        Objects.requireNonNull(tx, "a TransactionalExecutor is required: signing keys are never held unsealed in memory"),
                        KeyEncryptionKeyring.fromEnvironment(environment)),
                jwksRouteRegistrar,
                scheduler,
                auditRecorder != null ? new TokenIssuerAuditBridge(auditRecorder, Clock.systemUTC()) : null,
                Clock.systemUTC()
        );
    }

    /**
     * Instance that holds its signing keys unsealed in process memory, lost at restart. For
     * development and tests only: it needs no database and no keyring, and offers none of the custody
     * the wired constructor guarantees.
     *
     * <p>Requires an explicit {@link DevelopmentKeys#UNSEALED_ACKNOWLEDGED} acknowledgement and that
     * the configured issuer is a development issuer (a {@code urn:} URI or an
     * {@code http(s)://localhost|127.0.0.1} URL).
     *
     * @param acknowledgement    explicit acknowledgement that development keys are unsealed and
     *                           must never be used in production; non-null
     * @param environment        environment-style configuration; non-null
     * @param scheduler          kernel job scheduler; required unless manual rotation is configured
     * @param jwksRouteRegistrar publishes {@code GET /.well-known/jwks.json}; {@code null} when none
     * @param auditRecorder      security audit receiver; {@code null} when none
     * @throws NullPointerException              when acknowledgement or environment is null
     * @throws IllegalStateException             when the configured issuer is not a development issuer
     * @throws TokenIssuerConfigurationException when configuration or the scheduler is missing or malformed
     */
    public static TokenIssuerModule inMemoryForDevelopment(
            DevelopmentKeys acknowledgement,
            Map<String, String> environment,
            JobScheduler scheduler,
            JwksRouteRegistrar jwksRouteRegistrar,
            AuditRecorder auditRecorder
    ) {
        Objects.requireNonNull(acknowledgement, "acknowledgement must not be null");
        TokenIssuerConfig config = TokenIssuerConfig.fromEnvironment(
                Objects.requireNonNull(environment, "environment must not be null"));
        if (!isDevelopmentIssuer(config.issuer())) {
            throw new IllegalStateException("development signing keys are only permitted with a development issuer "
                    + "(urn:... or http(s)://localhost|127.0.0.1): " + config.issuer());
        }
        LOG.log(System.Logger.Level.WARNING,
                "token issuer signing keys are held unsealed in process memory: development use only");
        return new TokenIssuerModule(
                config,
                new InMemorySigningKeyRepository(),
                jwksRouteRegistrar,
                scheduler,
                auditRecorder != null ? new TokenIssuerAuditBridge(auditRecorder, Clock.systemUTC()) : null,
                Clock.systemUTC()
        );
    }

    private static boolean isDevelopmentIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return false;
        }
        try {
            URI uri = URI.create(issuer);
            String scheme = uri.getScheme();
            if (scheme == null) {
                return false;
            }
            if ("urn".equalsIgnoreCase(scheme)) {
                String ssp = uri.getSchemeSpecificPart();
                return ssp != null && !ssp.isBlank();
            }
            if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                String host = uri.getHost();
                return host != null && (host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1"));
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    TokenIssuerModule(
            TokenIssuerConfig config,
            SigningKeyRepository repository,
            JwksRouteRegistrar jwksRouteRegistrar,
            JobScheduler jobScheduler,
            TokenIssuerAuditBridge auditBridge,
            Clock clock
    ) {
        Objects.requireNonNull(config, "config must not be null");
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(clock, "clock must not be null");
        if (jobScheduler == null && !config.manualRotation()) {
            throw new TokenIssuerConfigurationException(TokenIssuerConfig.ENV_MANUAL_ROTATION,
                    "a JobScheduler is required to publish, promote and retire signing keys; set this to true "
                            + "only if the deployment calls rotateIfDue() and retireExpiredKeys() itself");
        }

        this.jwksRouteRegistrar = jwksRouteRegistrar;
        this.jwksMaxAge = config.jwksMaxAge();
        DefaultSigningKeyRotation rotation = new DefaultSigningKeyRotation(repository, config, auditBridge, jobScheduler, clock);
        this.signingKeyRotation = rotation;
        this.jwksPublisher = new DefaultJwksPublisher(repository, clock);
        this.accessTokenIssuer = new DefaultAccessTokenIssuer(repository, config, rotation, auditBridge, clock);
    }

    public AccessTokenIssuer accessTokenIssuer() {
        return requireWired(accessTokenIssuer);
    }

    public JwksPublisher jwksPublisher() {
        return requireWired(jwksPublisher);
    }

    public SigningKeyRotation signingKeyRotation() {
        return requireWired(signingKeyRotation);
    }

    /**
     * Withdraws a named signing key immediately, whatever its current lifecycle state.
     *
     * @param kid identifier of the key to withdraw; non-null
     * @throws IllegalStateException on a lifecycle-only instance
     * @throws IllegalArgumentException if no key with the given identifier exists
     */
    public void withdrawKey(String kid) {
        requireWired(signingKeyRotation).withdrawKey(kid);
    }

    /**
     * Re-seals every stored signing key record under the currently active key-encryption key (KEK).
     *
     * <p>Used during KEK rotation: after prepending a new KEK to the configured keyring,
     * calling this operation re-encrypts all stored private keys under the new active KEK.
     * Once all keys are re-sealed under the active KEK, the superseded KEK can be removed
     * from configuration.
     *
     * @return number of keys re-sealed under the active KEK
     * @throws IllegalStateException on a lifecycle-only instance
     */
    public int resealWithActiveKek() {
        return requireWired(signingKeyRotation).resealWithActiveKek();
    }

    private static <T> T requireWired(T service) {
        if (service == null) {
            throw new IllegalStateException("lifecycle-only instance: build the module with its wiring constructor to obtain services");
        }
        return service;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        if (signingKeyRotation != null) {
            // 1. Ensure an unexpired active signing key exists. After a long outage the successor may
            // still be maturing; the pending key is already published and issuance fails closed.
            try {
                signingKeyRotation.ensureActiveKey();
            } catch (NoActiveKeyException e) {
                LOG.log(System.Logger.Level.WARNING, e.getMessage());
            }

            // 2. Register HTTP route GET /.well-known/jwks.json if a registrar is wired
            if (jwksRouteRegistrar != null) {
                jwksRouteRegistrar.registerJwksRoute(jwksPublisher::getJwksJson, jwksMaxAge);
            }

            // 3. Start the background key lifecycle job if a scheduler is wired
            signingKeyRotation.startScheduledRotation();
        }
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
        if (signingKeyRotation != null) {
            signingKeyRotation.stopScheduledRotation();
        }
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
        if (signingKeyRotation != null) {
            signingKeyRotation.stopScheduledRotation();
        }
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
