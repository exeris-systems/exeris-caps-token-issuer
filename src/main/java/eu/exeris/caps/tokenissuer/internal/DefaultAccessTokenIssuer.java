package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.crypto.Ed25519Signer;
import eu.exeris.caps.tokenissuer.internal.crypto.JwtTokenBuilder;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;

import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link AccessTokenIssuer}.
 *
 * <p>Every token carries {@code iss} and {@code aud} from {@link TokenIssuerConfig}, {@code sub},
 * {@code iat = nbf = now}, {@code exp = now + ttl} and a fresh {@code jti}; {@code tid},
 * {@code sid} and {@code roles} when the request carries them. {@code ttl} never exceeds
 * {@link TokenIssuerConfig#maxTokenTtl()}, which is what bounds how long a retired key must stay
 * published. {@code iat} is the injected {@link Clock} truncated to whole seconds and {@code ttl} is a whole
 * number of seconds, so the returned {@code expiresAt} equals the {@code exp} claim and
 * {@code exp > iat}.
 *
 * @since 0.1.0
 */
public final class DefaultAccessTokenIssuer implements AccessTokenIssuer {

    private final SigningKeyRepository repository;
    private final TokenIssuerConfig config;
    private final DefaultSigningKeyRotation rotation;
    private final TokenIssuerAuditBridge auditBridge;
    private final Clock clock;

    public DefaultAccessTokenIssuer(
            SigningKeyRepository repository,
            TokenIssuerConfig config,
            DefaultSigningKeyRotation rotation,
            TokenIssuerAuditBridge auditBridge,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.rotation = Objects.requireNonNull(rotation, "rotation must not be null");
        this.auditBridge = auditBridge;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId) {
        return issueAccessToken(TokenIssueRequest.builder()
                .subjectId(subjectId)
                .sessionId(sessionId)
                .build());
    }

    @Override
    public IssuedAccessToken issueAccessToken(TokenIssueRequest request) {
        Objects.requireNonNull(request, "request must not be null");

        Duration ttl = request.ttl() != null ? request.ttl() : config.defaultTokenTtl();
        if (ttl.compareTo(config.maxTokenTtl()) > 0) {
            throw new IllegalArgumentException("ttl " + ttl + " exceeds the configured maximum " + config.maxTokenTtl());
        }

        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        SigningKeyRecord active = activeKeyAt(now);

        PrivateKey privateKey = Ed25519Signer.reconstructPrivateKey(active.privateKeyPkcs8Bytes());
        Instant exp = now.plus(ttl);
        String jti = UUID.randomUUID().toString();

        IssuedAccessToken issued = JwtTokenBuilder.create(active.kid(), privateKey)
                .issuer(config.issuer())
                .subject(request.subjectId())
                .audience(config.audience())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(exp)
                .jwtId(jti)
                .tenant(request.tenantId())
                .session(request.sessionId())
                .roles(request.roles())
                .customClaims(request.customClaims())
                .sign();

        if (auditBridge != null) {
            auditBridge.logTokenIssued(request.subjectId(), request.sessionId(), jti, active.kid());
        }
        return issued;
    }

    /**
     * The key that signs at {@code now}. A key past its {@code expiresAt} never signs: if no
     * scheduled rotation has replaced it yet, issuance rotates first.
     */
    private SigningKeyRecord activeKeyAt(Instant now) {
        Optional<SigningKeyRecord> active = repository.findActive();
        if (active.isPresent() && now.isBefore(active.get().expiresAt())) {
            return active.get();
        }
        rotation.rotateIfDue();
        return repository.findActive()
                .filter(record -> now.isBefore(record.expiresAt()))
                .orElseThrow(() -> new NoActiveKeyException("Failed to acquire an unexpired active signing key"));
    }
}
