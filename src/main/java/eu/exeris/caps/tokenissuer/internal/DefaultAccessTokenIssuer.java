package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.crypto.Ed25519Signer;
import eu.exeris.caps.tokenissuer.internal.crypto.JwtTokenBuilder;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Default implementation of {@link AccessTokenIssuer}.
 *
 * @since 0.1.0
 */
public final class DefaultAccessTokenIssuer implements AccessTokenIssuer {

    private final SigningKeyRepository repository;
    private final KeyRotationPolicy policy;
    private final DefaultSigningKeyRotation rotation;
    private final TokenIssuerAuditBridge auditBridge;

    public DefaultAccessTokenIssuer(
            SigningKeyRepository repository,
            KeyRotationPolicy policy,
            DefaultSigningKeyRotation rotation,
            TokenIssuerAuditBridge auditBridge
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.rotation = Objects.requireNonNull(rotation, "rotation must not be null");
        this.auditBridge = auditBridge;
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

        // 1. Resolve or generate active key
        SigningKeyRecord active = repository.findActive().orElseGet(() -> {
            rotation.ensureActiveKey();
            return repository.findActive()
                    .orElseThrow(() -> new NoActiveKeyException("Failed to acquire active signing key"));
        });

        // 2. Prepare signing key and token attributes
        PrivateKey privateKey = Ed25519Signer.reconstructPrivateKey(active.privateKeyPkcs8Bytes());
        Instant now = Instant.now();
        Duration ttl = request.ttl() != null ? request.ttl() : policy.defaultTokenTtl();
        Instant exp = now.plus(ttl);
        String issuer = request.issuer() != null ? request.issuer() : policy.defaultIssuer();
        String audience = request.audience() != null ? request.audience() : policy.defaultAudience();
        String jti = UUID.randomUUID().toString();

        // 3. Build and sign JWT
        JwtTokenBuilder builder = JwtTokenBuilder.create(active.kid(), privateKey)
                .subject(request.subjectId())
                .session(request.sessionId())
                .issuer(issuer)
                .audience(audience)
                .issuedAt(now)
                .expiresAt(exp)
                .jwtId(jti)
                .roles(request.roles())
                .customClaims(request.customClaims());

        IssuedAccessToken issued = builder.sign();

        // 4. Audit logging
        if (auditBridge != null) {
            auditBridge.logTokenIssued(request.subjectId(), request.sessionId(), jti, active.kid());
        }

        return issued;
    }
}
