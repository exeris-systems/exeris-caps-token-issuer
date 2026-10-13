package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies issued tokens with jose4j, holding nothing but the published JWKS document, the
 * expected issuer and audience, and an EdDSA-only algorithm constraint.
 */
class StandardLibraryInteropTest {

    private TokenIssuerConfig config;
    private MutableClock clock;
    private DefaultSigningKeyRotation rotation;
    private DefaultJwksPublisher jwks;
    private DefaultAccessTokenIssuer issuer;

    @BeforeEach
    void setUp() {
        InMemorySigningKeyRepository repository = new InMemorySigningKeyRepository();
        config = TestSupport.config();
        clock = new MutableClock(Instant.parse("2026-03-01T12:00:00Z"));
        rotation = new DefaultSigningKeyRotation(repository, config, null, null, clock);
        jwks = new DefaultJwksPublisher(repository, clock);
        issuer = new DefaultAccessTokenIssuer(repository, config, rotation, null, clock);
        rotation.ensureActiveKey();
    }

    private JwtConsumer consumer(String jwksJson) throws Exception {
        return new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(jwksJson).getJsonWebKeys()))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.EDDSA)
                .setExpectedIssuer(TestSupport.ISSUER)
                .setExpectedAudience(TestSupport.AUDIENCE)
                .setRequireSubject()
                .setRequireJwtId()
                .setRequireIssuedAt()
                .setRequireNotBefore()
                .setRequireExpirationTime()
                .setMaxFutureValidityInMinutes((int) config.maxTokenTtl().toMinutes())
                .setAllowedClockSkewInSeconds((int) config.clockSkew().toSeconds())
                .setEvaluationTime(NumericDate.fromMilliseconds(clock.millis()))
                .build();
    }

    @Test
    @DisplayName("a token verifies with jose4j using only the JWKS, and its claims read back")
    void verifiesWithJwksOnly() throws Exception {
        UUID subjectId = UUID.randomUUID();
        IssuedAccessToken token = issuer.issueAccessToken(TokenIssueRequest.builder()
                .subjectId(subjectId).tenantId("tenant-42").build());

        JwtClaims claims = consumer(jwks.getJwksJson()).processToClaims(token.token());
        assertThat(claims.getSubject()).isEqualTo(subjectId.toString());
        assertThat(claims.getStringClaimValue(TokenIssueRequest.TENANT_CLAIM)).isEqualTo("tenant-42");
        assertThat(claims.getAudience()).containsExactly(TestSupport.AUDIENCE);
    }

    @Test
    @DisplayName("a token signed before a rotation verifies through the overlap and not after the key leaves the JWKS")
    void verifiesAcrossRotationThenNotAfterRemoval() throws Exception {
        IssuedAccessToken beforeRotation = issuer.issueAccessToken(TokenIssueRequest.builder()
                .subjectId(UUID.randomUUID()).ttl(config.maxTokenTtl()).build());

        rotation.rotateKeys();
        IssuedAccessToken afterRotation = issuer.issueAccessToken(UUID.randomUUID(), null);

        String jwksDuringOverlap = jwks.getJwksJson();
        assertThat(consumer(jwksDuringOverlap).processToClaims(beforeRotation.token())).isNotNull();
        assertThat(consumer(jwksDuringOverlap).processToClaims(afterRotation.token())).isNotNull();

        clock.advance(config.publicationOverlap());
        String jwksAfterWindow = jwks.getJwksJson();
        assertThat(new JsonWebKeySet(jwksAfterWindow).getJsonWebKeys()).hasSize(1);
        assertThatThrownBy(() -> consumer(jwksAfterWindow).processToClaims(beforeRotation.token()))
                .isInstanceOf(InvalidJwtException.class);
    }

    @Test
    @DisplayName("a verifier pinned to a different issuer or audience rejects the token")
    void wrongIssuerOrAudienceRejected() throws Exception {
        IssuedAccessToken token = issuer.issueAccessToken(UUID.randomUUID(), null);
        JwtConsumer otherAudience = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(jwks.getJwksJson()).getJsonWebKeys()))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.EDDSA)
                .setExpectedIssuer(TestSupport.ISSUER)
                .setExpectedAudience("https://other.test.invalid")
                .setEvaluationTime(NumericDate.fromMilliseconds(clock.millis()))
                .build();
        assertThatThrownBy(() -> otherAudience.processToClaims(token.token())).isInstanceOf(InvalidJwtException.class);
    }
}
