package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.internal.crypto.Ed25519Signer;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultAccessTokenIssuerTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00.750Z");

    private InMemorySigningKeyRepository repository;
    private TokenIssuerConfig config;
    private MutableClock clock;
    private DefaultSigningKeyRotation rotation;
    private DefaultAccessTokenIssuer issuer;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        config = TestSupport.config();
        clock = new MutableClock(T0);
        rotation = new DefaultSigningKeyRotation(repository, config, null, null, clock);
        issuer = new DefaultAccessTokenIssuer(repository, config, rotation, null, clock);
    }

    private static Map<String, Object> decode(String part) throws Exception {
        return JsonUtil.parseJson(new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("the claim set is exactly iss, sub, aud, iat, nbf, exp, jti, tid, sid, roles plus custom claims")
    void claimSet() throws Exception {
        UUID subjectId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        IssuedAccessToken token = issuer.issueAccessToken(TokenIssueRequest.builder()
                .subjectId(subjectId)
                .sessionId(sessionId)
                .tenantId("tenant-7")
                .roles(Set.of("ADMIN", "BILLING"))
                .customClaims(Map.of("plan", "pro"))
                .ttl(Duration.ofMinutes(5))
                .build());

        String[] parts = token.token().split("\\.");
        Map<String, Object> header = decode(parts[0]);
        Map<String, Object> claims = decode(parts[1]);
        long iat = Instant.parse("2026-01-01T00:00:00Z").getEpochSecond();

        assertThat(header).containsOnlyKeys("alg", "typ", "kid")
                .containsEntry("alg", "EdDSA")
                .containsEntry("typ", "JWT")
                .containsEntry("kid", repository.findActive().orElseThrow().kid());
        assertThat(claims).containsOnlyKeys("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "tid", "sid", "roles", "plan");
        assertThat(claims)
                .containsEntry("iss", TestSupport.ISSUER)
                .containsEntry("aud", TestSupport.AUDIENCE)
                .containsEntry("sub", subjectId.toString())
                .containsEntry("sid", sessionId.toString())
                .containsEntry("tid", "tenant-7")
                .containsEntry("iat", iat)
                .containsEntry("nbf", iat)
                .containsEntry("exp", iat + 300)
                .containsEntry("roles", List.of("ADMIN", "BILLING"))
                .containsEntry("plan", "pro");
        assertThat(UUID.fromString((String) claims.get("jti"))).isNotNull();
        assertThat(token.expiresAt()).isEqualTo(Instant.ofEpochSecond(iat + 300));

        SigningKeyRecord active = repository.findActive().orElseThrow();
        PublicKey publicKey = Ed25519Signer.reconstructPublicKey(active.publicKeyRawBytes());
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        assertThat(Ed25519Signer.verify((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII), sig, publicKey)).isTrue();
    }

    @Test
    @DisplayName("optional claims are omitted, the default lifetime applies, and every jti is fresh")
    void minimalTokenAndDefaults() throws Exception {
        UUID subjectId = UUID.randomUUID();
        IssuedAccessToken first = issuer.issueAccessToken(TokenIssueRequest.builder().subjectId(subjectId).build());
        IssuedAccessToken second = issuer.issueAccessToken(TokenIssueRequest.builder().subjectId(subjectId).build());

        Map<String, Object> claims = decode(first.token().split("\\.")[1]);
        assertThat(claims).containsOnlyKeys("iss", "sub", "aud", "iat", "nbf", "exp", "jti");
        assertThat((Long) claims.get("exp") - (Long) claims.get("iat")).isEqualTo(config.defaultTokenTtl().toSeconds());
        assertThat(claims.get("jti")).isNotEqualTo(decode(second.token().split("\\.")[1]).get("jti"));
    }

    @Test
    @DisplayName("a lifetime above the configured maximum is refused")
    void maxLifetimeBounded() {
        assertThatThrownBy(() -> issuer.issueAccessToken(TokenIssueRequest.builder()
                .subjectId(UUID.randomUUID())
                .ttl(config.maxTokenTtl().plusSeconds(1))
                .build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds");
        assertThat(issuer.issueAccessToken(TokenIssueRequest.builder()
                .subjectId(UUID.randomUUID()).ttl(config.maxTokenTtl()).build())).isNotNull();
    }

    @Test
    @DisplayName("a key past its expiresAt never signs: issuance rotates first")
    void expiredKeyDoesNotSign() throws Exception {
        String firstKid = rotation.ensureActiveKey().kid();
        clock.advance(config.keyTtl().plusSeconds(1));

        IssuedAccessToken token = issuer.issueAccessToken(UUID.randomUUID(), null);
        String kid = (String) decode(token.token().split("\\.")[0]).get("kid");
        assertThat(kid).isNotEqualTo(firstKid);
    }
}
