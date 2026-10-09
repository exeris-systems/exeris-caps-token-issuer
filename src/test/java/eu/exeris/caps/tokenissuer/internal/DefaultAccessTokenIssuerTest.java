package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.caps.tokenissuer.internal.crypto.Ed25519Signer;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultAccessTokenIssuerTest {

    private InMemorySigningKeyRepository repository;
    private KeyRotationPolicy policy;
    private DefaultSigningKeyRotation rotation;
    private DefaultAccessTokenIssuer issuer;

    @BeforeEach
    void setUp() {
        repository = new InMemorySigningKeyRepository();
        policy = KeyRotationPolicy.defaults();
        rotation = new DefaultSigningKeyRotation(repository, policy, null);
        issuer = new DefaultAccessTokenIssuer(repository, policy, rotation, null);
    }

    @Test
    @DisplayName("Issues token with subjectId and sessionId (session-management compatibility)")
    void issuesTokenWithSubjectAndSession() {
        UUID subjectId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        IssuedAccessToken token = issuer.issueAccessToken(subjectId, sessionId);

        assertThat(token).isNotNull();
        assertThat(token.tokenType()).isEqualTo("Bearer");
        assertThat(token.expiresAt()).isNotNull();

        String[] parts = token.token().split("\\.");
        assertThat(parts).hasSize(3);

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payload).contains("\"sub\":\"" + subjectId + "\"");
        assertThat(payload).contains("\"sid\":\"" + sessionId + "\"");

        SigningKeyRecord active = repository.findActive().orElseThrow();
        PublicKey publicKey = Ed25519Signer.reconstructPublicKey(active.publicKeyRawBytes());
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        String signingInput = parts[0] + "." + parts[1];

        assertThat(Ed25519Signer.verify(signingInput.getBytes(StandardCharsets.US_ASCII), sig, publicKey)).isTrue();
    }

    @Test
    @DisplayName("Issues token with rich TokenIssueRequest")
    void issuesTokenWithRichRequest() {
        UUID subjectId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        TokenIssueRequest req = TokenIssueRequest.builder()
                .subjectId(subjectId)
                .sessionId(sessionId)
                .issuer("https://custom-issuer.exeris.eu")
                .audience("https://custom-api.exeris.eu")
                .roles(Set.of("ADMIN", "BILLING_MANAGER"))
                .customClaims(Map.of("tenant_id", "t-12345"))
                .ttl(Duration.ofMinutes(5))
                .build();

        IssuedAccessToken token = issuer.issueAccessToken(req);

        assertThat(token).isNotNull();
        String[] parts = token.token().split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        assertThat(payload).contains("\"iss\":\"https://custom-issuer.exeris.eu\"");
        assertThat(payload).contains("\"aud\":\"https://custom-api.exeris.eu\"");
        assertThat(payload).contains("\"tenant_id\":\"t-12345\"");
        assertThat(payload).contains("\"roles\":");
        assertThat(payload).contains("\"ADMIN\"");
        assertThat(payload).contains("\"BILLING_MANAGER\"");
    }
}
