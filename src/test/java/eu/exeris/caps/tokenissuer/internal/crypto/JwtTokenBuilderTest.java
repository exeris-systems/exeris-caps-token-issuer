package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenBuilderTest {

    @Test
    @DisplayName("Builds, signs, and verifies compact JWT token")
    void buildsAndSignsCompactJwt() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        String kid = "k-test-1";
        UUID subjectId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofMinutes(15));

        IssuedAccessToken issued = JwtTokenBuilder.create(kid, keyPair.getPrivate())
                .subject(subjectId)
                .session(sessionId)
                .issuer("https://auth.exeris.eu")
                .audience("https://api.exeris.eu")
                .issuedAt(now)
                .expiresAt(exp)
                .roles(Set.of("ADMIN", "OPERATOR"))
                .customClaims(Map.of("tenantId", "tenant-100", "verified", true))
                .sign();

        assertThat(issued).isNotNull();
        assertThat(issued.tokenType()).isEqualTo("Bearer");
        assertThat(issued.expiresAt()).isEqualTo(exp);

        String[] parts = issued.token().split("\\.");
        assertThat(parts).hasSize(3);

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);

        assertThat(headerJson).contains("\"alg\":\"EdDSA\"");
        assertThat(headerJson).contains("\"typ\":\"JWT\"");
        assertThat(headerJson).contains("\"kid\":\"k-test-1\"");

        assertThat(payloadJson).contains("\"sub\":\"" + subjectId + "\"");
        assertThat(payloadJson).contains("\"sid\":\"" + sessionId + "\"");
        assertThat(payloadJson).contains("\"iss\":\"https://auth.exeris.eu\"");
        assertThat(payloadJson).contains("\"aud\":\"https://api.exeris.eu\"");
        assertThat(payloadJson).contains("\"tenantId\":\"tenant-100\"");
        assertThat(payloadJson).contains("\"verified\":true");

        // Verify digital signature against header.payload
        String signingInput = parts[0] + "." + parts[1];
        boolean valid = Ed25519Signer.verify(
                signingInput.getBytes(StandardCharsets.US_ASCII),
                signature,
                keyPair.getPublic()
        );
        assertThat(valid).isTrue();
    }
}
