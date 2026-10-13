package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenBuilderTest {

    private static JwtTokenBuilder complete(KeyPair keyPair, Instant now) {
        return JwtTokenBuilder.create("k-test-1", keyPair.getPrivate())
                .issuer("https://issuer.test.invalid")
                .subject(UUID.randomUUID())
                .audience("https://audience.test.invalid")
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(Duration.ofMinutes(15)))
                .jwtId(UUID.randomUUID().toString());
    }

    @Test
    @DisplayName("signs a verifiable compact JWT with the EdDSA header")
    void buildsAndSignsCompactJwt() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        Instant now = Instant.ofEpochSecond(1_800_000_000L);

        IssuedAccessToken issued = complete(keyPair, now).customClaims(Map.of("verified", true)).sign();

        String[] parts = issued.token().split("\\.");
        assertThat(parts).hasSize(3);
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson).isEqualTo("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"k-test-1\"}");
        assertThat(Ed25519Signer.verify((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII),
                Base64.getUrlDecoder().decode(parts[2]), keyPair.getPublic())).isTrue();
    }

    @Test
    @DisplayName("refuses to sign without every registered claim, and custom claims cannot replace one")
    void requiredAndReservedClaims() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        assertThatThrownBy(() -> JwtTokenBuilder.create("k", keyPair.getPrivate())
                .issuer("i").subject(UUID.randomUUID()).audience("a").issuedAt(now).expiresAt(now).jwtId("j").sign())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("nbf");
        assertThatThrownBy(() -> complete(keyPair, now).customClaims(Map.of("exp", 0)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("control characters in claim values are escaped into valid JSON")
    void escapesControlCharacters() throws Exception {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        IssuedAccessToken issued = complete(keyPair, Instant.ofEpochSecond(1_800_000_000L))
                .customClaims(Map.of("note", "a\u0001b\"c\\d "))
                .sign();
        String payload = new String(Base64.getUrlDecoder().decode(issued.token().split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(JsonUtil.parseJson(payload)).containsEntry("note", "a\u0001b\"c\\d ");
    }
}
