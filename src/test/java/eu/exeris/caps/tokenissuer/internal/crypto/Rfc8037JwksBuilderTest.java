package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.JwksDocument;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class Rfc8037JwksBuilderTest {

    @Test
    @DisplayName("Builds RFC 8037 OKP JWK params for Ed25519 public key")
    void buildsRfc8037JwkParams() {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
        String kid = "k-2026-1";

        Map<String, String> jwk = Rfc8037JwksBuilder.buildJwkParams(kid, rawPub);

        assertThat(jwk.get("kty")).isEqualTo("OKP");
        assertThat(jwk.get("crv")).isEqualTo("Ed25519");
        assertThat(jwk.get("alg")).isEqualTo("EdDSA");
        assertThat(jwk.get("use")).isEqualTo("sig");
        assertThat(jwk.get("kid")).isEqualTo("k-2026-1");
        assertThat(jwk.get("x")).isNotEmpty();
    }

    @Test
    @DisplayName("Builds and serializes RFC 7517 compliant JWKS document")
    void buildsAndSerializesJwksDocument() {
        KeyPair key1 = Ed25519Signer.generateKeyPair();
        KeyPair key2 = Ed25519Signer.generateKeyPair();

        Map<String, String> jwk1 = Rfc8037JwksBuilder.buildJwkParams("k-1", Ed25519Signer.extractRawPublicKeyBytes(key1.getPublic()));
        Map<String, String> jwk2 = Rfc8037JwksBuilder.buildJwkParams("k-2", Ed25519Signer.extractRawPublicKeyBytes(key2.getPublic()));

        JwksDocument doc = Rfc8037JwksBuilder.buildJwksDocument(List.of(jwk1, jwk2));

        assertThat(doc.keys()).hasSize(2);
        assertThat(doc.rawJson()).contains("\"keys\":[");
        assertThat(doc.rawJson()).contains("\"kid\":\"k-1\"");
        assertThat(doc.rawJson()).contains("\"kid\":\"k-2\"");
        assertThat(doc.rawJson()).contains("\"crv\":\"Ed25519\"");
        assertThat(doc.rawJson()).contains("\"kty\":\"OKP\"");
    }
}
