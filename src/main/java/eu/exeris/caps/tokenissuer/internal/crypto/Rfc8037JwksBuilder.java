package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.JwksDocument;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Serializes Ed25519 public keys to RFC 8037 and RFC 7517 compliant JWK / JWKS structures.
 *
 * @since 0.1.0
 */
public final class Rfc8037JwksBuilder {

    private Rfc8037JwksBuilder() {}

    /**
     * Constructs a single JWK map representing an Ed25519 public key.
     *
     * @param kid            key identifier; non-null
     * @param rawPublicKey32 32-byte raw public key; non-null
     * @return map of JWK parameters
     */
    public static Map<String, String> buildJwkParams(String kid, byte[] rawPublicKey32) {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(rawPublicKey32, "rawPublicKey32 must not be null");
        if (rawPublicKey32.length != 32) {
            throw new IllegalArgumentException("Ed25519 raw public key must be 32 bytes, got " + rawPublicKey32.length);
        }

        String xCoord = Base64.getUrlEncoder().withoutPadding().encodeToString(rawPublicKey32);

        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("alg", "EdDSA");
        jwk.put("use", "sig");
        jwk.put("kid", kid);
        jwk.put("x", xCoord);
        return jwk;
    }

    /**
     * Serializes a single JWK map to JSON string.
     *
     * @param jwkParams map of JWK parameters; non-null
     * @return JSON string
     */
    public static String serializeJwk(Map<String, String> jwkParams) {
        Objects.requireNonNull(jwkParams, "jwkParams must not be null");
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : jwkParams.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":\"")
              .append(escapeJson(entry.getValue())).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Serializes a collection of JWK maps into an RFC 7517 JWKS document descriptor.
     *
     * @param keyList list of JWK parameter maps; non-null
     * @return JwksDocument containing key maps and serialized JSON
     */
    public static JwksDocument buildJwksDocument(List<Map<String, String>> keyList) {
        Objects.requireNonNull(keyList, "keyList must not be null");
        List<Map<String, String>> defensiveList = new ArrayList<>(keyList.size());
        for (Map<String, String> k : keyList) {
            defensiveList.add(Map.copyOf(k));
        }

        StringBuilder sb = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < defensiveList.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(serializeJwk(defensiveList.get(i)));
        }
        sb.append("]}");

        return new JwksDocument(defensiveList, sb.toString());
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
