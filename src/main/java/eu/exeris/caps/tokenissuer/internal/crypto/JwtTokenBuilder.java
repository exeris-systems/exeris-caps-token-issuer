package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Builds and signs compact JWT access tokens using Ed25519 (EdDSA).
 *
 * <p>Produces tokens conforming to RFC 7519, RFC 7515, and RFC 8037 with zero third-party libraries.
 *
 * @since 0.1.0
 */
public final class JwtTokenBuilder {

    private final String kid;
    private final PrivateKey privateKey;
    private final Map<String, Object> claims = new LinkedHashMap<>();
    private Instant expiresAt;

    private JwtTokenBuilder(String kid, PrivateKey privateKey) {
        this.kid = Objects.requireNonNull(kid, "kid must not be null");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    }

    public static JwtTokenBuilder create(String kid, PrivateKey privateKey) {
        return new JwtTokenBuilder(kid, privateKey);
    }

    public JwtTokenBuilder subject(UUID subjectId) {
        if (subjectId != null) {
            claims.put("sub", subjectId.toString());
        }
        return this;
    }

    public JwtTokenBuilder session(UUID sessionId) {
        if (sessionId != null) {
            claims.put("sid", sessionId.toString());
        }
        return this;
    }

    public JwtTokenBuilder issuer(String issuer) {
        if (issuer != null && !issuer.isBlank()) {
            claims.put("iss", issuer);
        }
        return this;
    }

    public JwtTokenBuilder audience(String audience) {
        if (audience != null && !audience.isBlank()) {
            claims.put("aud", audience);
        }
        return this;
    }

    public JwtTokenBuilder issuedAt(Instant iat) {
        if (iat != null) {
            claims.put("iat", iat.getEpochSecond());
        }
        return this;
    }

    public JwtTokenBuilder expiresAt(Instant exp) {
        if (exp != null) {
            this.expiresAt = exp;
            claims.put("exp", exp.getEpochSecond());
        }
        return this;
    }

    public JwtTokenBuilder jwtId(String jti) {
        if (jti != null && !jti.isBlank()) {
            claims.put("jti", jti);
        }
        return this;
    }

    public JwtTokenBuilder roles(Set<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            claims.put("roles", roles);
        }
        return this;
    }

    public JwtTokenBuilder customClaims(Map<String, Object> custom) {
        if (custom != null && !custom.isEmpty()) {
            claims.putAll(custom);
        }
        return this;
    }

    public IssuedAccessToken sign() {
        if (expiresAt == null) {
            throw new IllegalStateException("expiresAt must be specified before signing");
        }
        if (!claims.containsKey("jti")) {
            claims.put("jti", UUID.randomUUID().toString());
        }
        if (!claims.containsKey("iat")) {
            claims.put("iat", Instant.now().getEpochSecond());
        }

        // 1. Header
        String headerJson = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"" + escapeJson(kid) + "\"}";
        String b64Header = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));

        // 2. Payload
        String payloadJson = serializeClaimsJson(claims);
        String b64Payload = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));

        // 3. Signing input
        String signingInput = b64Header + "." + b64Payload;
        byte[] signatureBytes = Ed25519Signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII), privateKey);
        String b64Signature = base64Url(signatureBytes);

        String compactJwt = signingInput + "." + b64Signature;
        return new IssuedAccessToken(compactJwt, expiresAt, "Bearer");
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String serializeClaimsJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
            sb.append(toJsonValue(entry.getValue()));
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static String toJsonValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof String s) {
            return "\"" + escapeJson(s) + "\"";
        }
        if (value instanceof Collection<?> coll) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : coll) {
                if (!first) sb.append(",");
                sb.append(toJsonValue(item));
                first = false;
            }
            sb.append("]");
            return sb.toString();
        }
        if (value instanceof Map<?, ?> m) {
            return serializeClaimsJson((Map<String, Object>) m);
        }
        return "\"" + escapeJson(value.toString()) + "\"";
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
