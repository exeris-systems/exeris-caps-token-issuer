package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Builds and signs compact JWT access tokens using Ed25519 (EdDSA).
 *
 * <p>Produces tokens conforming to RFC 7519, RFC 7515, and RFC 8037 with zero third-party libraries.
 * The header is always {@code {"alg":"EdDSA","typ":"JWT","kid":...}}. A token is signed only when
 * {@code iss}, {@code sub}, {@code aud}, {@code iat}, {@code nbf}, {@code exp} and {@code jti} are
 * all set; the builder supplies no value of its own, and a custom claim can never replace one set
 * through a dedicated method.
 *
 * @since 0.1.0
 */
public final class JwtTokenBuilder {

    private static final List<String> REQUIRED_CLAIMS = List.of("iss", "sub", "aud", "iat", "nbf", "exp", "jti");

    private final String kid;
    private final PrivateKey privateKey;
    private final Map<String, Object> claims = new LinkedHashMap<>();
    private final Map<String, Object> custom = new LinkedHashMap<>();
    private Instant expiresAt;

    private JwtTokenBuilder(String kid, PrivateKey privateKey) {
        this.kid = Objects.requireNonNull(kid, "kid must not be null");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    }

    public static JwtTokenBuilder create(String kid, PrivateKey privateKey) {
        return new JwtTokenBuilder(kid, privateKey);
    }

    public JwtTokenBuilder issuer(String issuer) {
        return put("iss", requireText("issuer", issuer));
    }

    public JwtTokenBuilder subject(UUID subjectId) {
        return put("sub", Objects.requireNonNull(subjectId, "subjectId must not be null").toString());
    }

    public JwtTokenBuilder audience(String audience) {
        return put("aud", requireText("audience", audience));
    }

    public JwtTokenBuilder issuedAt(Instant iat) {
        return put("iat", Objects.requireNonNull(iat, "iat must not be null").getEpochSecond());
    }

    public JwtTokenBuilder notBefore(Instant nbf) {
        return put("nbf", Objects.requireNonNull(nbf, "nbf must not be null").getEpochSecond());
    }

    public JwtTokenBuilder expiresAt(Instant exp) {
        this.expiresAt = Objects.requireNonNull(exp, "exp must not be null");
        return put("exp", exp.getEpochSecond());
    }

    public JwtTokenBuilder jwtId(String jti) {
        return put("jti", requireText("jti", jti));
    }

    public JwtTokenBuilder tenant(String tenantId) {
        return tenantId != null ? put(TokenIssueRequest.TENANT_CLAIM, tenantId) : this;
    }

    public JwtTokenBuilder session(UUID sessionId) {
        return sessionId != null ? put("sid", sessionId.toString()) : this;
    }

    public JwtTokenBuilder roles(Set<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            put("roles", new TreeSet<>(roles));
        }
        return this;
    }

    /**
     * Adds claims that are serialised after the issuer-set claims. A name that is reserved, or
     * already set through a dedicated method, is rejected.
     */
    public JwtTokenBuilder customClaims(Map<String, Object> customClaims) {
        if (customClaims != null) {
            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                if (TokenIssueRequest.RESERVED_CLAIMS.contains(entry.getKey()) || claims.containsKey(entry.getKey())) {
                    throw new IllegalArgumentException("custom claim '" + entry.getKey() + "' is reserved for the issuer");
                }
                custom.put(entry.getKey(), entry.getValue());
            }
        }
        return this;
    }

    public IssuedAccessToken sign() {
        for (String required : REQUIRED_CLAIMS) {
            if (!claims.containsKey(required)) {
                throw new IllegalStateException("claim '" + required + "' must be set before signing");
            }
        }
        Map<String, Object> payload = new LinkedHashMap<>(claims);
        payload.putAll(custom);

        String headerJson = "{\"alg\":\"" + Ed25519Signer.JWT_ALGORITHM + "\",\"typ\":\"JWT\",\"kid\":\""
                + escapeJson(kid) + "\"}";
        String b64Header = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String b64Payload = base64Url(serializeClaimsJson(payload).getBytes(StandardCharsets.UTF_8));

        String signingInput = b64Header + "." + b64Payload;
        byte[] signatureBytes = Ed25519Signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII), privateKey);
        return new IssuedAccessToken(signingInput + "." + base64Url(signatureBytes), expiresAt, "Bearer");
    }

    private JwtTokenBuilder put(String name, Object value) {
        if (custom.containsKey(name)) {
            throw new IllegalArgumentException("claim '" + name + "' was already supplied as a custom claim");
        }
        claims.put(name, value);
        return this;
    }

    private static String requireText(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
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
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
