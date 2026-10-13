package eu.exeris.caps.tokenissuer.api;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Request for one signed access token.
 *
 * <p>The issuer and audience are not part of a request: they come from {@link TokenIssuerConfig},
 * so a caller cannot mint a token for another deployment's verifier. Custom claims may not use a
 * name in {@link #RESERVED_CLAIMS}; the claims the issuer sets are set only by the issuer.
 *
 * @param subjectId    the {@code sub} claim; non-null
 * @param sessionId    the {@code sid} claim; nullable, omitted when null
 * @param tenantId     the {@code tid} claim; nullable, omitted when null, otherwise non-blank
 * @param roles        the {@code roles} claim; never null, omitted when empty
 * @param customClaims additional claims; never null, no reserved name, JSON-serialisable values only
 * @param ttl          token lifetime; nullable (the configured default), otherwise positive
 * @since 0.1.0
 */
public record TokenIssueRequest(
        UUID subjectId,
        UUID sessionId,
        String tenantId,
        Set<String> roles,
        Map<String, Object> customClaims,
        Duration ttl
) {

    /** Claim carrying the tenant the token is scoped to. */
    public static final String TENANT_CLAIM = "tid";

    /** Claim names only the issuer sets. */
    public static final Set<String> RESERVED_CLAIMS = Set.of(
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti", TENANT_CLAIM, "sid", "roles");

    private static final int MAX_TENANT_ID_LENGTH = 128;

    public TokenIssueRequest {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (tenantId != null) {
            tenantId = requireTenantId(tenantId);
        }
        roles = roles != null ? Set.copyOf(roles) : Set.of();
        customClaims = customClaims != null ? Collections.unmodifiableMap(new LinkedHashMap<>(customClaims)) : Map.of();
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            String name = entry.getKey();
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("custom claim name must not be blank");
            }
            if (RESERVED_CLAIMS.contains(name)) {
                throw new IllegalArgumentException("custom claim '" + name + "' is reserved for the issuer");
            }
            requireJsonValue(name, entry.getValue());
        }
        if (ttl != null && (ttl.isNegative() || ttl.isZero())) {
            throw new IllegalArgumentException("ttl must be positive");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    private static String requireTenantId(String tenantId) {
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        if (tenantId.length() > MAX_TENANT_ID_LENGTH) {
            throw new IllegalArgumentException("tenantId must be at most " + MAX_TENANT_ID_LENGTH + " characters");
        }
        for (int i = 0; i < tenantId.length(); i++) {
            if (Character.isISOControl(tenantId.charAt(i)) || Character.isWhitespace(tenantId.charAt(i))) {
                throw new IllegalArgumentException("tenantId must not contain whitespace or control characters");
            }
        }
        return tenantId;
    }

    private static void requireJsonValue(String name, Object value) {
        switch (value) {
            case null -> throw new IllegalArgumentException("custom claim '" + name + "' must not be null");
            case String ignored -> { }
            case Boolean ignored -> { }
            case Double d when d.isNaN() || d.isInfinite() ->
                    throw new IllegalArgumentException("custom claim '" + name + "' must be a finite number");
            case Float f when f.isNaN() || f.isInfinite() ->
                    throw new IllegalArgumentException("custom claim '" + name + "' must be a finite number");
            case Number ignored -> { }
            case Collection<?> items -> items.forEach(item -> requireJsonValue(name, item));
            case Map<?, ?> map -> map.forEach((k, v) -> {
                if (!(k instanceof String)) {
                    throw new IllegalArgumentException("custom claim '" + name + "' has a non-string member name");
                }
                requireJsonValue(name, v);
            });
            default -> throw new IllegalArgumentException("custom claim '" + name
                    + "' must be a string, number, boolean, list or map");
        }
    }

    public static final class Builder {
        private UUID subjectId;
        private UUID sessionId;
        private String tenantId;
        private Set<String> roles = Set.of();
        private Map<String, Object> customClaims = Map.of();
        private Duration ttl;

        public Builder subjectId(UUID subjectId) {
            this.subjectId = subjectId;
            return this;
        }

        public Builder sessionId(UUID sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder roles(Set<String> roles) {
            this.roles = roles != null ? roles : Set.of();
            return this;
        }

        public Builder customClaims(Map<String, Object> customClaims) {
            this.customClaims = customClaims != null ? customClaims : Map.of();
            return this;
        }

        public Builder ttl(Duration ttl) {
            this.ttl = ttl;
            return this;
        }

        public TokenIssueRequest build() {
            return new TokenIssueRequest(subjectId, sessionId, tenantId, roles, customClaims, ttl);
        }
    }
}
