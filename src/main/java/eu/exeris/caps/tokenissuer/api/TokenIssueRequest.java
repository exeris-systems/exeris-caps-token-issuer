package eu.exeris.caps.tokenissuer.api;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Detailed request for issuing a signed access token.
 *
 * @param subjectId    identity subject identifier; non-null
 * @param sessionId    session identifier; nullable
 * @param issuer       token issuer claim (iss); nullable (defaults to policy issuer)
 * @param audience     token audience claim (aud); nullable (defaults to policy audience)
 * @param roles        set of role identifiers; never null
 * @param customClaims additional claims to embed in payload; never null
 * @param ttl          custom token lifetime; nullable (defaults to policy default token TTL)
 * @since 0.1.0
 */
public record TokenIssueRequest(
        UUID subjectId,
        UUID sessionId,
        String issuer,
        String audience,
        Set<String> roles,
        Map<String, Object> customClaims,
        Duration ttl
) {

    public TokenIssueRequest {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        roles = roles != null ? Set.copyOf(roles) : Set.of();
        customClaims = customClaims != null ? Collections.unmodifiableMap(new LinkedHashMap<>(customClaims)) : Map.of();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private UUID subjectId;
        private UUID sessionId;
        private String issuer;
        private String audience;
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

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder audience(String audience) {
            this.audience = audience;
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
            return new TokenIssueRequest(subjectId, sessionId, issuer, audience, roles, customClaims, ttl);
        }
    }
}
