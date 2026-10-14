package eu.exeris.caps.tokenissuer.api;

import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Objects;

/**
 * Deployment configuration of the token issuer: the claims every token carries, the bounds on token
 * lifetime, and the signing-key lifecycle.
 *
 * <p>{@code issuer} and {@code audience} have no defaults. They identify one deployment, and a
 * placeholder that looks like a real URL would let tokens from an unconfigured deployment pass a
 * verifier that happens to expect the same value.
 *
 * @param issuer                the {@code iss} claim of every token; required
 * @param audience              the {@code aud} claim of every token; required
 * @param defaultTokenTtl       lifetime of a token whose request names none; whole seconds, at most {@code maxTokenTtl}
 * @param maxTokenTtl           upper bound on any token lifetime; whole seconds, at least one
 * @param clockSkew             verifier clock tolerance the key publication window allows for; zero or positive
 * @param keyTtl                how long a signing key stays active before it is due for rotation; positive
 * @param rotationCheckInterval how often the scheduled job checks whether rotation or retirement is due; positive
 * @since 0.2.0
 */
public record TokenIssuerConfig(
        String issuer,
        String audience,
        Duration defaultTokenTtl,
        Duration maxTokenTtl,
        Duration clockSkew,
        Duration keyTtl,
        Duration rotationCheckInterval
) {

    public static final String ENV_ISSUER = "EXERIS_TOKEN_ISSUER_ISSUER";
    public static final String ENV_AUDIENCE = "EXERIS_TOKEN_ISSUER_AUDIENCE";
    public static final String ENV_TOKEN_TTL = "EXERIS_TOKEN_ISSUER_TOKEN_TTL";
    public static final String ENV_MAX_TOKEN_TTL = "EXERIS_TOKEN_ISSUER_MAX_TOKEN_TTL";
    public static final String ENV_CLOCK_SKEW = "EXERIS_TOKEN_ISSUER_CLOCK_SKEW";
    public static final String ENV_KEY_TTL = "EXERIS_TOKEN_ISSUER_KEY_TTL";
    public static final String ENV_ROTATION_CHECK_INTERVAL = "EXERIS_TOKEN_ISSUER_ROTATION_CHECK_INTERVAL";

    public static final Duration DEFAULT_TOKEN_TTL = Duration.ofMinutes(15);
    public static final Duration DEFAULT_MAX_TOKEN_TTL = Duration.ofHours(1);
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofMinutes(1);
    public static final Duration DEFAULT_KEY_TTL = Duration.ofDays(7);
    public static final Duration DEFAULT_ROTATION_CHECK_INTERVAL = Duration.ofHours(1);

    private static final int MAX_CLAIM_VALUE_LENGTH = 2048;

    public TokenIssuerConfig {
        issuer = requireClaimValue(ENV_ISSUER, issuer);
        audience = requireClaimValue(ENV_AUDIENCE, audience);
        requireWholeSeconds(ENV_TOKEN_TTL, defaultTokenTtl);
        requireWholeSeconds(ENV_MAX_TOKEN_TTL, maxTokenTtl);
        requirePositive(ENV_KEY_TTL, keyTtl);
        requirePositive(ENV_ROTATION_CHECK_INTERVAL, rotationCheckInterval);
        if (clockSkew == null || clockSkew.isNegative()) {
            throw new TokenIssuerConfigurationException(ENV_CLOCK_SKEW, "must be zero or a positive duration");
        }
        if (defaultTokenTtl.compareTo(maxTokenTtl) > 0) {
            throw new TokenIssuerConfigurationException(ENV_TOKEN_TTL,
                    "must not exceed " + ENV_MAX_TOKEN_TTL);
        }
    }

    /**
     * Configuration with the given issuer and audience and the default lifetimes.
     */
    public static TokenIssuerConfig of(String issuer, String audience) {
        return new TokenIssuerConfig(issuer, audience, DEFAULT_TOKEN_TTL, DEFAULT_MAX_TOKEN_TTL,
                DEFAULT_CLOCK_SKEW, DEFAULT_KEY_TTL, DEFAULT_ROTATION_CHECK_INTERVAL);
    }

    /**
     * Reads the configuration from environment-style key/value pairs. Durations are ISO-8601
     * ({@code PT15M}); an absent duration takes its default, an absent issuer or audience fails.
     *
     * @param environment the variables, typically {@code System.getenv()}; non-null
     * @throws TokenIssuerConfigurationException naming the first missing or malformed key
     */
    public static TokenIssuerConfig fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        return new TokenIssuerConfig(
                environment.get(ENV_ISSUER),
                environment.get(ENV_AUDIENCE),
                duration(environment, ENV_TOKEN_TTL, DEFAULT_TOKEN_TTL),
                duration(environment, ENV_MAX_TOKEN_TTL, DEFAULT_MAX_TOKEN_TTL),
                duration(environment, ENV_CLOCK_SKEW, DEFAULT_CLOCK_SKEW),
                duration(environment, ENV_KEY_TTL, DEFAULT_KEY_TTL),
                duration(environment, ENV_ROTATION_CHECK_INTERVAL, DEFAULT_ROTATION_CHECK_INTERVAL)
        );
    }

    /**
     * How long a key that stopped signing stays in the JWKS: the last token it signed is valid for
     * at most {@code maxTokenTtl}, and a verifier may accept it for {@code clockSkew} longer.
     */
    public Duration publicationOverlap() {
        return maxTokenTtl.plus(clockSkew);
    }

    private static Duration duration(Map<String, String> environment, String key, Duration fallback) {
        String raw = environment.get(key);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Duration.parse(raw.trim());
        } catch (DateTimeParseException e) {
            throw new TokenIssuerConfigurationException(key, "must be an ISO-8601 duration such as PT15M", e);
        }
    }

    private static void requireWholeSeconds(String key, Duration value) {
        if (value == null || !TokenIssueRequest.isWholeSeconds(value)) {
            throw new TokenIssuerConfigurationException(key, "must be a whole number of seconds, at least 1");
        }
    }

    private static void requirePositive(String key, Duration value) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new TokenIssuerConfigurationException(key, "must be a positive duration");
        }
    }

    private static String requireClaimValue(String key, String value) {
        if (value == null || value.isBlank()) {
            throw new TokenIssuerConfigurationException(key, "is required and has no default");
        }
        String trimmed = value.trim();
        if (trimmed.length() > MAX_CLAIM_VALUE_LENGTH) {
            throw new TokenIssuerConfigurationException(key, "must be at most " + MAX_CLAIM_VALUE_LENGTH + " characters");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                throw new TokenIssuerConfigurationException(key, "must not contain whitespace or control characters");
            }
        }
        return trimmed;
    }
}
