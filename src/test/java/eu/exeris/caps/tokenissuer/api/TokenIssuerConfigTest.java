package eu.exeris.caps.tokenissuer.api;

import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenIssuerConfigTest {

    private static Map<String, String> env() {
        Map<String, String> env = new HashMap<>();
        env.put(TokenIssuerConfig.ENV_ISSUER, "https://issuer.test.invalid");
        env.put(TokenIssuerConfig.ENV_AUDIENCE, "https://audience.test.invalid");
        return env;
    }

    @Test
    @DisplayName("issuer and audience have no default")
    void issuerAndAudienceAreRequired() {
        Map<String, String> noIssuer = env();
        noIssuer.remove(TokenIssuerConfig.ENV_ISSUER);
        assertThatThrownBy(() -> TokenIssuerConfig.fromEnvironment(noIssuer))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(TokenIssuerConfig.ENV_ISSUER));

        Map<String, String> blankAudience = env();
        blankAudience.put(TokenIssuerConfig.ENV_AUDIENCE, "  ");
        assertThatThrownBy(() -> TokenIssuerConfig.fromEnvironment(blankAudience))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .satisfies(e -> assertThat(((TokenIssuerConfigurationException) e).key())
                        .isEqualTo(TokenIssuerConfig.ENV_AUDIENCE));
    }

    @Test
    @DisplayName("durations default, parse as ISO-8601, and malformed values name their key")
    void durations() {
        TokenIssuerConfig defaults = TokenIssuerConfig.fromEnvironment(env());
        assertThat(defaults.defaultTokenTtl()).isEqualTo(Duration.ofMinutes(15));
        assertThat(defaults.maxTokenTtl()).isEqualTo(Duration.ofHours(1));
        assertThat(defaults.clockSkew()).isEqualTo(Duration.ofMinutes(1));
        assertThat(defaults.publicationOverlap()).isEqualTo(Duration.ofMinutes(61));

        Map<String, String> custom = env();
        custom.put(TokenIssuerConfig.ENV_MAX_TOKEN_TTL, "PT30M");
        custom.put(TokenIssuerConfig.ENV_CLOCK_SKEW, "PT0S");
        assertThat(TokenIssuerConfig.fromEnvironment(custom).publicationOverlap()).isEqualTo(Duration.ofMinutes(30));

        Map<String, String> malformed = env();
        malformed.put(TokenIssuerConfig.ENV_KEY_TTL, "7 days");
        assertThatThrownBy(() -> TokenIssuerConfig.fromEnvironment(malformed))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .hasMessageContaining(TokenIssuerConfig.ENV_KEY_TTL);
    }

    @Test
    @DisplayName("the default lifetime may not exceed the maximum")
    void defaultTtlBoundedByMax() {
        Map<String, String> env = env();
        env.put(TokenIssuerConfig.ENV_TOKEN_TTL, "PT2H");
        assertThatThrownBy(() -> TokenIssuerConfig.fromEnvironment(env))
                .isInstanceOf(TokenIssuerConfigurationException.class)
                .hasMessageContaining(TokenIssuerConfig.ENV_TOKEN_TTL);
    }

    @Test
    @DisplayName("configured lifetimes must be whole seconds")
    void lifetimesAreWholeSeconds() {
        for (String key : new String[]{TokenIssuerConfig.ENV_TOKEN_TTL, TokenIssuerConfig.ENV_MAX_TOKEN_TTL}) {
            Map<String, String> env = env();
            env.put(key, "PT0.5S");
            assertThatThrownBy(() -> TokenIssuerConfig.fromEnvironment(env))
                    .isInstanceOf(TokenIssuerConfigurationException.class)
                    .hasMessageContaining(key);
        }
    }
}
