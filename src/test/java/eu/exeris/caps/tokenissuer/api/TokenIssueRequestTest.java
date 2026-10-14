package eu.exeris.caps.tokenissuer.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenIssueRequestTest {

    @ParameterizedTest
    @ValueSource(strings = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "tid", "sid", "roles"})
    @DisplayName("a custom claim cannot use a reserved name")
    void reservedClaimsRejected(String name) {
        assertThatThrownBy(() -> TokenIssueRequest.builder()
                .subjectId(UUID.randomUUID())
                .customClaims(Map.of(name, "x"))
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(name);
    }

    @Test
    @DisplayName("custom claim values must be JSON-serialisable and finite")
    void customValuesValidated() {
        assertThatThrownBy(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID())
                .customClaims(Map.of("ratio", Double.NaN)).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID())
                .customClaims(Map.of("when", new Object())).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatCode(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID())
                .customClaims(Map.of("plan", "pro", "seats", 5, "flags", java.util.List.of(true))).build())
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a tenant id is non-blank and free of whitespace when present")
    void tenantValidated() {
        assertThatThrownBy(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID()).tenantId(" ").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID()).tenantId("a b").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatCode(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID()).tenantId(null).build())
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"PT1.5S", "PT0.5S", "PT0.999999999S", "PT0S", "PT-1S"})
    @DisplayName("a ttl that is not a whole number of seconds of at least one is refused")
    void ttlMustBeWholeSeconds(String ttl) {
        Duration parsed = Duration.parse(ttl);
        assertThatThrownBy(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID())
                .ttl(parsed).build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("whole number of seconds");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PT1S", "PT15M", "PT1H"})
    @DisplayName("a whole-second ttl is accepted")
    void wholeSecondTtlAccepted(String ttl) {
        assertThatCode(() -> TokenIssueRequest.builder().subjectId(UUID.randomUUID())
                .ttl(Duration.parse(ttl)).build()).doesNotThrowAnyException();
    }
}
