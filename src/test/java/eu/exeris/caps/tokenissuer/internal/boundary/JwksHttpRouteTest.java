package eu.exeris.caps.tokenissuer.internal.boundary;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwksHttpRouteTest {

    private static HttpResponse serve(Duration maxAge) {
        AtomicReference<HttpResponse> sent = new AtomicReference<>();
        HttpRequest request = HttpRequest.noBody(HttpMethod.GET, JwksHttpRoute.PATH, HttpVersion.HTTP_1_1, List.of());
        new JwksHttpRoute(() -> "{\"keys\":[]}", maxAge).handle(new HttpExchange() {
            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public void respond(HttpResponse response) {
                sent.set(response);
            }
        });
        return sent.get();
    }

    @Test
    @DisplayName("the served max-age is the configured JWKS cache lifetime")
    void maxAgeIsTheConfiguredLifetime() {
        HttpResponse response = serve(Duration.ofSeconds(300));
        assertThat(response.headers()).anySatisfy(h -> {
            assertThat(h.name()).isEqualToIgnoringCase("cache-control");
            assertThat(h.value()).isEqualTo("public, max-age=300");
        });
    }

    @Test
    @DisplayName("a max-age that is not a whole number of seconds of at least one is refused")
    void maxAgeMustBeWholeSeconds() {
        Duration fractional = Duration.ofMillis(1500);
        assertThatThrownBy(() -> new JwksHttpRoute(() -> "{}", fractional))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new JwksHttpRoute(() -> "{}", Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
