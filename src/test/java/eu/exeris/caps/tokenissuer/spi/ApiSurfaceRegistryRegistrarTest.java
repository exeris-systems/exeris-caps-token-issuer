package eu.exeris.caps.tokenissuer.spi;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ApiSurfaceRegistryRegistrarTest {

    @Test
    @DisplayName("the JWKS route registers on a strict registry and serves the document")
    void registersOnStrictRegistryAndServes() {
        ApiSurfaceRegistry registry = ServiceBoundaryCoreModule.builder()
                .strictRoutes(true)
                .build()
                .apiSurfaceRegistry();

        new ApiSurfaceRegistryRegistrar(registry)
                .registerJwksRoute(() -> "{\"keys\":[]}", Duration.ofSeconds(300));

        assertThat(registry.routeCount()).isEqualTo(1);

        AtomicReference<HttpResponse> sent = new AtomicReference<>();
        HttpRequest request = HttpRequest.noBody(
                HttpMethod.GET, "/.well-known/jwks.json", HttpVersion.HTTP_1_1, List.of());
        registry.handle(new HttpExchange() {
            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public void respond(HttpResponse response) {
                sent.set(response);
            }
        });

        assertThat(sent.get()).isNotNull();
        assertThat(sent.get().status()).isEqualTo(HttpStatus.OK);
    }
}
