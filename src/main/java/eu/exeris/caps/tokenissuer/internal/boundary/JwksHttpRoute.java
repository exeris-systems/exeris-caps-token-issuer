package eu.exeris.caps.tokenissuer.internal.boundary;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Service Boundary HTTP route handler exposing {@code GET /.well-known/jwks.json}.
 *
 * @since 0.1.0
 */
public final class JwksHttpRoute implements HttpHandler {

    public static final String PATH = "/.well-known/jwks.json";
    public static final String ACTION_NAME = "getJwksDocument";

    private final Supplier<String> jwksJsonSupplier;

    public JwksHttpRoute(Supplier<String> jwksJsonSupplier) {
        this.jwksJsonSupplier = Objects.requireNonNull(jwksJsonSupplier, "jwksJsonSupplier must not be null");
    }

    public static ApiSurfaceRoute createRoute(Supplier<String> jwksJsonSupplier) {
        JwksHttpRoute handler = new JwksHttpRoute(jwksJsonSupplier);
        return new ApiSurfaceRoute(
                HttpMethod.GET,
                PATH,
                ACTION_NAME,
                List.of(),
                handler
        );
    }

    @Override
    public void handle(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange must not be null");
        String jwks = jwksJsonSupplier.get();
        List<HttpHeader> headers = List.of(
                new HttpHeader("content-type", "application/json; charset=utf-8"),
                new HttpHeader("cache-control", "public, max-age=3600")
        );
        HttpResponse response = new HttpResponse(
                HttpStatus.OK,
                exchange.request().version(),
                headers,
                HeapLoanedBuffer.of(jwks)
        );
        exchange.respond(response);
    }
}
