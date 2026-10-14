package eu.exeris.caps.tokenissuer.internal.boundary;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;

import java.time.Duration;
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
    private final String cacheControl;

    /**
     * @param jwksJsonSupplier supplies the current JWKS document
     * @param maxAge           the {@code max-age} served to verifiers; whole seconds, at least one. A
     *                         new key is published at least this long before it signs
     */
    public JwksHttpRoute(Supplier<String> jwksJsonSupplier, Duration maxAge) {
        this.jwksJsonSupplier = Objects.requireNonNull(jwksJsonSupplier, "jwksJsonSupplier must not be null");
        Objects.requireNonNull(maxAge, "maxAge must not be null");
        if (maxAge.getNano() != 0 || maxAge.getSeconds() < 1) {
            throw new IllegalArgumentException("maxAge must be a whole number of seconds, at least 1: " + maxAge);
        }
        this.cacheControl = "public, max-age=" + maxAge.getSeconds();
    }

    public static ApiSurfaceRoute createRoute(Supplier<String> jwksJsonSupplier, Duration maxAge) {
        JwksHttpRoute handler = new JwksHttpRoute(jwksJsonSupplier, maxAge);
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
                new HttpHeader("cache-control", cacheControl)
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
