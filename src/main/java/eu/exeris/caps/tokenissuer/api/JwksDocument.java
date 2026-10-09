package eu.exeris.caps.tokenissuer.api;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * JWKS (JSON Web Key Set) document representation compliant with RFC 7517 and RFC 8037.
 *
 * @param keys    list of key parameter maps
 * @param rawJson serialized JSON string of the JWKS document
 * @since 0.1.0
 */
public record JwksDocument(
        List<Map<String, String>> keys,
        String rawJson
) {

    public JwksDocument {
        keys = keys != null ? List.copyOf(keys) : List.of();
        Objects.requireNonNull(rawJson, "rawJson must not be null");
    }
}
