package eu.exeris.caps.tokenissuer.internal.repository;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * The public half of a published signing key: all the JWKS needs, read without unsealing any private
 * key.
 *
 * @param kid               unique key identifier
 * @param publicKeyRawBytes 32-byte raw Ed25519 public key
 * @since 0.1.0
 */
public record PublicSigningKey(String kid, byte[] publicKeyRawBytes) {

    public PublicSigningKey {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(publicKeyRawBytes, "publicKeyRawBytes must not be null");
    }

    @Override
    public boolean equals(Object o) {
        return this == o || o instanceof PublicSigningKey that
                && kid.equals(that.kid) && Arrays.equals(publicKeyRawBytes, that.publicKeyRawBytes);
    }

    @Override
    public int hashCode() {
        return 31 * kid.hashCode() + Arrays.hashCode(publicKeyRawBytes);
    }

    @Override
    public String toString() {
        return "PublicSigningKey[kid=" + kid + ", publicKeyRawBytes=" + HexFormat.of().formatHex(publicKeyRawBytes) + "]";
    }
}
