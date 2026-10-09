package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;

import java.time.Instant;
import java.util.Objects;

/**
 * Persistent record of a signing key generation with raw and serialized key material.
 *
 * @param kid                 unique key identifier
 * @param algorithm           algorithm name (e.g. {@code EdDSA})
 * @param publicKeyJwkJson    serialized RFC 8037 JWK JSON representation
 * @param publicKeyRawBytes   32-byte raw Ed25519 public key coordinate
 * @param privateKeyPkcs8Bytes PKCS#8 DER encoded private key bytes
 * @param state               lifecycle state
 * @param createdAt           creation timestamp
 * @param expiresAt           expiration timestamp
 * @param retiredAt           retirement timestamp (or null if not yet retired)
 * @since 0.1.0
 */
public record SigningKeyRecord(
        String kid,
        String algorithm,
        String publicKeyJwkJson,
        byte[] publicKeyRawBytes,
        byte[] privateKeyPkcs8Bytes,
        KeyState state,
        Instant createdAt,
        Instant expiresAt,
        Instant retiredAt
) {

    public SigningKeyRecord {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(publicKeyJwkJson, "publicKeyJwkJson must not be null");
        Objects.requireNonNull(publicKeyRawBytes, "publicKeyRawBytes must not be null");
        Objects.requireNonNull(privateKeyPkcs8Bytes, "privateKeyPkcs8Bytes must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }

    public SigningKeyInfo toInfo() {
        return new SigningKeyInfo(kid, algorithm, state, createdAt, expiresAt, retiredAt);
    }
}
