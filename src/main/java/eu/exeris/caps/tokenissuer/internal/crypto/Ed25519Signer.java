package eu.exeris.caps.tokenissuer.internal.crypto;

import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerException;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * Standard Java JCA Ed25519 cryptographic primitives.
 *
 * <p>Provides key generation, digital signing, signature verification, and DER/raw byte
 * conversions compliant with RFC 8032 and RFC 8037 with zero third-party dependencies.
 *
 * @since 0.1.0
 */
public final class Ed25519Signer {

    public static final String ALGORITHM = "Ed25519";
    public static final String JWT_ALGORITHM = "EdDSA";

    /**
     * Standard 12-byte DER X.509 SubjectPublicKeyInfo prefix for Ed25519:
     * SEQUENCE (42) -> SEQUENCE (5) -> OID 1.3.101.112 -> BIT STRING (33) 0x00.
     */
    private static final byte[] ED25519_X509_HEADER = new byte[]{
            0x30, 0x2a,
            0x30, 0x05,
            0x06, 0x03, (byte) 0x2b, 0x65, 0x70,
            0x03, 0x21,
            0x00
    };

    private static final int RAW_KEY_LENGTH = 32;

    private Ed25519Signer() {}

    /**
     * Generates a new Ed25519 key pair.
     *
     * @return newly generated key pair
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new TokenIssuerException("Ed25519 algorithm not supported by JVM JCA provider", e);
        }
    }

    /**
     * Signs data using an Ed25519 private key.
     *
     * @param data       payload bytes to sign; non-null
     * @param privateKey Ed25519 private key; non-null
     * @return 64-byte Ed25519 signature
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new TokenIssuerException("Failed to generate Ed25519 signature", e);
        }
    }

    /**
     * Verifies an Ed25519 digital signature.
     *
     * @param data      original payload bytes; non-null
     * @param signature signature bytes to verify; non-null
     * @param publicKey Ed25519 public key; non-null
     * @return {@code true} if signature is valid, {@code false} otherwise
     */
    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts raw 32 bytes from an Ed25519 X.509 encoded public key.
     *
     * @param publicKey Ed25519 public key; non-null
     * @return 32 raw public key bytes
     */
    public static byte[] extractRawPublicKeyBytes(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        byte[] encoded = publicKey.getEncoded();
        if (encoded.length < RAW_KEY_LENGTH) {
            throw new TokenIssuerException("Invalid Ed25519 public key encoded length: " + encoded.length);
        }
        byte[] raw = new byte[RAW_KEY_LENGTH];
        System.arraycopy(encoded, encoded.length - RAW_KEY_LENGTH, raw, 0, RAW_KEY_LENGTH);
        return raw;
    }

    /**
     * Reconstructs an Ed25519 {@link PublicKey} from 32 raw bytes.
     *
     * @param rawBytes 32 raw public key bytes; non-null
     * @return reconstructed public key
     */
    public static PublicKey reconstructPublicKey(byte[] rawBytes) {
        Objects.requireNonNull(rawBytes, "rawBytes must not be null");
        if (rawBytes.length != RAW_KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 raw public key must be exactly 32 bytes, got " + rawBytes.length);
        }
        byte[] x509 = new byte[ED25519_X509_HEADER.length + RAW_KEY_LENGTH];
        System.arraycopy(ED25519_X509_HEADER, 0, x509, 0, ED25519_X509_HEADER.length);
        System.arraycopy(rawBytes, 0, x509, ED25519_X509_HEADER.length, RAW_KEY_LENGTH);
        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            return factory.generatePublic(new X509EncodedKeySpec(x509));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new TokenIssuerException("Failed to reconstruct Ed25519 public key", e);
        }
    }

    /**
     * Reconstructs an Ed25519 {@link PrivateKey} from PKCS#8 DER bytes.
     *
     * @param pkcs8Bytes PKCS#8 DER bytes; non-null
     * @return reconstructed private key
     */
    public static PrivateKey reconstructPrivateKey(byte[] pkcs8Bytes) {
        Objects.requireNonNull(pkcs8Bytes, "pkcs8Bytes must not be null");
        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new TokenIssuerException("Failed to reconstruct Ed25519 private key from PKCS#8", e);
        }
    }
}
