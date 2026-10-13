package eu.exeris.caps.tokenissuer.testing;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Shared fixtures: freshly generated key-encryption keys.
 */
public final class TestSupport {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestSupport() {
    }

    /** A fresh random 32-byte key-encryption key, Base64-encoded. */
    public static String newKek() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
