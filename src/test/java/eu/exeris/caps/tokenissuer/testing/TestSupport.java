package eu.exeris.caps.tokenissuer.testing;

import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;

/**
 * Shared fixtures: a settable clock, a configuration whose issuer and audience are test-only
 * values, and freshly generated key-encryption keys.
 */
public final class TestSupport {

    public static final String ISSUER = "https://issuer.test.invalid";
    public static final String AUDIENCE = "https://audience.test.invalid";

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestSupport() {
    }

    public static TokenIssuerConfig config() {
        return TokenIssuerConfig.of(ISSUER, AUDIENCE);
    }

    /** A fresh random 32-byte key-encryption key, Base64-encoded. */
    public static String newKek() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    public static final class MutableClock extends Clock {
        private Instant now;

        public MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(Duration duration) {
            now = now.plus(duration);
        }

        public void set(Instant instant) {
            now = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
