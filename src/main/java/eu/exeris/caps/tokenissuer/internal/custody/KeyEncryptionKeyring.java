package eu.exeris.caps.tokenissuer.internal.custody;

import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The key-encryption keys that wrap signing keys at rest, each under an id.
 *
 * <p>The first entry is the active KEK and seals every new envelope; the others only open
 * envelopes sealed earlier, so a KEK rotates by prepending a new entry and is dropped once no
 * stored envelope names it. A KEK is exactly 32 random bytes (AES-256), given in Base64. There is
 * no default and no derivation from a passphrase: a keyring that is absent or malformed is a
 * configuration error, never a reason to substitute a key.
 *
 * <p>Format: {@code <id>:<base64>[,<id>:<base64>...]}, from {@value #ENV_KEKS} or from the file
 * named by {@value #ENV_KEKS_FILE} (a mounted secret), never both.
 */
public final class KeyEncryptionKeyring {

    public static final String ENV_KEKS = "EXERIS_TOKEN_ISSUER_KEKS";
    public static final String ENV_KEKS_FILE = "EXERIS_TOKEN_ISSUER_KEKS_FILE";

    static final int KEK_LENGTH_BYTES = 32;
    private static final Pattern KEK_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");

    private final String activeId;
    private final Map<String, SecretKey> keys;

    private KeyEncryptionKeyring(String activeId, Map<String, SecretKey> keys) {
        this.activeId = activeId;
        this.keys = keys;
    }

    /**
     * Reads the keyring from {@value #ENV_KEKS} or {@value #ENV_KEKS_FILE}.
     *
     * @throws TokenIssuerConfigurationException when neither or both are set, the file cannot be
     *                                           read, or the content is malformed
     */
    public static KeyEncryptionKeyring fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        String inline = environment.get(ENV_KEKS);
        String file = environment.get(ENV_KEKS_FILE);
        boolean hasInline = inline != null && !inline.isBlank();
        boolean hasFile = file != null && !file.isBlank();
        if (hasInline && hasFile) {
            throw new TokenIssuerConfigurationException(ENV_KEKS, "set either " + ENV_KEKS + " or "
                    + ENV_KEKS_FILE + ", not both");
        }
        if (hasInline) {
            return parse(ENV_KEKS, inline);
        }
        if (hasFile) {
            String content;
            try {
                content = Files.readString(Path.of(file.trim()), StandardCharsets.UTF_8);
            } catch (IOException | RuntimeException e) {
                throw new TokenIssuerConfigurationException(ENV_KEKS_FILE, "the keyring file cannot be read", e);
            }
            return parse(ENV_KEKS_FILE, content);
        }
        throw new TokenIssuerConfigurationException(ENV_KEKS, "a key-encryption keyring is required to store "
                + "signing keys; set " + ENV_KEKS + " or " + ENV_KEKS_FILE);
    }

    /**
     * Parses a keyring specification. {@code source} names the configuration key in errors; the
     * specification itself never appears in a message.
     */
    public static KeyEncryptionKeyring parse(String source, String specification) {
        Objects.requireNonNull(source, "source must not be null");
        if (specification == null || specification.isBlank()) {
            throw new TokenIssuerConfigurationException(source, "the keyring is empty");
        }
        Map<String, SecretKey> keys = new LinkedHashMap<>();
        String activeId = null;
        String[] entries = specification.trim().split(",");
        for (int i = 0; i < entries.length; i++) {
            String entry = entries[i].trim();
            int colon = entry.indexOf(':');
            if (colon <= 0) {
                throw new TokenIssuerConfigurationException(source, "entry " + (i + 1) + " is not <id>:<base64>");
            }
            String id = entry.substring(0, colon);
            if (!KEK_ID.matcher(id).matches()) {
                throw new TokenIssuerConfigurationException(source, "entry " + (i + 1)
                        + " has an id that is not 1-32 characters of [A-Za-z0-9._-]");
            }
            if (keys.containsKey(id)) {
                throw new TokenIssuerConfigurationException(source, "KEK id '" + id + "' appears twice");
            }
            byte[] material = decode(source, id, entry.substring(colon + 1).trim());
            keys.put(id, new SecretKeySpec(material, "AES"));
            java.util.Arrays.fill(material, (byte) 0);
            if (activeId == null) {
                activeId = id;
            }
        }
        return new KeyEncryptionKeyring(activeId, Map.copyOf(keys));
    }

    private static byte[] decode(String source, String id, String base64) {
        byte[] decoded;
        try {
            decoded = base64.indexOf('-') >= 0 || base64.indexOf('_') >= 0
                    ? Base64.getUrlDecoder().decode(base64)
                    : Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new TokenIssuerConfigurationException(source, "KEK '" + id + "' is not valid Base64");
        }
        if (decoded.length != KEK_LENGTH_BYTES) {
            int length = decoded.length;
            java.util.Arrays.fill(decoded, (byte) 0);
            throw new TokenIssuerConfigurationException(source, "KEK '" + id + "' must decode to "
                    + KEK_LENGTH_BYTES + " bytes, got " + length);
        }
        return decoded;
    }

    /**
     * Returns the id of the KEK that seals new envelopes.
     *
     * @return the active KEK id
     */
    public String activeId() {
        return activeId;
    }

    SecretKey activeKey() {
        return keys.get(activeId);
    }

    Optional<SecretKey> key(String id) {
        return Optional.ofNullable(keys.get(id));
    }

    @Override
    public String toString() {
        return "KeyEncryptionKeyring[active=" + activeId + ", ids=" + keys.keySet() + "]";
    }
}
