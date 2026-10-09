package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Storage contract for persisting and retrieving cryptographic signing keys.
 *
 * @since 0.1.0
 */
public interface SigningKeyRepository {

    /**
     * Persists a newly generated signing key record.
     *
     * @param record key record; non-null
     */
    void save(SigningKeyRecord record);

    /**
     * Retrieves the currently active signing key record, if one exists.
     *
     * @return optional containing the active key record, or empty
     */
    Optional<SigningKeyRecord> findActive();

    /**
     * Retrieves a signing key record by its key identifier.
     *
     * @param kid key identifier; non-null
     * @return optional containing the matching record, or empty
     */
    Optional<SigningKeyRecord> findByKid(String kid);

    /**
     * Retrieves all publishable keys for JWKS distribution:
     * - Keys in {@link KeyState#ACTIVE}
     * - Keys in {@link KeyState#RETIRING} whose {@code retiredAt} (or {@code expiresAt + overlapWindow}) is after {@code now}.
     *
     * @param now           reference current instant
     * @param overlapWindow overlap grace window
     * @return list of publishable key records
     */
    List<SigningKeyRecord> findPublishable(Instant now, Duration overlapWindow);

    /**
     * Retrieves all recorded signing key records ordered by creation date descending.
     *
     * @return list of all key records
     */
    List<SigningKeyRecord> findAll();

    /**
     * Updates the lifecycle state and optional retired timestamp of a key.
     *
     * @param kid       key identifier; non-null
     * @param state     new lifecycle state; non-null
     * @param retiredAt retirement instant; nullable
     */
    void updateState(String kid, KeyState state, Instant retiredAt);

    /**
     * Deletes retired key records older than the cutoff instant.
     *
     * @param cutoff cutoff instant; non-null
     * @return number of deleted records
     */
    int deleteRetiredBefore(Instant cutoff);
}
