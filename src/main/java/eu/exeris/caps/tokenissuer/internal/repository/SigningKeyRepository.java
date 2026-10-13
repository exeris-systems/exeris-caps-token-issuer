package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

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
     * Retrieves the keys the JWKS publishes at {@code now}: the {@link KeyState#ACTIVE} key and every
     * {@link KeyState#RETIRING} key whose {@code retiredAt} is after {@code now}. A retiring key's
     * {@code retiredAt} is set when it stops signing, so publication ends on time whether or not
     * {@code retireExpiredKeys} has run.
     *
     * @param now reference instant
     * @return publishable key records, newest first
     */
    List<SigningKeyRecord> findPublishable(Instant now);

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

    /**
     * Executes rotation action under a transactional cluster advisory lock.
     *
     * @param rotationLogic rotation logic callback
     * @return rotated or active key info
     */
    default SigningKeyInfo rotateUnderClusterLock(Supplier<SigningKeyInfo> rotationLogic) {
        return rotationLogic.get();
    }
}

