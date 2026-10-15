package eu.exeris.caps.tokenissuer.spi;

import java.time.Instant;
import java.util.Map;

/**
 * Receiver of the security events this capability records (key generated, rotated and retired, token
 * issued).
 *
 * <p>The capability treats a failing recorder as a lost event, never as a failed cryptographic
 * operation: an exception thrown here is logged and swallowed. The interface names no type of the
 * audit-trail capability, so a composition without that jar loads this capability unchanged;
 * {@link AuditLogSinkRecorder} adapts an audit-trail sink for a composition that has it.
 *
 * @since 0.1.0
 */
@FunctionalInterface
public interface AuditRecorder {

    /**
     * Records one event.
     *
     * @param action       event name, for example {@code key.rotated}
     * @param resourceType kind of the affected resource, for example {@code signing-key}
     * @param resourceId   identifier of the affected resource; never null
     * @param actorId      who caused the event; {@code system} for the capability itself
     * @param details      event metadata; never contains key material or a token
     * @param occurredAt   the instant of the event, read from the capability's clock
     */
    void recordEvent(String action, String resourceType, String resourceId, String actorId,
                     Map<String, Object> details, Instant occurredAt);
}
