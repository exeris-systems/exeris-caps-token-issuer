package eu.exeris.caps.tokenissuer.internal.audit;

import eu.exeris.caps.tokenissuer.spi.AuditRecorder;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Emits the capability's security audit events to an {@link AuditRecorder}.
 *
 * <p>Every event is stamped from the injected {@link Clock}, so the audit trail and the keys and
 * tokens it describes share one notion of time. A failing recorder is logged and never fails a
 * cryptographic operation.
 *
 * @since 0.1.0
 */
public final class TokenIssuerAuditBridge {

    private static final System.Logger LOG = System.getLogger(TokenIssuerAuditBridge.class.getName());

    private final AuditRecorder recorder;
    private final Clock clock;

    public TokenIssuerAuditBridge(AuditRecorder recorder, Clock clock) {
        this.recorder = Objects.requireNonNull(recorder, "recorder must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public void logKeyGenerated(String kid) {
        emit("key.generated", "signing-key", kid, "system", Map.of(
                "kid", kid,
                "algorithm", "EdDSA"
        ));
    }

    public void logKeyRotated(String newKid, String retiringKid) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("activeKid", newKid);
        if (retiringKid != null) {
            details.put("retiringKid", retiringKid);
        }
        emit("key.rotated", "signing-key", newKid, "system", details);
    }

    public void logKeyRetired(String kid) {
        emit("key.retired", "signing-key", kid, "system", Map.of("kid", kid));
    }

    public void logKeyWithdrawn(String kid) {
        emit("key.withdrawn", "signing-key", kid, "system", Map.of("kid", kid));
    }

    public void logKekResealed(int count, String activeKekId) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("resealedCount", count);
        if (activeKekId != null) {
            details.put("activeKekId", activeKekId);
        }
        emit("kek.resealed", "key-encryption-key", activeKekId != null ? activeKekId : "active", "system", details);
    }

    public void logTokenIssued(UUID subjectId, UUID sessionId, String jti, String kid) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("kid", kid);
        if (sessionId != null) {
            details.put("sessionId", sessionId.toString());
        }
        emit("token.issued", "access-token", jti, subjectId != null ? subjectId.toString() : "system", details);
    }

    private void emit(String action, String resourceType, String resourceId, String actorId, Map<String, Object> details) {
        try {
            recorder.recordEvent(action, resourceType, resourceId != null ? resourceId : "",
                    actorId != null ? actorId : "system", details, clock.instant());
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "audit event " + action + " was lost: the recorder failed", e);
        }
    }
}
