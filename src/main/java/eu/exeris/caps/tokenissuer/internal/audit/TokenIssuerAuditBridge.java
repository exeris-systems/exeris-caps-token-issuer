package eu.exeris.caps.tokenissuer.internal.audit;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Optional bridge emitting security audit events to {@code exeris-caps-audit-trail}.
 *
 * @since 0.1.0
 */
public final class TokenIssuerAuditBridge {

    private final AuditLogSink sink;

    public TokenIssuerAuditBridge(AuditLogSink sink) {
        this.sink = sink;
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

    public void logTokenIssued(UUID subjectId, UUID sessionId, String jti, String kid) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("kid", kid);
        if (sessionId != null) {
            details.put("sessionId", sessionId.toString());
        }
        emit("token.issued", "access-token", jti, subjectId != null ? subjectId.toString() : "system", details);
    }

    private void emit(String action, String resourceType, String resourceId, String actorId, Map<String, Object> details) {
        if (sink != null) {
            try {
                sink.emit(AuditEvent.builder()
                        .action(action)
                        .resourceType(resourceType)
                        .resourceId(resourceId != null ? resourceId : "")
                        .actorId(actorId != null ? actorId : "system")
                        .timestamp(Instant.now())
                        .details(details)
                        .build());
            } catch (Exception ignored) {
                // Audit failure must never fail cryptographic operations
            }
        }
    }
}
