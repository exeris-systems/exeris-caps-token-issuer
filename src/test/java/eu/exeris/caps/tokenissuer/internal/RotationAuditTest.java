package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Audit events describe keys that were stored, so they are emitted after the transaction that stores
 * them has committed and never while it is still open.
 */
class RotationAuditTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    private final List<String> events = new ArrayList<>();
    private boolean insideClusterLock;
    private boolean failAfterRotation;

    private SigningKeyRepository transactionalRepository() {
        SigningKeyRepository delegate = new InMemorySigningKeyRepository();
        return (SigningKeyRepository) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {SigningKeyRepository.class}, (proxy, method, args) -> {
                    if (!method.getName().equals("rotateUnderClusterLock")) {
                        try {
                            return method.invoke(delegate, args);
                        } catch (java.lang.reflect.InvocationTargetException e) {
                            throw e.getCause();
                        }
                    }
                    @SuppressWarnings("unchecked")
                    Supplier<SigningKeyInfo> logic = (Supplier<SigningKeyInfo>) args[0];
                    insideClusterLock = true;
                    try {
                        SigningKeyInfo result = logic.get();
                        if (failAfterRotation) {
                            throw new IllegalStateException("commit failed");
                        }
                        return result;
                    } finally {
                        insideClusterLock = false;
                    }
                });
    }

    private DefaultSigningKeyRotation rotation(SigningKeyRepository repository, MutableClock clock) {
        TokenIssuerAuditBridge bridge = new TokenIssuerAuditBridge(
                (action, type, id, actor, details, at) -> {
                    assertThat(insideClusterLock).as("event %s emitted inside the transaction", action).isFalse();
                    events.add(action);
                }, clock);
        return new DefaultSigningKeyRotation(repository, TestSupport.config(), bridge, null, clock);
    }

    @Test
    void eventsAreEmittedAfterTheClusterLockIsReleased() {
        DefaultSigningKeyRotation rotation = rotation(transactionalRepository(), new MutableClock(T0));

        rotation.ensureActiveKey();

        assertThat(events).containsExactly("key.generated");
    }

    @Test
    void aRolledBackRotationEmitsNothing() {
        failAfterRotation = true;
        DefaultSigningKeyRotation rotation = rotation(transactionalRepository(), new MutableClock(T0));

        assertThatThrownBy(rotation::ensureActiveKey).isInstanceOf(IllegalStateException.class);

        assertThat(events).isEmpty();
    }
}
