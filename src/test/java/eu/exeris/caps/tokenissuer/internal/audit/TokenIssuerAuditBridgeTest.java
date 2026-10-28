package eu.exeris.caps.tokenissuer.internal.audit;

import eu.exeris.caps.tokenissuer.internal.DefaultAccessTokenIssuer;
import eu.exeris.caps.tokenissuer.internal.DefaultSigningKeyRotation;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class TokenIssuerAuditBridgeTest {

    private record Recorded(String action, Instant at) {
    }

    @Test
    @DisplayName("every audit event is stamped from the injected clock, not the wall clock")
    void eventsUseTheInjectedClock() {
        List<Recorded> events = new ArrayList<>();
        MutableClock clock = new MutableClock(Instant.parse("2001-02-03T04:05:06Z"));
        TokenIssuerAuditBridge bridge = new TokenIssuerAuditBridge(
                (action, type, id, actor, details, at) -> events.add(new Recorded(action, at)), clock);
        var repository = new InMemorySigningKeyRepository();
        var rotation = new DefaultSigningKeyRotation(repository, TestSupport.config(), bridge, null, clock);
        var issuer = new DefaultAccessTokenIssuer(repository, TestSupport.config(), rotation, bridge, clock);

        rotation.ensureActiveKey();
        issuer.issueAccessToken(UUID.randomUUID(), null);
        clock.advance(Duration.ofDays(1));
        bridge.logKeyRetired("k-x");
        bridge.logKeyWithdrawn("k-w");

        assertThat(events).extracting(Recorded::action).contains("key.generated", "token.issued", "key.retired", "key.withdrawn");
        assertThat(events.get(0).at()).isEqualTo(Instant.parse("2001-02-03T04:05:06Z"));
        assertThat(events.get(events.size() - 1).at()).isEqualTo(Instant.parse("2001-02-04T04:05:06Z"));
        assertThat(events).extracting(Recorded::at).doesNotContain(Instant.now());
    }

    @Test
    @DisplayName("a failing recorder neither throws nor fails the operation")
    void failingRecorderIsSwallowed() {
        TokenIssuerAuditBridge bridge = new TokenIssuerAuditBridge(
                (action, type, id, actor, details, at) -> {
                    throw new IllegalStateException("sink down");
                }, new MutableClock(Instant.parse("2026-01-01T00:00:00Z")));
        assertThatCode(() -> bridge.logKeyGenerated("k-1")).doesNotThrowAnyException();
    }
}
