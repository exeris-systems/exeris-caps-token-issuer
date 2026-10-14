package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.internal.repository.InMemorySigningKeyRepository;
import eu.exeris.caps.tokenissuer.internal.repository.PublicSigningKey;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.caps.tokenissuer.testing.TestSupport.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The cluster lock is always taken before the in-process monitor. The repository below models the
 * advisory lock with a real lock and forces the interleaving that deadlocks under the opposite order:
 * one thread is inside {@code ensureActiveKey} and about to ask for the cluster lock while another
 * already owns it. Both find the active key inside its publication lead, so both have a successor to
 * generate.
 */
class RotationLockOrderTest {

    private static final class LockingRepository implements SigningKeyRepository {
        private final InMemorySigningKeyRepository delegate = new InMemorySigningKeyRepository();
        private final ReentrantLock clusterLock = new ReentrantLock();
        private final CountDownLatch firstIsAboutToLock = new CountDownLatch(1);
        private final CountDownLatch secondOwnsLock = new CountDownLatch(1);
        private volatile boolean armed;
        private volatile Thread first;

        @Override
        public SigningKeyInfo rotateUnderClusterLock(Supplier<SigningKeyInfo> rotationLogic) {
            boolean isFirst = armed && Thread.currentThread() == first;
            try {
                if (armed && !isFirst) {
                    firstIsAboutToLock.await();
                }
                if (isFirst) {
                    firstIsAboutToLock.countDown();
                    secondOwnsLock.await();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            clusterLock.lock();
            try {
                if (armed && !isFirst) {
                    secondOwnsLock.countDown();
                }
                return rotationLogic.get();
            } finally {
                clusterLock.unlock();
            }
        }

        @Override public void save(SigningKeyRecord record) { delegate.save(record); }
        @Override public Optional<SigningKeyRecord> findActive() { return delegate.findActive(); }
        @Override public Optional<SigningKeyRecord> findByKid(String kid) { return delegate.findByKid(kid); }
        @Override public List<PublicSigningKey> findPublishablePublicKeys(Instant now) { return delegate.findPublishablePublicKeys(now); }
        @Override public List<SigningKeyInfo> findAllInfo() { return delegate.findAllInfo(); }
        @Override public void updateState(String kid, KeyState state, Instant retiredAt) { delegate.updateState(kid, state, retiredAt); }
        @Override public int deleteRetiredBefore(Instant cutoff) { return delegate.deleteRetiredBefore(cutoff); }
    }

    @Test
    @DisplayName("ensureActiveKey and rotateIfDue running together on a due key do not deadlock")
    void noDeadlockBetweenMonitorAndClusterLock() throws Exception {
        LockingRepository repository = new LockingRepository();
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        DefaultSigningKeyRotation rotation =
                new DefaultSigningKeyRotation(repository, TestSupport.config(), null, null, clock);
        SigningKeyInfo initial = rotation.ensureActiveKey();
        // Inside the publication lead both paths find a successor to generate and both want the lock.
        clock.set(initial.expiresAt().minus(TestSupport.config().publicationLead()));

        ExecutorService executor = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "rotation-lock-order");
            thread.setDaemon(true);
            return thread;
        });
        try {
            repository.armed = true;
            Future<SigningKeyInfo> first = executor.submit(() -> {
                repository.first = Thread.currentThread();
                return rotation.ensureActiveKey();
            });
            while (repository.first == null) {
                Thread.sleep(2);
            }
            Future<SigningKeyInfo> second = executor.submit(rotation::rotateIfDue);

            SigningKeyInfo a = first.get(10, TimeUnit.SECONDS);
            SigningKeyInfo b = second.get(10, TimeUnit.SECONDS);
            assertThat(a.state()).isEqualTo(KeyState.ACTIVE);
            assertThat(b.kid()).isEqualTo(a.kid());
            assertThat(repository.findAllInfo()).filteredOn(k -> k.state() == KeyState.PENDING).hasSize(1);
        } finally {
            executor.shutdownNow();
        }
    }
}
