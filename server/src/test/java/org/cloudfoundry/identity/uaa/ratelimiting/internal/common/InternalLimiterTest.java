package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

class InternalLimiterTest {
    static final Instant NOW = Instant.parse("2000-01-01T00:00:00Z");

    static final CompoundKey KEY_A = CompoundKey.from("A", "A", "A");
    static final CompoundKey KEY_B = CompoundKey.from("B", "B", "B");
    static final CompoundKey KEY_Z = CompoundKey.from("Z", "Z", "Z");

    @Test
    void simpleStuff() {
        int initialRequestsRemaining = 0;
        Instant windowEndExclusive = NOW.plusSeconds(1);

        InternalLimiter limiter = new InternalLimiter(KEY_A, initialRequestsRemaining, windowEndExclusive);

        assertThat(limiter.isExpired(NOW)).isFalse();
        assertThat(limiter.isExpired(windowEndExclusive)).isTrue();

        assertThat(limiter.getCompoundKey()).isEqualTo(KEY_A);
        assertThat(limiter.getRequestsRemaining()).isEqualTo(initialRequestsRemaining);
        assertThat(limiter.getWindowEndExclusive()).isEqualTo(windowEndExclusive);
    }

    @Test
    void shouldLimitLogic() {
        RecordingInternalLimiter A = new RecordingInternalLimiter(KEY_A, 2, false);
        RecordingInternalLimiter B = new RecordingInternalLimiter(KEY_B, 0, false);
        RecordingInternalLimiter Z = new RecordingInternalLimiter(KEY_Z, 1, false);

        List<RecordingInternalLimiter> az = List.of(A, Z);
        List<RecordingInternalLimiter> bz = List.of(B, Z);

        assertThat(checkList(az)).isFalse();
        assertThat(checkList(bz)).isTrue();
        assertThat(checkList(az)).isTrue();

        assertThat(compressCalls()).isEqualTo("Aok Zok Z-- A-- Bno Aok Zno");
    }

    @Test
    void shouldLimitConcurrency() {
        RecordingInternalLimiter A = new RecordingInternalLimiter(KEY_A, 200, true);
        RecordingInternalLimiter B = new RecordingInternalLimiter(KEY_B, 200, true);
        RecordingInternalLimiter Z = new RecordingInternalLimiter(KEY_Z, 398, true);

        List<RecordingInternalLimiter> az = List.of(A, Z);
        List<RecordingInternalLimiter> bz = List.of(B, Z);

        Coordinator coordinator = new Coordinator(2, 9, IllegalStateException::new);
        run("1", coordinator, az);
        run("2", coordinator, bz);

        coordinator.waitForReady();
        coordinator.start();
        coordinator.waitForDone();

        List<String> problemStream = new StreamProcessor(compressCalls()).process();
        assertThat(problemStream).as("unexpected sequence from:\n" + problemStream).isEmpty();
    }

    // Start of stream:   A1ok B2ok Z1ok Z1-- A1-- Z2ok Z2-- B2-- B2ok Z2ok A1ok Z2-- B2-- Z1ok Z1-- A1--
    // End of stream:          B2no A1ok Z1ok Z1-- A1-- A1ok Z1ok Z1-- A1-- A1ok Z1ok Z1-- A1-- A1ok Z1no
    private static class StreamProcessor {
        private final List<String> stream;
        int currentOffsetIndex;
        String currentNode;
        String nextNode;

        public StreamProcessor(String compressCalls) {
            stream = new ArrayList<>(List.of(compressCalls.split(" ")));
        }

        private String getNode(int offsetIndex) {
            if (stream.size() <= offsetIndex) {
                fail("no node[" + offsetIndex + "]\n  stream: " + stream);
            }
            String node = stream.get(offsetIndex);
            if ((node == null) || (node.length() != 4)) {
                fail("node[" + offsetIndex + "] not 4 characters: " + node + "\n  stream: " + stream);
            }
            String last2char = node.substring(2);
            if (!"ok".equals(last2char) && !"no".equals(last2char) && !"--".equals(last2char)) {
                fail("node[" + offsetIndex + "] bad last 2 characters: " + node + "\n  stream: " + stream);
            }
            return node;
        }

        private void dropNode(int offsetIndex) {
            stream.remove(offsetIndex);
        }

        private int nextSetNode(int fromOffsetIndex, String findType, String panicType, boolean decrementTail) {
            String message;
            for (; true; fromOffsetIndex++) {
                nextNode = getNode(fromOffsetIndex);
                if (nextNode.startsWith(findType)) {
                    boolean isDecrementTail = nextNode.endsWith("--");
                    if (decrementTail) {
                        if (isDecrementTail) {
                            return fromOffsetIndex;
                        }
                        message = "'--'";
                    } else if (!isDecrementTail) {
                        return fromOffsetIndex;
                    } else {
                        message = "'ok' or 'no'";
                    }
                    fail("node[" + fromOffsetIndex + "] expected node tail to be " + message + ", but got: " + nextNode + "\n  stream: " + stream);
                }
                if (nextNode.startsWith(panicType)) {
                    fail("node[" + fromOffsetIndex + "] search for type '" + findType + "', but got: " + nextNode + "\n  stream: " + stream);
                }
            }
        }

        public List<String> process() {
            while (currentOffsetIndex < stream.size()) {
                currentNode = getNode(currentOffsetIndex);
                switch (currentNode) {
                    case "A1ok":
                        processSet("A1", "Z1");
                        break;
                    case "B2ok":
                        processSet("B2", "Z2");
                        break;
                    case "A1no", "B2no": // Done with B2s
                        dropNode(currentOffsetIndex);
                        break;
                    default:
                        return stream; // effectively an error
                }
            }
            return stream;
        }

        public void processSet(String okType, String zType) {
            int okTypeAt = nextSetNode(currentOffsetIndex + 1, zType, okType, false);
            if (!nextNode.endsWith("no")) {
                // must be "Z?ok"
                int zTypeDecAt = nextSetNode(okTypeAt + 1, zType, okType, true);
                int okTypeDecAt = nextSetNode(zTypeDecAt + 1, okType, zType, true);
                dropNode(okTypeDecAt);
                dropNode(zTypeDecAt);
            }
            dropNode(okTypeAt);
            dropNode(currentOffsetIndex);
        }
    }

    @SuppressWarnings("UnusedReturnValue")
    private static class Coordinator {
        private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;
        private final long timeout;
        private final Function<String, ? extends RuntimeException> awaitFailureExceptionMapper;
        private final CountDownLatch ready;
        private final CountDownLatch start;
        private final CountDownLatch done;

        public Coordinator(int expectedThreads, int timeoutSecs, Function<String, ? extends RuntimeException> awaitFailureExceptionMapper) {
            if (timeoutSecs > 300) { // 5 mins
                throw new IllegalArgumentException("timeoutSecs exceeded 300 (5 mins)");
            }
            timeout = timeoutSecs;
            this.awaitFailureExceptionMapper = awaitFailureExceptionMapper;
            ready = new CountDownLatch(expectedThreads);
            start = new CountDownLatch(1);
            done = new CountDownLatch(expectedThreads);
        }

        public void ready() {
            ready.countDown();
        }

        public boolean waitForReady() {
            return commonWaitFor("ready", ready);
        }

        public void start() {
            start.countDown();
        }

        public boolean waitForStart() {
            return commonWaitFor("start", start);
        }

        public void done() {
            done.countDown();
        }

        public boolean waitForDone() {
            return commonWaitFor("done", done);
        }

        private boolean commonWaitFor(String name, CountDownLatch latch) {
            String message = name;
            try {
                boolean success = latch.await(timeout, TIME_UNIT);
                if (success) {
                    return true;
                }
                message += " timed out";
            } catch (InterruptedException e) {
                message += ":" + e.getMessage();
            }
            if (awaitFailureExceptionMapper != null) {
                throw awaitFailureExceptionMapper.apply(message);
            }
            return false;
        }
    }

    private void run(String threadNumber, Coordinator coordinator, List<RecordingInternalLimiter> toProcess) {
        Thread thread = new Thread(threadNumber) {
            @Override
            public void run() {
                coordinator.ready();
                coordinator.waitForStart();
                for (int i = 0; !checkList(toProcess); i++) {
                    if ((i & 31) == 0) {
                        System.out.print(threadNumber);
                    }
                }
                coordinator.done();
            }
        };
        thread.setDaemon(true);
        thread.start();
    }

    private boolean checkList(List<RecordingInternalLimiter> limiters) {
        List<InternalLimiter> iLimiters = cast(limiters);
        return LimiterImpl.from(iLimiters, LoggingOption.DEFAULT).shouldLimit();
    }

    private String compressCalls() {
        StringBuilder sb = new StringBuilder();
        calls.forEach(s -> {
            if (!sb.isEmpty()) {
                sb.append(' ');
            }
            sb.append(s);
        });
        return sb.toString();
    }

    private final Queue<String> calls = new ConcurrentLinkedQueue<>();

    private class RecordingInternalLimiter extends InternalLimiter {
        private final boolean addThreadName;

        public RecordingInternalLimiter(CompoundKey compoundKey, int initialRequestsRemaining, boolean addThreadName) {
            super(compoundKey, initialRequestsRemaining, NOW); // windowEndExclusive ignored in shouldLimit
            this.addThreadName = addThreadName;
        }

        @Override
        public int getRequestsRemaining() {
            int remaining = super.getRequestsRemaining();
            logCall(remaining < 1 ? "no" : "ok");
            return remaining;
        }

        @Override
        protected int decrementRequestsRemaining() {
            logCall("--");
            return super.decrementRequestsRemaining();
        }

        void logCall(String tail) {
            String sep = addThreadName ? Thread.currentThread().getName() : "";
            calls.add(getCompoundKey().getLimiterName() + sep + tail);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T cast(Object o) {
        return (T) o;
    }
}
