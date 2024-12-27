package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public interface NanoTimeSupplier {
    long now();

    default Instant nowAsInstant() {
        return Instant.ofEpochSecond(0L, now());
    }

    NanoTimeSupplier SYSTEM = System::nanoTime;

    static NanoTimeSupplier deNull(NanoTimeSupplier instance) {
        return null != instance ? instance : SYSTEM;
    }

    class Mock implements NanoTimeSupplier {
        private long epochNano;

        @Override
        public long now() {
            return epochNano;
        }

        public void set(Instant instant) {
            epochNano = instant.getNano();
        }

        public void add(long millis) {
            epochNano += millis;
        }

        public void add(Duration duration) {
            add(duration.toNanos());
        }

        public Mock(long epochNano) {
            this.epochNano = epochNano;
        }

        public Mock(Instant instant) {
            this(TimeUnit.MILLISECONDS.toNanos(instant.toEpochMilli()));
        }

        public Mock() {
            this(System.nanoTime());
        }
    }
}
