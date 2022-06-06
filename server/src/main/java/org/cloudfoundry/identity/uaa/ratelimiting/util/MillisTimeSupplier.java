package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.time.Duration;
import java.time.Instant;

public interface MillisTimeSupplier {
    long now();

    default Instant nowAsInstant() {
        return Instant.ofEpochMilli( now() );
    }

    MillisTimeSupplier SYSTEM = System::currentTimeMillis;

    static MillisTimeSupplier deNull( MillisTimeSupplier instance ) {
        return (null != instance) ? instance : SYSTEM;
    }

    class Mock implements MillisTimeSupplier {
        private long epochMillis;

        @Override
        public long now() {
            return epochMillis;
        }

        public void set( Instant instant ) {
            epochMillis = instant.toEpochMilli();
        }

        public void add( long millis ) {
            epochMillis += millis;
        }

        public void add( Duration duration ) {
            add( duration.toMillis() );
        }

        public Mock( long epochMillis ) {
            this.epochMillis = epochMillis;
        }

        public Mock( Instant instant ) {
            this( instant.toEpochMilli() );
        }

        public Mock() {
            this( System.currentTimeMillis() );
        }
    }
}
