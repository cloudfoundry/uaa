package org.cloudfoundry.identity.uaa.ratelimiting.core;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;

import org.cloudfoundry.identity.uaa.ratelimiting.util.Null;

public enum LoggingOption {
    OnlyLimited() { // Default - see below
        public static final String PREFIX = "Rate Limited path"; // public for reflection in tests
        public static final String SUFFIX = "->";

        @Override
        public void log( String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime ) {
            if ( limiter.shouldLimit() ) {
                logger.accept( prefixAndPath( PREFIX, requestPath )
                                       .append( SUFFIX ).append( ' ' ).append( limiter.getLimitingKey() )
                                       .toString() );
            }
        }
    },
    AllCalls() {
        public static final String PREFIX = "path";
        public static final String SUFFIX_CallsLimited = "-- LIMITED by ->";
        public static final String SUFFIX_CallsNotLimited = "-- NOT limited";

        @Override
        public void log( String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime ) {
            StringBuilder sb = prefixAndPath( PREFIX, requestPath );
            addDuration( sb, startTime, endTime );
            if ( limiter.shouldLimit() ) {
                sb.append( SUFFIX_CallsLimited ).append( ' ' ).append( limiter.getLimitingKey() );
            } else {
                sb.append( SUFFIX_CallsNotLimited );
            }
            logger.accept( sb.toString() );
        }
    },
    AllCallsWithDetails() {
        public static final String PREFIX = "********************************** RateLimiter w/ path";
        public static final String SUFFIX = "->";

        @Override
        public void log( String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime ) {
            logger.accept( prefixAndPath( PREFIX, requestPath )
                                   .append( SUFFIX ).append( ' ' ).append( limiter )
                                   .toString() );
        }
    };

    abstract public void log( String requestPath, Consumer<String> logger, Instant startTime, Limiter limiter, Instant endTime );

    protected StringBuilder prefixAndPath( String prefix, String requestPath ) {
        return new StringBuilder().append( prefix ).append( " '" ).append( requestPath ).append( "' " );
    }

    public static LoggingOption valueFor( String value ) {
        for ( LoggingOption option : values() ) {
            if ( option.name().equalsIgnoreCase( value ) ) {
                return option;
            }
        }
        return null;
    }

    public static LoggingOption DEFAULT = LoggingOption.OnlyLimited;

    public static LoggingOption deNull( LoggingOption option ) {
        return Null.defaultOn( option, DEFAULT );
    }

    // packageFriendly for testing
    static void addDuration( StringBuilder sb, Instant startTime, Instant endTime ) {
        if ( (startTime != null) && (endTime != null) ) {
            sb.append( '(' ).append( Duration.between( startTime, endTime ).toNanos() ).append( "ns) " );
        }
    }
}
