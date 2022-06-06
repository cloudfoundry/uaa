package org.cloudfoundry.identity.uaa.ratelimiting.core;

import java.util.function.Consumer;

public enum LoggingOption {
    OnlyLimited() { // Default
        public static final String PREFIX = "Rate Limited path"; // public for reflection in tests
        public static final String SUFFIX = "->";

        @Override
        public void log( String requestPath, Consumer<String> logger, Limiter limiter ) {
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
        public void log( String requestPath, Consumer<String> logger, Limiter limiter ) {
            StringBuilder sb = prefixAndPath( PREFIX, requestPath );
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
        public void log( String requestPath, Consumer<String> logger, Limiter limiter ) {
            logger.accept( prefixAndPath( PREFIX, requestPath )
                                   .append( SUFFIX ).append( ' ' ).append( limiter )
                                   .toString() );
        }
    };

    abstract public void log( String requestPath, Consumer<String> logger, Limiter limiter );

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
}
