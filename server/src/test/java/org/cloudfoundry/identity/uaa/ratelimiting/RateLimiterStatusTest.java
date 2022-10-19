package org.cloudfoundry.identity.uaa.ratelimiting;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RateLimiterStatusTest {
    private static final long now15_123456 = Instant.parse( "2011-01-15T12:34:56Z" ).toEpochMilli();
    private static final long now16_012345 = Instant.parse( "2011-01-16T01:23:45Z" ).toEpochMilli();
    private static final long now16_012400 = Instant.parse( "2011-01-16T01:24:00Z" ).toEpochMilli();

    @Test
    void statusVariations() {
        String now = Instant.now().truncatedTo( ChronoUnit.SECONDS ).toString();
        assertEquals( 20, now.length(), now );

        RateLimiterStatus status = RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.DISABLED )
                                  .asOf( now15_123456 )
                                  .build() )
                .fromSource( "https://github.com/xyz/main/RateLimiters.yaml" )
                .build();
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.toBuilder()
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.PENDING )
                                 .asOf( now15_123456 )
                                 .build() )
                .build();
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
        status = status.toBuilder()
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.FAILED )
                                 .asOf( now16_012345 )
                                 .error( "someError" )
                                 .checkCountOfStatus( 1 )
                                 .build() )
                .build();
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 1",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
        status = status.incUpdateCountOfStatus();
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 2",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
        status = status.updateFailed( "someError", () -> now16_012400 );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 3",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
        status = status.updateFailed( "otherError", () -> now16_012400 );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:24:00Z',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
    }

    private void check( RateLimiterStatus status, String... expected ) {
        check( status.toString(), expected );
    }

    private void check( String actualStr, String... expected ) {
        StringBuilder sb = new StringBuilder();
        for ( String str : expected ) {
            if ( sb.length() != 0 ) {
                sb.append( '\n' );
            }
            sb.append( str );
        }
        String expectedStr = sb.toString().replace( '\'', '"' );
        assertEquals( expectedStr, actualStr );
    }
}