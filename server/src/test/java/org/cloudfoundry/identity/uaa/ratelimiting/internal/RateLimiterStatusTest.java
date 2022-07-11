package org.cloudfoundry.identity.uaa.ratelimiting.internal;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("SameParameterValue")
class RateLimiterStatusTest {
    private static final long now15_123450 = Instant.parse( "2011-01-15T12:34:50Z" ).toEpochMilli();
    private static final long now15_123456 = Instant.parse( "2011-01-15T12:34:56Z" ).toEpochMilli();
    private static final long now16_012345 = Instant.parse( "2011-01-16T01:23:45Z" ).toEpochMilli();
    private static final long now16_012500 = Instant.parse( "2011-01-16T01:25:00Z" ).toEpochMilli();
    private static final long now16_013000 = Instant.parse( "2011-01-16T01:30:00Z" ).toEpochMilli();
    private static final long now16_013500 = Instant.parse( "2011-01-16T01:35:00Z" ).toEpochMilli();
    private static final long now16_014000 = Instant.parse( "2011-01-16T01:40:00Z" ).toEpochMilli();

    @Test
    void statusVariation_CompletelyDisabled() {
        check( createCompletelyDisabled( now15_123456 ), // Example of Rate Limiting completely Disabled!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  }",
               "}" );
    }

    @Test
    void statusVariation_WithLocalFileOnly() {
        check( createInitialFileOnlySuccess( now15_123456 ),
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:56Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 9",
               "  },",
               "  'update' : {",
               "    'status' : 'DISABLED'",
               "  },",
               "  'fromSource' : 'Local Config File'",
               "}" );

        check( createInitialFileOnlyError( now15_123456 ),
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z',",
               "    'error' : 'someError'",
               "  },",
               "  'update' : {",
               "    'status' : 'DISABLED'",
               "  },",
               "  'fromSource' : 'Local Config File'",
               "}" );
    }

    @Test
    void statusVariation_WithDynamicURLUpdateOnly() {
        RateLimiterStatus status = createInitialUrlBased( now15_123456 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", () -> now16_012345 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", () -> now16_012500 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
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

        status = status.updateFailed( "someError", () -> now16_013000 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
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

        status = status.updateFailed( "otherError", () -> now16_013500 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed with different error!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '2011-01-15T12:34:56Z'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:35:00Z',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        check( updateSucceeded( status, now16_014000 ), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-16T01:40:00Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 9",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
    }

    @Test
    void statusVariation_WithLocalFile_AND_WithDynamicURLUpdate() {
        RateLimiterStatus status = createInitialFile_AND_UrlBased( now15_123450 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:50Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", () -> now16_012345 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:50Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", () -> now16_012500 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:50Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 2",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", () -> now16_013000 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:50Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:23:45Z',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 3",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "otherError", () -> now16_013500 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed with different error!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-15T12:34:50Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '2011-01-16T01:35:00Z',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        check( updateSucceeded( status, now16_014000 ), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '2011-01-16T01:40:00Z',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 9",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );
    }

    private RateLimiterStatus createCompletelyDisabled( long asOf ) {
        return RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.DISABLED )
                                  .asOf( asOf )
                                  .build() )
                .build();
    }

    RateLimiterStatus createInitialFileOnlySuccess( long asOf ) {
        return RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.ACTIVE )
                                  .asOf( asOf )
                                  .credentialIdExtractor( "JWT[1]" )
                                  .loggingLevel( "OnlyLimited" )
                                  .limiterMappings( 9 )
                                  .build() )
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.DISABLED )
                                 .build() )
                .fromSource( "Local Config File" )
                .build();
    }

    RateLimiterStatus createInitialFileOnlyError( long asOf ) {
        return RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.DISABLED )
                                  .asOf( asOf )
                                  .error( "someError" )
                                  .build() )
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.DISABLED )
                                 .build() )
                .fromSource( "Local Config File" )
                .build();
    }

    private RateLimiterStatus createInitialUrlBased( long asOf ) {
        return RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.DISABLED )
                                  .asOf( asOf )
                                  .build() )
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.PENDING )
                                 .build() )
                .fromSource( "https://github.com/xyz/main/RateLimiters.yaml" )
                .build();
    }

    private RateLimiterStatus createInitialFile_AND_UrlBased( long asOf ) {
        return RateLimiterStatus.builder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.ACTIVE )
                                  .asOf( asOf )
                                  .credentialIdExtractor( "JWT[1]" )
                                  .loggingLevel( "OnlyLimited" )
                                  .limiterMappings( 8 )
                                  .build() )
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.PENDING )
                                 .build() )
                .fromSource( "https://github.com/xyz/main/RateLimiters.yaml" )
                .build();
    }

    private RateLimiterStatus updateSucceeded( RateLimiterStatus status, long asOf ) {
        return status.toBuilder()
                .current( RateLimiterStatus.Current.builder()
                                  .status( RateLimiterStatus.CurrentStatus.ACTIVE )
                                  .asOf( asOf )
                                  .credentialIdExtractor( "JWT[1]" )
                                  .loggingLevel( "OnlyLimited" )
                                  .limiterMappings( 9 )
                                  .build() )
                .update( RateLimiterStatus.Update.builder()
                                 .status( RateLimiterStatus.UpdateStatus.PENDING )
                                 .build() )
                .build();
    }

    @Test
    void checkTimestampTruncation() {
        String now = RateLimiterStatus.toISO8601ZtoSec( System.currentTimeMillis() );
        assertEquals( 20, now.length(), now );
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