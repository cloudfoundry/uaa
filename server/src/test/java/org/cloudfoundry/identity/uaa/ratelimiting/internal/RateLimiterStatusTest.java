package org.cloudfoundry.identity.uaa.ratelimiting.internal;

import java.time.Instant;
import java.util.LinkedHashMap;
import javax.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"SameParameterValue", "UnnecessaryLocalVariable"})
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
        check( createCompletelyDisabled( now15_123456 ), false, // Example of Rate Limiting completely Disabled!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( now15_123456 ) + "'",
               "  }",
               "}" );
    }

    @Test
    void statusVariation_WithLocalFileOnly() {
        check( createInitialFileOnlySuccess( now15_123456 ),
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( now15_123456 ) + "',",
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
               "    'asOf' : '" + toISO( now15_123456 ) + "',",
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
        long time1 = now15_123456; // Times for time based sequence
        long time2 = now16_012345;
        long time3 = now16_012500;
        long time4 = now16_013000;
        long time5 = now16_013500;
        long time6 = now16_014000;

        RateLimiterStatus status = createInitialUrlBased( time1 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time2 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time3 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 2",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time4 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 3",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "otherError", time5 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed with different error!
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time5 ) + "',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        check( updateSucceeded( status, time6 ), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time6 ) + "',",
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
        long time1 = now15_123450; // Times for time based sequence
        long time2 = now16_012345;
        long time3 = now16_012500;
        long time4 = now16_013000;
        long time5 = now16_013500;
        long time6 = now16_014000;

        RateLimiterStatus status = createInitialFile_AND_UrlBased( time1 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time2 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time3 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 2",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "someError", time4 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed again!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'someError',",
               "    'checkCountOfStatus' : 3",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        status = status.updateFailed( "otherError", time5 );
        check( status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and update failed with different error!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT[1]',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 8",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time5 ) + "',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
               "}" );

        check( updateSucceeded( status, time6 ), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time6 ) + "',",
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
    void check_create_AND_update() {
        long time1 = now16_012345; // Times for time based sequence
        long time2 = now16_012500;
        long time3 = now16_013000;
        long time4 = now16_013500;
        long time5 = now16_014000;

        // Scenario 1
        RateLimiterStatus status = RateLimiterStatus.create( InternalLimiterFactoriesSupplier.NOOP, null, time1, "test", false );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'DISABLED'",
               "  },",
               "  'fromSource' : 'test'",
               "}" );
        status = RateLimiterStatus.create( InternalLimiterFactoriesSupplier.NOOP, null, time1, "test", true );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'test'",
               "}" );
        status = status.update( "Kaboom", time2, "aURL" );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'Kaboom'",
               "  },",
               "  'fromSource' : 'aURL'",
               "}" );
        status = status.update( "Kaboom", time3, "aURL" );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time2 ) + "',",
               "    'error' : 'Kaboom',",
               "    'checkCountOfStatus' : 2",
               "  },",
               "  'fromSource' : 'aURL'",
               "}" );
        status = status.update( "otherError", time4, "aURL" );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'FAILED',",
               "    'asOf' : '" + toISO( time4 ) + "',",
               "    'error' : 'otherError'",
               "  },",
               "  'fromSource' : 'aURL'",
               "}" );
        status = status.update( null, time5, "aURL" );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time1 ) + "'",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING',",
               "    'asOf' : '" + toISO( time5 ) + "'",
               "  },",
               "  'fromSource' : 'aURL'",
               "}" );

        InternalLimiterFactoriesSupplier mockSupplier = new InternalLimiterFactoriesSupplier() {
            @Override
            public LinkedHashMap<CompoundKey, InternalLimiterFactory> factoryMapFor( RequestInfo info ) {
                throw new IllegalStateException( "Not Implemented" );
            }

            @Override
            public @NotNull LoggingOption getLoggingOption() {
                return LoggingOption.DEFAULT;
            }

            @Override
            public boolean isSupplierNOOP() {
                return false;
            }

            @Override
            public String getCallerCredentialsIdSupplierDescription() {
                return "JWT";
            }

            @Override
            public int getLimiterMappings() {
                return 1;
            }
        };

        // Scenario 2
        status = RateLimiterStatus.create( mockSupplier, null, time1, "test", true );
        check( status,
               "{",
               "  'current' : {",
               "    'status' : 'ACTIVE',",
               "    'asOf' : '" + toISO( time1 ) + "',",
               "    'credentialIdExtractor' : 'JWT',",
               "    'loggingLevel' : 'OnlyLimited',",
               "    'limiterMappings' : 1",
               "  },",
               "  'update' : {",
               "    'status' : 'PENDING'",
               "  },",
               "  'fromSource' : 'test'",
               "}" );
    }

    @Test
    void check_noRateLimiting() {
        check( RateLimiterStatus.noRateLimiting( now15_123456 ), false,
               "{",
               "  'current' : {",
               "    'status' : 'DISABLED',",
               "    'asOf' : '" + toISO( now15_123456 ) + "'",
               "  }",
               "}" );
    }

    @Test
    void check_toISO8601ZtoSec_Truncation() {
        String now = RateLimiterStatus.toISO8601ZtoSec( System.currentTimeMillis() );
        assertEquals( 20, now.length(), now );
    }

    private void check( RateLimiterStatus status, String... expected ) {
        check( status, true, expected );
    }

    private void check( RateLimiterStatus status, boolean shouldHaveUpdateSection, String... expected ) {
        assertTrue( status.hasCurrentSection() );
        assertEquals( shouldHaveUpdateSection, status.hasUpdateSection() );
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

    private static String toISO( long time ) {
        return RateLimiterStatus.toISO8601ZtoSec( time );
    }
}