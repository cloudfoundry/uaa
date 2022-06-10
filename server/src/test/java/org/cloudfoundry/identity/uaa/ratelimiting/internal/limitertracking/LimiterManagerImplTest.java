package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.TypeProperties;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LimiterManagerImplTest {

    static final List<TypeProperties> allAndPathBasedTypePropertiesList = List.of(
            TypeProperties.builder().name( "F1" ).pathSelector( "equals:/F1" ).withCallerCredentialsID( "2r/s" ).build(),
            TypeProperties.builder().name( "F2" ).pathSelector( "equals:/F2" ).withCallerCredentialsID( "4r/2s" ).build(),
            TypeProperties.builder().name( "F3" ).pathSelector( "equals:/F3" ).global( "8r/4s" ).build(),
            TypeProperties.builder().name( "GB" ).pathSelector( "All" ).global( "74r/8s" ).build() );

    private void allAndPathBasedCalls() {
        call( "/F1", "K1" );
        call( "/F1", "K2" );
        call( "/F2", "K1" );
        call( "/F2", "K2" );
        call( "/F3", "??" );
    }

    // The combinatorics of the above should generate the following results. As the "All" InternalLimiter is only called
    // if the non-All (which is called first) doesn't limit, the "All" InternalLimiter is not directly shown below.
    // The "All" InternalLimiter is reflected in the results below starting at time '6.750' secs for "F2" and "K1"!
    private void allAndPathBasedCheckResults() {
        assertEquals( 6, instanceTracking.size() ); // 5 plus the GBs
        // . .  0...1...2...3...4...5...6...7...8 seconds with calls every 250ms
        check( "NFLLNFLLNFLLNFLLNFLLNFLLNFLLnLLL", "F1", "K1" );
        check( "NFLLNFLLNFLLNFLLNFLLNFLLNFLLnLLL", "F1", "K2" );
        check( "NFFFLLLLNFFFLLLLNFFFLLLLNFFLLLLL", "F2", "K1" );
        check( "NFFFLLLLNFFFLLLLNFFFLLLLNFFLLLLL", "F2", "K2" );
        check( "NFFFFFFFLLLLLLLLNFFFFFFFLLLLLLLL", "F3", WindowType.GLOBAL.cannedCallerID() );
    }

    @Test
    void testInteractionOfAllAndPathBasedLimiter() {
        runSet( allAndPathBasedTypePropertiesList,
                this::allAndPathBasedCalls,
                this::allAndPathBasedCheckResults );
    }

    static final List<TypeProperties> interactionOfMultiPathBasedTypePropertiesList = List.of(
            TypeProperties.builder().name( "FF" ).pathSelectors( "equals:/F1", "equals:/F2" ).withCallerCredentialsID( "4r/s" ).build(),
            TypeProperties.builder().name( "GB" ).pathSelector( "All" ).global( "999r/8s" ).build() ); // So can ignore

    private void interactionOfMultiPathBasedCalls() {
        call( "/F1", "K1" ); // first two calls should count against the same Limiter/CallerID (FF & K1)
        call( "/F2", "K1" );
        call( "/F1", "K2" ); // last two calls should count against the same Limiter/CallerID (FF & K2)
        call( "/F2", "K2" );
    }

    // The combinatorics of the above should generate the following results. As the "All" InternalLimiter is only called
    // if the non-All (which is called first) doesn't limit, the "All" InternalLimiter is not directly shown below.
    // The "All" InternalLimiter is NOT reflected in the results below as its limit is never reached!
    private void interactionOfMultiPathBasedCheckResults() {
        assertEquals( 3, instanceTracking.size() ); // 2 plus the GBs
        // . .  0 . . . 1 . . . 2 . . . 3 . . . 4 . . . 5 . . . 6 . . . 7 . . . 8 seconds with TWO calls every 250ms
        check( "NFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLL", "FF", "K1" );
        check( "NFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLLNFFFLLLL", "FF", "K2" );
    }

    @Test
    void testInteractionOfMultiPathSelectorLimiter() {
        runSet( interactionOfMultiPathBasedTypePropertiesList,
                this::interactionOfMultiPathBasedCalls,
                this::interactionOfMultiPathBasedCheckResults );
    }

    void runSet( List<TypeProperties> typePropertiesList, Runnable calls, Runnable checkResults ) {
        lm.update( new InternalLimiterFactoriesSupplierImpl( credentialIdExtractor, null, typePropertiesList ) );
        for ( int i = 0; i < 8; i++ ) {
            for ( int j = 0; j < 4; j++ ) {
                calls.run();
                mTS.add( 250 );
                lm.processExpirations();
            }
        }
        checkResults.run();
    }

    MillisTimeSupplier.Mock mTS = new MillisTimeSupplier.Mock( Instant.parse( "2000-01-01T00:00:00Z" ) );

    LimiterManagerImpl lm = new LimiterManagerImpl( mTS );

    MultiValueMap<String, Character> results = new LinkedMultiValueMap<>();

    Map<CompoundKey, InternalLimiter> instanceTracking = new LinkedHashMap<>();

    private void record( List<InternalLimiter> iLimiters ) {
        boolean limit = LimiterImpl.from( iLimiters, LoggingOption.DEFAULT ).shouldLimit();
        for ( InternalLimiter currentLimiter : iLimiters ) {
            CompoundKey compoundKey = currentLimiter.getCompoundKey();
            String resultsKey = resultsKey( compoundKey );
            boolean isNew = (currentLimiter != instanceTracking.get( compoundKey ));
            if ( isNew ) {
                instanceTracking.put( compoundKey, currentLimiter );
                results.add( resultsKey, limit ? 'n' : 'N' );
            } else {
                results.add( resultsKey, limit ? 'L' : 'F' );
            }
        }
    }

    String callerID;
    String servletPath;

    AuthorizationCredentialIdExtractor credentialIdExtractor = ( info ) -> callerID;

    RequestInfo requestInfo = new RequestInfo() {
        @Override
        public String getClientIP() {
            return null;
        }

        @Override
        public String getAuthorizationHeader() {
            return "whatever";
        }

        @Override
        public String getServletPath() {
            return servletPath;
        }
    };

    private void call( String servletPath, String callerID ) {
        this.servletPath = servletPath;
        this.callerID = callerID;
        record( lm.generateLimiterList( requestInfo, lm.getFactorySupplier() ) );
    }

    private void check( String expectedResult, String limiterName, String callerID ) {
        String instanceKey = resultsKey( limiterName, callerID );
        String actualResult = compress( results.get( instanceKey ) );
        assertEquals( expectedResult, actualResult, instanceKey );
    }

    private static String compress( List<Character> chars ) {
        StringBuilder sb = new StringBuilder( chars.size() );
        for ( Character chr : chars ) {
            sb.append( chr );
        }
        return sb.toString();
    }

    static String resultsKey( String limiterName, String callerID ) {
        return limiterName + "|" + callerID;
    }

    static String resultsKey( CompoundKey compoundKey ) {
        return resultsKey( compoundKey.getLimiterName(), compoundKey.getCallerID() );
    }
}