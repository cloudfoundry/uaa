package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.List;
import java.util.function.Function;

import org.cloudfoundry.identity.uaa.ratelimiting.AbstractExceptionTestSupport;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWTjsonField;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.LimiterMap;
import static org.junit.jupiter.api.Assertions.*;

public class RateLimitingConfigMapperTest extends AbstractExceptionTestSupport {
    public static final LimiterMap LIMITER_MAP_All_all = LimiterMap.builder().name( "All" ).global( "1r/s" ).pathSelectors( List.of( "all" ) ).build();
    public static final LimiterMap LIMITER_MAP_AAA_all = LimiterMap.builder().name( "AAA" ).withCallerCredentialsID( "1r/s" ).pathSelectors( List.of( "all" ) ).build();
    public static final LimiterMap LIMITER_MAP_AAA_other = LimiterMap.builder().name( "AAA" ).withCallerRemoteAddressID( "1r/s" ).pathSelectors( List.of( "other" ) ).build();
    public static final LimiterMap LIMITER_MAP_All_other = LimiterMap.builder().name( "All" ).withoutCallerID( "1r/s" ).pathSelectors( List.of( "other" ) ).build();
    public static final LimiterMap LIMITER_MAP_AAA_badPath = LimiterMap.builder().name( "AAA" ).global( "1r/s" ).pathSelectors( List.of( "equals" ) ).build();
    static final List<LimiterMap> MINIMAL_LIMITER_MAPPINGS = List.of( LIMITER_MAP_All_all );
    static final YamlConfigFileDTO MINIMAL_DTO = YamlConfigFileDTO.builder().limiterMappings( MINIMAL_LIMITER_MAPPINGS ).build();
    static final YamlConfigFileDTO EMPTY_DTO = new YamlConfigFileDTO();

    MillisTimeSupplier currentTimeSupplier = new MillisTimeSupplier.Mock();

    private RateLimitingConfigMapper createMapper( CredentialIdType... credentialIdTypes ) {
        return new RateLimitingConfigMapper( true, currentTimeSupplier, credentialIdTypes );
    }

    @Test
    void checkForCredentialIdTypes() {
        assertEquals( 0, new RateLimitingConfigMapper( true ).getCredentialIdTypeCount() );
        assertEquals( 1, new RateLimitingConfigMapper( true, new CredentialIdTypeJWT( null ) ).getCredentialIdTypeCount() );
        assertEquals( 2, new RateLimitingConfigMapper( true, new CredentialIdTypeJWT( null ), new CredentialIdTypeJWTjsonField( null ) ).getCredentialIdTypeCount() );
    }

    @Test
    void check_map_and_checkNoChange() {
        RateLimitingConfigMapper mapper = createMapper();
        assertNull( mapper.dtoPrevious );
        assertTrue( mapper.checkNoChange( null ) );
        assertNull( mapper.dtoPrevious );
        assertFalse( mapper.checkNoChange( EMPTY_DTO ) );
        assertEquals( EMPTY_DTO, mapper.dtoPrevious ); // cache Updated!
        assertTrue( mapper.checkNoChange( EMPTY_DTO ) );
        assertEquals( EMPTY_DTO, mapper.dtoPrevious );

        assertNull( mapper.map( null, "test", null ) );
        assertNull( mapper.map( null, "test", EMPTY_DTO ) );
        assertNotNull( mapper.map( null, "test", MINIMAL_DTO ) );
    }

    @Test
    void check_createSupplier_and_createErrorSupplierPair() {
        RateLimitingConfigMapper mapper = createMapper();

        InternalLimiterFactoriesSupplier supplier = mapper.createSupplier( MINIMAL_DTO );
        assertNotNull( supplier );
        assertEquivalent( supplier, null, mapper.createErrorSupplierPair( MINIMAL_DTO ) );

        try {
            supplier = mapper.createSupplier( EMPTY_DTO );
            fail( "Expected Exception, but got supplier: " + supplier );
        }
        catch ( Exception e ) {
            assertEquivalent( InternalLimiterFactoriesSupplier.NOOP, e, mapper.createErrorSupplierPair( EMPTY_DTO ) );
        }
    }

    private void assertEquivalent( InternalLimiterFactoriesSupplier supplier, Exception error, ErrorSupplierPair pair ) {
        assertEquivalentStrings( "error", error, pair.getError(), Exception::getMessage );
        assertEquivalentStrings( "supplier", supplier, pair.getSupplier(), InternalLimiterFactoriesSupplier::toString );
    }

    private <T> void assertEquivalentStrings( String what, T expected, T actual, Function<T, String> toString ) {
        if ( expected != actual ) {
            if ( expected == null ) {
                fail( "Expected null, but actual " + what + " was: " + toString.apply( actual ) );
            } else if ( actual == null ) {
                fail( "Actual " + what + " was null, but expected: " + toString.apply( expected ) );
            } else { // Neither 'null'
                String expectedStr = toString.apply( expected );
                String actualStr = toString.apply( actual );
                assertEquals( expectedStr, actualStr, what + "s" );
            }
        }
    }

    @Test
    void checkForHappyCases() {
        RateLimitingConfigMapper mapper = createMapper( new CredentialIdTypeJWT( null ) );
        assertSupplier( false, LoggingOption.DEFAULT, 1, mapper, MINIMAL_DTO );
        assertSupplier( false, LoggingOption.AllCalls, 1, mapper,
                        YamlConfigFileDTO.builder().limiterMappings( MINIMAL_LIMITER_MAPPINGS ).loggingOption( "allCalls" ).build());
        assertSupplier( true, LoggingOption.DEFAULT, 1, mapper,
                        YamlConfigFileDTO.builder().limiterMappings( MINIMAL_LIMITER_MAPPINGS ).credentialID( "JWT:claims" ).build());
        assertSupplier( false, LoggingOption.DEFAULT, 2, mapper,
                        YamlConfigFileDTO.builder().limiterMappings( List.of( LIMITER_MAP_All_all, LIMITER_MAP_AAA_other ) ).build());
    }

    private void assertSupplier( boolean hasCallerCredentialsIdSupplierDescription, LoggingOption loggingOption, int mappings,
                                 RateLimitingConfigMapper mapper, YamlConfigFileDTO dto ) {
        InternalLimiterFactoriesSupplier supplier = mapper.createSupplier( dto );
        assertEquals( mappings, supplier.getLimiterMappings(), dto::toString );
        assertEquals( loggingOption, supplier.getLoggingOption(), dto::toString );
        String description = supplier.getCallerCredentialsIdSupplierDescription();
        if (hasCallerCredentialsIdSupplierDescription) {
            assertNotNull( description, dto::toString );
        } else  {
            assertEquals( "None", description, dto::toString );
        }
    }

//    @Test
//    void checkForHappyCaseLoggingOptionAllCalls()
//            throws Exception {
//        String[] yaml = {
//                "loggingOption: AllCalls",
//                "limiterMappings:",
//                "- name: All",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'all'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectSuccess( 1, LoggingOption.AllCalls );
//    }
//
//    @Test
//    void checkForHappyCaseLoggingOptionAllCallsWithDetails()
//            throws Exception {
//        String[] yaml = {
//                "loggingOption: AllCallsWithDetails",
//                "limiterMappings:",
//                "- name: All",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'all'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectSuccess( 1, LoggingOption.AllCallsWithDetails );
//    }
//
//    @Test
//    void checkForHappyCaseJWT()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: JWT",
//                "limiterMappings:",
//                "- name: All",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'all'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectSuccess( 1,
//                       new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForHappyCaseJWTsection()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: JWT:payload",
//                "limiterMappings:",
//                "- name: All",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'all'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectSuccess( 1,
//                       new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForHappyCaseJWTregex()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: 'JWT:Claims+\"email\": *\"(.*?)\"'",
//                "limiterMappings:",
//                "- name: All",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'all'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectSuccess( 1,
//                       new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadCredentialIDFormat1()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: JWT:-1",
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Unrecognized JWT section reference ",
//                         new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadCredentialIDFormat2()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: ':-1'",
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Empty key from: ",
//                         new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_TwoCredentialIDs()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: 'JWT'",
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                "credentialID: 'JWT'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[1] Second 'credentialID' (key == 'JWT')",
//                         new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadCredentialIdKey()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: '!JWT'",
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] 'credentialID' (key == '!JWT') not found, ",
//                         new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BothLimitsAndCredentialID()
//            throws Exception {
//        String[] yaml = {
//                "credentialID: JWT",
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[1] Contained both a 'limiter' (name == 'Info') and a 'credentialID' (key == 'JWT')",
//                         new CredentialIdTypeJWT( exceptionCollector::add ) );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_IOException()
//            throws Exception {
//
//        when( fetcher.fetchYaml() ).thenThrow( new FileNotFoundException( "File Not Found" ) );
//        expectException( RateLimitingConfigLoader.YAML_FETCH_FAILED, IOException.class );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_None_null()
//            throws Exception {
//
//        when( fetcher.fetchYaml() ).thenReturn( null );
//        expectException( RateLimitingConfigLoader.YAML_NULL );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_None_empty()
//            throws Exception {
//
//        when( fetcher.fetchYaml() ).thenReturn( "" );
//        expectException( RateLimitingConfigLoader.YAML_EMPTY );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadFormat_global()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: PebblesBirthDate",
//                "  global: 15r/m",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Unacceptable format, " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadData_WindowSecs()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: PebblesBirthDate",
//                "  global: 150r/3600s",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Window seconds " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadData()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  windowSecs: 1",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[1] did not bind to 'YamlConfigDTO'", ConstructorException.class );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadData_NoPathSelector()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 15r/s",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[1] No pathSelectors " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadData_NoLimits()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[1] No limits " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadPathSelector()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:info'", // no leading '/'
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Info's PathSelector[0] 'path' ('info' in 'equals:info') - must start with " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_BadPathMatchType()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - '!equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] Info's PathSelector[0] 'type' ('!equals' " );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_NoName()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( "document[0] " + "" ); // TODO: YamlConfigDTO.NO_NAME_PROVIDED );
//    }
//
//    @Test
//    void checkForUpdatedPropertiesException_ConflictingData()
//            throws Exception {
//        String[] yaml = {
//                "limiterMappings:",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/info'",
//                "- name: Info",
//                "  global: 150r/s",
//                "  pathSelectors:",
//                "  - 'equals:/authenticate'",
//                ""
//        };
//
//        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
//        expectException( RateLimitingConfigLoader.TYPE_PROPERTIES_PROBLEM, RateLimitingConfigException.class );
//    }
//
//    private void expectException( String expectedMessageOrPrefix, CredentialIdType... credentialIdTypesArray ) {
//        expectException( expectedMessageOrPrefix, null, credentialIdTypesArray );
//    }
//
//    private void expectException( String expectedMessageOrPrefix, Class<?> expectedExceptionCauseClass, CredentialIdType... credentialIdTypesArray ) {
//        RateLimitingConfigLoader loader = createMapper( credentialIdTypesArray ); // TODO: Fix null?
//        expectException( "Yaml " + expectedMessageOrPrefix, expectedExceptionCauseClass, loader::checkForUpdatedProperties );
//    }
}