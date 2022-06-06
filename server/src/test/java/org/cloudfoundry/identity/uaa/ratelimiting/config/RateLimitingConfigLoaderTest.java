package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.cloudfoundry.identity.uaa.ratelimiting.AbstractExceptionTestSupport;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByTypeFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.InternalLimiterFactoriesSupplierImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.yaml.snakeyaml.constructor.ConstructorException;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;
import static org.cloudfoundry.identity.uaa.ratelimiting.internal.common.CallerIdSupplierByTypeFactoryFactory.FactoryWithCredentialIdExtractor;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class RateLimitingConfigLoaderTest extends AbstractExceptionTestSupport {
    private static class SupplierUpdatable implements LimiterFactorySupplierUpdatable {
        InternalLimiterFactoriesSupplierImpl lfs;

        @Override
        public void update( InternalLimiterFactoriesSupplier factoriesSupplier ) {
            if ( factoriesSupplier instanceof InternalLimiterFactoriesSupplierImpl ) {
                lfs = (InternalLimiterFactoriesSupplierImpl)factoriesSupplier;
                return;
            }
            throw new Error( (factoriesSupplier == null) ? "No FactoriesSupplier" : "FactoriesSupplier class: " + factoriesSupplier.getClass().getSimpleName() );
        }
    }

    MillisTimeSupplier currentTimeSupplier = new MillisTimeSupplier.Mock();

    LoaderLogger logger = Mockito.mock( LoaderLogger.class );

    Fetcher fetcher = Mockito.mock( Fetcher.class );

    SupplierUpdatable supplierUpdatable = new SupplierUpdatable();

    private RateLimitingConfigLoader createLoader( CredentialIdType... credentialIdTypes ) {
        return new RateLimitingConfigLoader( logger, fetcher, supplierUpdatable,
                                             currentTimeSupplier, true,
                                             credentialIdTypes );
    }

    private void expectSuccess( int typePropertiesPathOptions, CredentialIdType... credentialIdTypesArray ) {
        RateLimitingConfigLoader loader = createLoader( credentialIdTypesArray );
        boolean updated = loader.checkForUpdatedProperties();
        assertTrue( updated );
        InternalLimiterFactoriesSupplierImpl lfs = supplierUpdatable.lfs;
        assertNotNull( lfs, "InternalLimiterFactoriesSupplierImpl" );
        assertEquals( typePropertiesPathOptions, lfs.typePropertiesPathOptionsCount(), "TypePropertiesPathOptions" );

        CallerIdSupplierByTypeFactory factory = lfs.callerIdSupplierByTypeFactory;
        assertNotNull( factory, "CallerIdSupplierByTypeMapper" );

        AuthorizationCredentialIdExtractor extractor = !(factory instanceof FactoryWithCredentialIdExtractor) ? null :
                                                       ((FactoryWithCredentialIdExtractor)factory).credentialIdExtractor;
        if ( loader.hasCredentialIdTypes() ) {
            assertNotNull( extractor, "AuthorizationCredentialIdExtractor" );
        } else {
            assertNull( extractor, "AuthorizationCredentialIdExtractor" );
        }
    }

    @Test
    void checkForUpdatedPropertiesHappyCaseNoDocSeps()
            throws Exception {
        String[] yaml = { // No "c-directives-end"s (document sep)
                          "name: ALL",
                          "global: 150r/s",
                          "pathSelectors:",
                          " - 'all'",
                          ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 1 ); // just the All!
    }

    @Test
    void checkForUpdatedPropertiesHappyCaseExtraDocSeps()
            throws Exception {
        String[] yaml = { // Extra "c-directives-end"s (document sep)
                          "---",
                          "name: ALL",
                          "global: 150r/s",
                          "pathSelectors:",
                          " - 'all'",
                          "---",
                          ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 1 ); // just the All!
    }

    @Test
    void checkForUpdatedPropertiesHappyCaseManyDocs()
            throws Exception {
        String[] yaml = {
                "---",
                "name: Info",
                "global: 50r/s",
                "withCallerRemoteAddressID: 2r/s",
                "withoutCallerID: 4r/s",
                "pathSelectors:",
                "- 'equals:/info'",
                "---",
                "name: Authenticate",
                "global: 50r/s",
                "withCallerRemoteAddressID: 5r/s",
                "withoutCallerID: 10r/s",
                "pathSelectors:",
                "- 'equals:/authenticate'",
                "---",
                "name: AuthToken",
                "global: 50r/s",
                "withCallerRemoteAddressID: 2r/s",
                "withoutCallerID: 4r/s",
                "pathSelectors:",
                "- 'equals:/oauth/token'",
                "---",
                "name: AuthAuthorize",
                "global: 25r/s",
                "withCallerRemoteAddressID: 1r/s",
                "withoutCallerID: 2r/s",
                "pathSelectors:",
                "- 'equals:/oauth/authorize'",
                "---",
                "name: LoginPage",
                "withCallerRemoteAddressID: 3r/3s",
                "withoutCallerID: 2r/s",
                "global: 25r/s",
                "pathSelectors:",
                "- 'equals:/login'",
                "---",
                "name: LoginResource",
                "global: 150r/s",
                "withCallerRemoteAddressID: 12r/3s",
                "withoutCallerID: 6r/s",
                "pathSelectors:",
                "- 'startsWith:/resources/'",
                "- 'startsWith:/vendor/'",
                "---",
                "name: LoginDo",
                "global: 25r/s",
                "withCallerRemoteAddressID: 1r/s",
                "withoutCallerID: 2r/s",
                "pathSelectors:",
                "- 'equals:/login.do'",
                "---",
                "name: EverythingElse",
                "global: 250r/s",
                "withCallerCredentialsID: 50r/s",
                "withCallerRemoteAddressID: 50r/s",
                "withoutCallerID: 25r/s",
                "pathSelectors:",
                "- 'other'",
                "---",
                "name: ALL",
                "global: 1000r/s",
                "withCallerCredentialsID: 80r/s",
                "withCallerRemoteAddressID: 80r/s",
                "withoutCallerID: 35r/s",
                "pathSelectors:",
                "- 'all'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 10 ); // "other" and "all" in config
    }

    @Test
    void checkForHappyCaseJWT()
            throws Exception {
        String[] yaml = {
                "credentialID: JWT",
                "---",
                "name: All",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'all'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 1, new CredentialIdTypeJWT() );
    }

    @Test
    void checkForHappyCaseJWTsection()
            throws Exception {
        String[] yaml = {
                "credentialID: JWT:payload",
                "---",
                "name: All",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'all'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 1, new CredentialIdTypeJWT() );
    }

    @Test
    void checkForHappyCaseJWTregex()
            throws Exception {
        String[] yaml = {
                "credentialID: 'JWT:Claims+\"email\": *\"(.*?)\"'",
                "---",
                "name: All",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'all'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectSuccess( 1, new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_BadCredentialIDFormat1()
            throws Exception {
        String[] yaml = {
                "credentialID: JWT:-1",
                "---",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Unrecognized JWT section reference ", new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_BadCredentialIDFormat2()
            throws Exception {
        String[] yaml = {
                "credentialID: ':-1'",
                "---",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Empty key from: ", new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_TwoCredentialIDs()
            throws Exception {
        String[] yaml = {
                "credentialID: 'JWT'",
                "---",
                "credentialID: 'JWT'",
                "---",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[1] Second 'credentialID' (key == 'JWT')", new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_BadCredentialIdKey()
            throws Exception {
        String[] yaml = {
                "credentialID: '!JWT'",
                "---",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] 'credentialID' (key == '!JWT') not found, ", new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_BothLimitsAndCredentialID()
            throws Exception {
        String[] yaml = {
                "---",
                "credentialID: JWT",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[1] Contained both a 'limiter' (name == 'Info') and a 'credentialID' (key == 'JWT')", new CredentialIdTypeJWT() );
    }

    @Test
    void checkForUpdatedPropertiesException_IOException()
            throws Exception {

        when( fetcher.fetchYaml() ).thenThrow( new FileNotFoundException( "File Not Found" ) );
        expectException( RateLimitingConfigLoader.YAML_FETCH_FAILED, IOException.class );
    }

    @Test
    void checkForUpdatedPropertiesException_None_null()
            throws Exception {

        when( fetcher.fetchYaml() ).thenReturn( null );
        expectException( RateLimitingConfigLoader.YAML_NULL );
    }

    @Test
    void checkForUpdatedPropertiesException_None_empty()
            throws Exception {

        when( fetcher.fetchYaml() ).thenReturn( "" );
        expectException( RateLimitingConfigLoader.YAML_EMPTY );
    }

    @Test
    void checkForUpdatedPropertiesException_BadFormat_global()
            throws Exception {
        String[] yaml = {
                "name: PebblesBirthDate",
                "global: 15r/m",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Unacceptable format, " );
    }

    @Test
    void checkForUpdatedPropertiesException_BadData_WindowSecs()
            throws Exception {
        String[] yaml = {
                "name: PebblesBirthDate",
                "global: 150r/3600s",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Window seconds " );
    }

    @Test
    void checkForUpdatedPropertiesException_BadData()
            throws Exception {
        String[] yaml = {
                "---",
                "name: Info",
                "windowSecs: 1",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[1] did not bind to 'YamlConfigDTO'", ConstructorException.class );
    }

    @Test
    void checkForUpdatedPropertiesException_BadData_NoPathSelector()
            throws Exception {
        String[] yaml = {
                "---",
                "name: Info",
                "global: 15r/s",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[1] No pathSelectors " );
    }

    @Test
    void checkForUpdatedPropertiesException_BadData_NoLimits()
            throws Exception {
        String[] yaml = {
                "---",
                "name: Info",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[1] No limits " );
    }

    @Test
    void checkForUpdatedPropertiesException_BadPathSelector()
            throws Exception {
        String[] yaml = {
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:info'", // no leading '/'
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Info's PathSelector[0] 'path' ('info' in 'equals:info') - must start with " );
    }

    @Test
    void checkForUpdatedPropertiesException_BadPathMatchType()
            throws Exception {
        String[] yaml = {
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - '!equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] Info's PathSelector[0] 'type' ('!equals' " );
    }

    @Test
    void checkForUpdatedPropertiesException_NoName()
            throws Exception {
        String[] yaml = {
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( "document[0] " + YamlConfigDTO.NO_NAME_PROVIDED );
    }

    @Test
    void checkForUpdatedPropertiesException_ConflictingData()
            throws Exception {
        String[] yaml = {
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/info'",
                "---",
                "name: Info",
                "global: 150r/s",
                "pathSelectors:",
                "  - 'equals:/authenticate'",
                ""
        };

        when( fetcher.fetchYaml() ).thenReturn( String.join( "\n", yaml ) );
        expectException( RateLimitingConfigLoader.TYPE_PROPERTIES_PROBLEM, RateLimitingConfigException.class );
    }

    private void expectException( String expectedMessageOrPrefix, CredentialIdType... credentialIdTypesArray ) {
        expectException( expectedMessageOrPrefix, null, credentialIdTypesArray );
    }

    private void expectException( String expectedMessageOrPrefix, Class<?> expectedExceptionCauseClass, CredentialIdType... credentialIdTypesArray ) {
        RateLimitingConfigLoader loader = createLoader( credentialIdTypesArray );
        expectException( "Yaml " + expectedMessageOrPrefix, expectedExceptionCauseClass, loader::checkForUpdatedProperties );
    }
}