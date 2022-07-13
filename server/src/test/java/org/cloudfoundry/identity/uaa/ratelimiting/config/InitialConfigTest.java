package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.List;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.util.SourcedFile;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InitialConfigTest {
    public static final String SAMPLE_RATE_LIMITER_CONFIG_FILE =
            "dynamicConfigUrl: urlGoesHere\n" +
            "\n" +
            "loggingOption: AllCallsWithDetails\n" +
            "# loggingOption: AllCalls\n" +
            "# loggingOption: OnlyLimited\n" +
            "# OnlyLimited is the default\n" +
            "\n" +
            "credentialID: 'JWTjsonField:Claims:email'\n" +
            "\n" +
            "limiterMappings:\n" +
            "  - name: Info\n" +
            "    withCallerRemoteAddressID: 1r/s\n" +
            "    pathSelectors:\n" +
            "      - 'equals:/info'\n" +
            "  - name: Authenticate\n" +
            "    withCallerRemoteAddressID: 5r/s\n" +
            "    pathSelectors:\n" +
            "      - 'equals:/authenticate'\n" +
            "";

    private static final String EMPTY_LEADING_DOCS = "\n" +
                                                     "---\n" +
                                                     "---\n";

    @Test
    void create() {
        InitialConfig ic = InitialConfig.create();
        assertNotNull( ic );
        System.out.println( "InitialConfigTest.create, RateLimitingEnabled: " + ic.isRateLimitingEnabled() );
    }

    @Test
    void getLocalConfigDirs() {
        String[] results = InitialConfig.getLocalConfigDirs( List.of("", "  Fred", "! ", "  "), s -> s.startsWith( "!" ) ? s.substring( 1 ) : s);
        assertNotNull( results );
        assertEquals( 1, results.length );
        assertEquals( "Fred", results[0] );
    }

    @Test
    void clean() {
        assertNull( InitialConfig.clean( null ) );
        assertNull( InitialConfig.clean( new SourcedFile( EMPTY_LEADING_DOCS, "test-1" ) ) );
        check( SAMPLE_RATE_LIMITER_CONFIG_FILE, "test-2", SAMPLE_RATE_LIMITER_CONFIG_FILE );
        check( SAMPLE_RATE_LIMITER_CONFIG_FILE, "test-3", EMPTY_LEADING_DOCS + SAMPLE_RATE_LIMITER_CONFIG_FILE );
    }

    @SuppressWarnings("SameParameterValue")
    private void check( String expectedBody, String source, String possiblyDirtyBody ) {
        SourcedFile sourcedFile = InitialConfig.clean( new SourcedFile( possiblyDirtyBody, source ) );
        assertNotNull( sourcedFile, source );
        assertEquals( source, sourcedFile.getSource() );
        assertEquals( expectedBody, sourcedFile.getBody(), source );
    }

    @Test
    void parseFile() {
        BindYaml<InitialConfig.ExtendedYamlConfigFileDTO> bindYaml = new BindYaml<>( InitialConfig.ExtendedYamlConfigFileDTO.class, "test" );
        InitialConfig.ExtendedYamlConfigFileDTO dto = InitialConfig.parseFile( bindYaml, SAMPLE_RATE_LIMITER_CONFIG_FILE );
        assertEquals( dto.toString(), SAMPLE_RATE_LIMITER_CONFIG_FILE_ROUND_TRIPPED_THRU_SNAKE_YAML );

        try {
            dto = InitialConfig.parseFile( bindYaml, "BadField" + SAMPLE_RATE_LIMITER_CONFIG_FILE );
            fail( "expected Exception, but got dto: " + dto );
        }
        catch ( YamlRateLimitingConfigException expected ) {
            String msg = expected.getMessage();
            assertTrue( msg.contains( "BadFielddynamicConfigUrl" ), () -> "msg was: " + msg );
        }
    }

    private static final String SAMPLE_RATE_LIMITER_CONFIG_FILE_ROUND_TRIPPED_THRU_SNAKE_YAML =
            "!!org.cloudfoundry.identity.uaa.ratelimiting.config.InitialConfig$ExtendedYamlConfigFileDTO\n"
            + "credentialID: JWTjsonField:Claims:email\n"
            + "dynamicConfigUrl: urlGoesHere\n"
            + "limiterMappings:\n"
            + "- global: null\n"
            + "  name: Info\n"
            + "  pathSelectors: ['equals:/info']\n"
            + "  withCallerCredentialsID: null\n"
            + "  withCallerRemoteAddressID: 1r/s\n"
            + "  withoutCallerID: null\n"
            + "- global: null\n"
            + "  name: Authenticate\n"
            + "  pathSelectors: ['equals:/authenticate']\n"
            + "  withCallerCredentialsID: null\n"
            + "  withCallerRemoteAddressID: 5r/s\n"
            + "  withoutCallerID: null\n"
            + "loggingOption: AllCallsWithDetails\n";
}