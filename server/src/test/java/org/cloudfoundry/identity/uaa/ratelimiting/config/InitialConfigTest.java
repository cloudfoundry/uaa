package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
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
    void loadFile() {
        assertNull( InitialConfig.loadFile( null, "test-0" ) );

        assertNull( InitialConfig.loadFile( inputStringFrom( " \n" ), "test-1" ) );
        assertNull( InitialConfig.loadFile( inputStringFrom( EMPTY_LEADING_DOCS ), "test-2" ) );

        assertEquals( SAMPLE_RATE_LIMITER_CONFIG_FILE, InitialConfig.loadFile(
                inputStringFrom( EMPTY_LEADING_DOCS + SAMPLE_RATE_LIMITER_CONFIG_FILE ) , "test-3").body );
    }

    InputStream inputStringFrom( String fileContents ) {
        return new ByteArrayInputStream( fileContents.getBytes( StandardCharsets.UTF_8 ) );
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