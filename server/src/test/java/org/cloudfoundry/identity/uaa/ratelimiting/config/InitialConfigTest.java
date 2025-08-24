package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.SourcedFile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InitialConfigTest {
    public static final String SAMPLE_RATE_LIMITER_CONFIG_FILE =
            """
                    ratelimit:
                      dynamicConfigUrl: urlGoesHere
                    
                      loggingOption: AllCallsWithDetails
                      # loggingOption: AllCalls
                      # loggingOption: OnlyLimited
                      # OnlyLimited is the default
                    
                      credentialID: 'JWTjsonField:Claims:email'
                    
                      limiterMappings:
                        - name: Info
                          withCallerRemoteAddressID: 1r/s
                          pathSelectors:
                            - 'equals:/info'
                        - name: Authenticate
                          withCallerRemoteAddressID: 5r/s
                          pathSelectors:
                            - 'equals:/authenticate'
                    """;

    private static final String EMPTY_LEADING_DOCS = """
            
            ---
            ---
            """;

    @Test
    void create() {
        InitialConfig ic = InitialConfig.create();
        assertThat(ic).isNotNull();
        System.out.println("InitialConfigTest.create, RateLimitingEnabled: " + ic.isRateLimitingEnabled());
    }

    @Test
    void getLocalConfigDirs() {
        String[] results = InitialConfig.getLocalConfigDirs(List.of("", "  Fred", "! ", "  "), s -> s.startsWith("!") ? s.substring(1) : s);
        assertThat(results).isNotNull();
        assertThat(results.length).isOne();
        assertThat(results[0]).isEqualTo("Fred");
    }

    @Test
    void clean() {
        assertThat(InitialConfig.clean(null)).isNull();
        assertThat(InitialConfig.clean(new SourcedFile(EMPTY_LEADING_DOCS, "test-1"))).isNull();
        check(SAMPLE_RATE_LIMITER_CONFIG_FILE, "test-2", SAMPLE_RATE_LIMITER_CONFIG_FILE);
        check(SAMPLE_RATE_LIMITER_CONFIG_FILE, "test-3", EMPTY_LEADING_DOCS + SAMPLE_RATE_LIMITER_CONFIG_FILE);
    }

    @SuppressWarnings("SameParameterValue")
    private void check(String expectedBody, String source, String possiblyDirtyBody) {
        SourcedFile sourcedFile = InitialConfig.clean(new SourcedFile(possiblyDirtyBody, source));
        assertThat(sourcedFile).as(source).isNotNull();
        assertThat(sourcedFile.getSource()).isEqualTo(source);
        assertThat(sourcedFile.getBody()).as(source).isEqualTo(expectedBody);
    }

    @Test
    void create_noFileSourced() {
        NanoTimeSupplier timeSupplier = mock(NanoTimeSupplier.class);

        InitialConfig initialConfig = InitialConfig.create(null, timeSupplier);

        assertThat(initialConfig.getConfigurationWithStatus()).isEqualTo(RateLimitingFactoriesSupplierWithStatus.NO_RATE_LIMITING);
    }

    @Test
    void create_withConfig() {
        NanoTimeSupplier timeSupplier = mock(NanoTimeSupplier.class);
        when(timeSupplier.now()).thenReturn(4711L);
        SourcedFile localConfigFile = mock(SourcedFile.class);
        when(localConfigFile.getBody()).thenReturn(SAMPLE_RATE_LIMITER_CONFIG_FILE);

        InitialConfig initialConfig = InitialConfig.create(localConfigFile, timeSupplier);

        assertThat(initialConfig.getInitialError()).isNull();
        assertThat(initialConfig.getLocalConfigFileDTO()).isNotNull();
        assertThat(initialConfig.getConfigurationWithStatus()).isNotNull();
        assertThat(initialConfig.getConfigurationWithStatus().getStatusJson()).contains("\"status\" : \"PENDING\"");
    }

    private static final String SAMPLE_RATE_LIMITER_CONFIG_FILE_ROUND_TRIPPED_THRU_SNAKE_YAML =
            """
                    !!org.cloudfoundry.identity.uaa.ratelimiting.config.InitialConfig$UaaYamlConfigFileDTO
                    ratelimit:
                      credentialID: JWTjsonField:Claims:email
                      dynamicConfigUrl: urlGoesHere
                      limiterMappings:
                      - global: null
                        name: Info
                        pathSelectors: ['equals:/info']
                        withCallerCredentialsID: null
                        withCallerRemoteAddressID: 1r/s
                        withoutCallerID: null
                      - global: null
                        name: Authenticate
                        pathSelectors: ['equals:/authenticate']
                        withCallerCredentialsID: null
                        withCallerRemoteAddressID: 5r/s
                        withoutCallerID: null
                      loggingOption: AllCallsWithDetails
                    """;
}