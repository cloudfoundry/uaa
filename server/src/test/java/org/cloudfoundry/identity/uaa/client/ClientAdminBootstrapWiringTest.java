package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Spring wiring regression tests for ClientAdminBootstrap.allowPublicClients.
 *
 * Commit a1459a300 converted ClientAdminBootstrap to @Component but accidentally
 * omitted the @Value SpEL annotation from the allowPublicClients constructor parameter.
 * Without it, Spring injects all String-typed beans in the context into that Set
 * rather than reading oauth.client.allowpublic from the YAML config.
 *
 * These tests boot a minimal Spring context (bypassing the full UAA context) to verify
 * that the @Value expression resolves correctly under different config shapes. They
 * fail without the @Value annotation and pass with it.
 */
class ClientAdminBootstrapWiringTest {

    // -------------------------------------------------------------------------
    // Happy path: oauth.client.allowpublic is configured
    // -------------------------------------------------------------------------

    @Nested
    @SpringJUnitConfig(classes = WithAllowPublicConfigured.Config.class)
    class WithAllowPublicConfigured {

        @Configuration
        @Import(ClientAdminBootstrap.class)
        static class Config {
            @Bean("config")
            Map<String, Object> config() {
                return Map.of("oauth", Map.of("client", Map.of("allowpublic", List.of("public-test-client"))));
            }

            @Bean("applicationProperties")
            Properties applicationProperties() {
                return new Properties();
            }

            @Bean("nonCachingPasswordEncoder")
            PasswordEncoder passwordEncoder() {
                return mock(PasswordEncoder.class);
            }

            @Bean
            MultitenantClientServices clientRegistrationService() {
                MultitenantClientServices svc = mock(MultitenantClientServices.class);
                // Minimal stub: client lookup is not the concern here; we only verify the correct id is wired
                doThrow(new NoSuchClientException("not found")).when(svc).loadClientByClientId(anyString(), anyString());
                return svc;
            }

            @Bean
            ClientMetadataProvisioning clientMetadataProvisioning() {
                return mock(ClientMetadataProvisioning.class);
            }

            @Bean
            JdbcTemplate jdbcTemplate() {
                return mock(JdbcTemplate.class);
            }
        }

        @Autowired
        MultitenantClientServices clientRegistrationService;

        @Test
        void allowpublic_clientId_isReadFromConfig() {
            // updateAllowedPublicClients() is called during afterPropertiesSet(); verify
            // it was invoked with the client id from oauth.client.allowpublic
            verify(clientRegistrationService).loadClientByClientId("public-test-client", "uaa");
        }
    }

    // -------------------------------------------------------------------------
    // Null-guard: oauth key is entirely absent from config
    // -------------------------------------------------------------------------

    @Nested
    @SpringJUnitConfig(classes = WhenOauthConfigAbsent.Config.class)
    class WhenOauthConfigAbsent {

        @Configuration
        @Import(ClientAdminBootstrap.class)
        static class Config {
            @Bean("config")
            Map<String, Object> config() {
                return Map.of();
            }

            @Bean("applicationProperties")
            Properties applicationProperties() {
                return new Properties();
            }

            @Bean("nonCachingPasswordEncoder")
            PasswordEncoder passwordEncoder() {
                return mock(PasswordEncoder.class);
            }

            @Bean
            MultitenantClientServices clientRegistrationService() {
                MultitenantClientServices svc = mock(MultitenantClientServices.class);
                doThrow(new NoSuchClientException("not found")).when(svc).loadClientByClientId(anyString(), anyString());
                return svc;
            }

            @Bean
            ClientMetadataProvisioning clientMetadataProvisioning() {
                return mock(ClientMetadataProvisioning.class);
            }

            @Bean
            JdbcTemplate jdbcTemplate() {
                return mock(JdbcTemplate.class);
            }
        }

        @Autowired
        ClientAdminBootstrap clientAdminBootstrap;

        @Test
        void allowpublic_isEmptySet_whenOauthConfigAbsent() throws ReflectiveOperationException {
            assertThat(getAllowPublicClients(clientAdminBootstrap)).isEmpty();
        }
    }

    // -------------------------------------------------------------------------
    // Null-guard: oauth present but oauth.client subkey is absent
    // -------------------------------------------------------------------------

    @Nested
    @SpringJUnitConfig(classes = WhenOauthClientConfigAbsent.Config.class)
    class WhenOauthClientConfigAbsent {

        @Configuration
        @Import(ClientAdminBootstrap.class)
        static class Config {
            @Bean("config")
            Map<String, Object> config() {
                return Map.of("oauth", Map.of());
            }

            @Bean("applicationProperties")
            Properties applicationProperties() {
                return new Properties();
            }

            @Bean("nonCachingPasswordEncoder")
            PasswordEncoder passwordEncoder() {
                return mock(PasswordEncoder.class);
            }

            @Bean
            MultitenantClientServices clientRegistrationService() {
                MultitenantClientServices svc = mock(MultitenantClientServices.class);
                doThrow(new NoSuchClientException("not found")).when(svc).loadClientByClientId(anyString(), anyString());
                return svc;
            }

            @Bean
            ClientMetadataProvisioning clientMetadataProvisioning() {
                return mock(ClientMetadataProvisioning.class);
            }

            @Bean
            JdbcTemplate jdbcTemplate() {
                return mock(JdbcTemplate.class);
            }
        }

        @Autowired
        ClientAdminBootstrap clientAdminBootstrap;

        @Test
        void allowpublic_isEmptySet_whenOauthClientConfigAbsent() throws ReflectiveOperationException {
            assertThat(getAllowPublicClients(clientAdminBootstrap)).isEmpty();
        }
    }

    @SuppressWarnings("unchecked")
    private static Set<String> getAllowPublicClients(ClientAdminBootstrap bootstrap)
            throws ReflectiveOperationException {
        Field f = ClientAdminBootstrap.class.getDeclaredField("allowPublicClients");
        f.setAccessible(true);
        return (Set<String>) f.get(bootstrap);
    }
}
