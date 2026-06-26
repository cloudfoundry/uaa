package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.db.beans.DatabaseConfiguration;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration;
import org.cloudfoundry.identity.uaa.db.beans.JdbcUrlCustomizer;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration;
import org.springframework.boot.transaction.autoconfigure.TransactionAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression test for UAA v79.0.0: verifies that running ClientAdminBootstrap twice
 * (simulating a UAA restart) does not re-encode the secret of a client with an empty secret.
 *
 * Uses the integrationTest source set so the real PasswordEncoderConfig (BCrypt-based,
 * wrapped in EmptyAwareDelegatingPasswordEncoder) is used — not the noop test shadow.
 * Without EmptyAwareDelegatingPasswordEncoder, Spring Security 7's BCryptPasswordEncoder
 * rejects empty rawPassword in matches(), causing the secret to be re-encoded on every
 * startup and invalidating existing tokens (DRAT failure).
 */
@SpringJUnitConfig(classes = {
        DatabaseConfiguration.class,
        PasswordEncoderConfig.class,
        FlywayConfiguration.class,
        FlywayConfiguration.FlywayConfigurationWithMigration.class,
        ClientAdminBootstrapProdEncoderTest.TestConfig.class
})
@ImportAutoConfiguration(classes = {
        JdbcTemplateAutoConfiguration.class,
        DataSourceTransactionManagerAutoConfiguration.class,
        TransactionAutoConfiguration.class
})
class ClientAdminBootstrapProdEncoderTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private IdentityZoneManager identityZoneManager;

    @Test
    void emptySecretHashIsStableAcrossBootstrapRuns() {
        MultitenantJdbcClientDetailsService clientService =
                new MultitenantJdbcClientDetailsService(namedJdbcTemplate, identityZoneManager, passwordEncoder);

        String clientId = "test-empty-secret-stability";
        Map<String, Object> clientConfig = new HashMap<>();
        clientConfig.put("secret", "");
        clientConfig.put("authorized-grant-types", "client_credentials");
        clientConfig.put("scope", "uaa.none");
        clientConfig.put("authorities", "uaa.none");
        Map<String, Map<String, Object>> clients = new HashMap<>();
        clients.put(clientId, clientConfig);

        ClientAdminBootstrap bootstrap = new ClientAdminBootstrap(
                passwordEncoder,
                clientService,
                new JdbcClientMetadataProvisioning(clientService, jdbcTemplate),
                true,
                clients,
                Collections.emptySet(),
                Collections.emptySet(),
                jdbcTemplate,
                Collections.emptySet());

        // First run — simulates UAA startup 1
        bootstrap.afterPropertiesSet();
        String hashAfterFirstRun = clientService.loadClientByClientId(clientId).getClientSecret();

        // Second run — simulates UAA restart
        bootstrap.afterPropertiesSet();
        String hashAfterSecondRun = clientService.loadClientByClientId(clientId).getClientSecret();

        assertThat(hashAfterSecondRun)
                .as("empty-secret client hash must not change across bootstrap runs (UAA v79.0.0 regression)")
                .isEqualTo(hashAfterFirstRun);
    }

    @Configuration
    static class TestConfig {
        @Bean
        JdbcUrlCustomizer testJdbcUrlCustomizer() {
            return url -> {
                var workerId = System.getProperty("org.gradle.test.worker");
                return workerId == null ? url : url.replace("uaa", "uaa_" + workerId);
            };
        }

        @Bean
        IdentityZoneManager identityZoneManager() {
            return new IdentityZoneManagerImpl();
        }
    }
}
