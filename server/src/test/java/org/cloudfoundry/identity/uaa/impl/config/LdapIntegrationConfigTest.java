package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class LdapIntegrationConfigTest {
    LdapIntegrationConfig ldapIntegrationConfig;

    @BeforeEach
    void beforeEach() {
        ldapIntegrationConfig = new LdapIntegrationConfig();
    }

    @Test
    void setLdapTimeoutPropertyTo30Minutes() {
        Environment env = Mockito.mock(Environment.class);
        Map properties = ldapIntegrationConfig.ldapProperties(env);
        assertThat(properties).containsEntry("com.sun.jndi.ldap.connect.timeout", String.valueOf(30 * 60 * 1000));
    }
}
