package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LdapIntegrationConfigTest {
    LdapIntegrationConfig ldapIntegrationConfig;

    @BeforeEach
    void beforeEach() {
        ldapIntegrationConfig = new LdapIntegrationConfig();
    }

    @Test
    void testSetLdapTimeoutPropertyTo30Minutes() {
        Environment env = Mockito.mock(Environment.class);
        Map properties = ldapIntegrationConfig.ldapProperties(env);
        assertEquals(String.valueOf(30 * 60 * 1000),
                properties.get("com.sun.jndi.ldap.connect.timeout"));
    }
}
