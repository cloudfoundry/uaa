package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SkipSslLdapSocketFactoryTest {

    @Test
    void testDefaultInstanceIsSkipSslLdapSocketFactory() {
        Object ldapFactory = SkipSslLdapSocketFactory.getDefault();
        assertNotNull(ldapFactory);
        assertTrue(ldapFactory instanceof  SkipSslLdapSocketFactory);
        assertTrue(SkipSslLdapSocketFactory.getDefault() instanceof  SkipSslLdapSocketFactory);
    }
}
