package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SkipSslLdapSocketFactoryTest {

    @Test
    void defaultInstanceIsSkipSslLdapSocketFactory() {
        Object ldapFactory = SkipSslLdapSocketFactory.getDefault();
        assertThat(ldapFactory).isInstanceOf(SkipSslLdapSocketFactory.class);
        assertThat(SkipSslLdapSocketFactory.getDefault()).isInstanceOf(SkipSslLdapSocketFactory.class);
    }
}
