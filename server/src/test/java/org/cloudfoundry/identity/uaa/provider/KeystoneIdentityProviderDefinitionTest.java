package org.cloudfoundry.identity.uaa.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


class KeystoneIdentityProviderDefinitionTest {

    @Test
    void equals() {
        KeystoneIdentityProviderDefinition kipd1 = new KeystoneIdentityProviderDefinition();
        kipd1.setAddShadowUserOnLogin(true);
        KeystoneIdentityProviderDefinition kipd2 = new KeystoneIdentityProviderDefinition();
        kipd2.setAddShadowUserOnLogin(false);
        assertThat(kipd2).isNotEqualTo(kipd1);

        kipd2.setAddShadowUserOnLogin(true);
        assertThat(kipd2).isEqualTo(kipd1);
    }
}
