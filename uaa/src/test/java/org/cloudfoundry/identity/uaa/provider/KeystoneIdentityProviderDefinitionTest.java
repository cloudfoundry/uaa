package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class KeystoneIdentityProviderDefinitionTest {

    @Test
    public void testEquals(){
        KeystoneIdentityProviderDefinition kipd1 = new KeystoneIdentityProviderDefinition();
        kipd1.setAddShadowUserOnLogin(true);
        KeystoneIdentityProviderDefinition kipd2 = new KeystoneIdentityProviderDefinition();
        kipd2.setAddShadowUserOnLogin(false);
        assertNotEquals(kipd1, kipd2);

        kipd2.setAddShadowUserOnLogin(true);
        assertEquals(kipd1, kipd2);
    }
}
