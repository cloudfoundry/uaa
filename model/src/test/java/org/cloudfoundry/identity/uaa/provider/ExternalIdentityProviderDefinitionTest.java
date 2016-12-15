package org.cloudfoundry.identity.uaa.provider;

import org.junit.Test;

import static org.junit.Assert.*;

public class ExternalIdentityProviderDefinitionTest {

    @Test
    public void testEquals() {
        ExternalIdentityProviderDefinition definition1 = new ExternalIdentityProviderDefinition();
        definition1.setAddShadowUserOnLogin(true);
        ExternalIdentityProviderDefinition definition2 = new ExternalIdentityProviderDefinition();
        definition2.setAddShadowUserOnLogin(false);

        assertNotEquals(definition1, definition2);
        definition2.setAddShadowUserOnLogin(true);
        assertEquals(definition1, definition2);
    }

}
