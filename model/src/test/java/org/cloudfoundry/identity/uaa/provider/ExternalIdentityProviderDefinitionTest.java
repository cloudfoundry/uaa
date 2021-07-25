package org.cloudfoundry.identity.uaa.provider;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ExternalIdentityProviderDefinitionTest {

    ExternalIdentityProviderDefinition definition;

    @Before
    public void createDefinition() {
        definition = new ExternalIdentityProviderDefinition();
    }

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

    @Test
    public void testDefaultValueForStoreCustomAttributes() {
        assertTrue(definition.isStoreCustomAttributes());
    }

    @Test
    public void testEquals2() {
        ExternalIdentityProviderDefinition def = new ExternalIdentityProviderDefinition();
        def.setStoreCustomAttributes(false);
        assertNotEquals(definition, def);
    }
}
