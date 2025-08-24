package org.cloudfoundry.identity.uaa.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExternalIdentityProviderDefinitionTest {

    ExternalIdentityProviderDefinition definition;

    @BeforeEach
    void createDefinition() {
        definition = new ExternalIdentityProviderDefinition();
    }

    @Test
    void equals() {
        ExternalIdentityProviderDefinition definition1 = new ExternalIdentityProviderDefinition();
        definition1.setAddShadowUserOnLogin(true);
        ExternalIdentityProviderDefinition definition2 = new ExternalIdentityProviderDefinition();
        definition2.setAddShadowUserOnLogin(false);

        assertThat(definition2).isNotEqualTo(definition1);
        definition2.setAddShadowUserOnLogin(true);
        assertThat(definition2).isEqualTo(definition1);
    }

    @Test
    void defaultValueForStoreCustomAttributes() {
        assertThat(definition.isStoreCustomAttributes()).isTrue();
    }

    @Test
    void equals2() {
        ExternalIdentityProviderDefinition def = new ExternalIdentityProviderDefinition();
        def.setStoreCustomAttributes(false);
        assertThat(def).isNotEqualTo(definition);
    }
}
