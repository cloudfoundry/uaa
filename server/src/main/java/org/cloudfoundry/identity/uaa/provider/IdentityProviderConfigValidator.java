package org.cloudfoundry.identity.uaa.provider;

public interface IdentityProviderConfigValidator {
    void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> definition);
}
