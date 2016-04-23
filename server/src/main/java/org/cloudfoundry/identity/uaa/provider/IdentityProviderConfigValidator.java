package org.cloudfoundry.identity.uaa.provider;

public interface IdentityProviderConfigValidator {
    void validate(AbstractIdentityProviderDefinition definition);
}
