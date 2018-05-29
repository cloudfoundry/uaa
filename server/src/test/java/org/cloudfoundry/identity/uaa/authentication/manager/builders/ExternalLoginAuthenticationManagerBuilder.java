package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;

import static org.mockito.Mockito.mock;

public class ExternalLoginAuthenticationManagerBuilder extends AbstractExternalLoginAuthenticationManagerBuilder<ExternalLoginAuthenticationManagerBuilder> {
    protected ExternalLoginAuthenticationManagerBuilder me() {
        return this;
    }

    public static ExternalLoginAuthenticationManagerBuilder aManager() {
        return new ExternalLoginAuthenticationManagerBuilder()
                .withIdProviderProvisioning(mock(IdentityProviderProvisioning.class))
                .withProviderDefinition(mock(ExternalIdentityProviderDefinition.class))
                .withProvider(mock(IdentityProvider.class));
    }

    public ExternalLoginAuthenticationManager build() {
        return buildManagerType(ExternalLoginAuthenticationManager.class);
    }
}
