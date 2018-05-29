package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.springframework.security.core.userdetails.UserDetails;

import static org.mockito.Mockito.mock;

public class LdapLoginAuthenticationManagerBuilder extends AbstractExternalLoginAuthenticationManagerBuilder<LdapLoginAuthenticationManagerBuilder> {
    protected LdapLoginAuthenticationManagerBuilder me() {
        return this;
    }

    public static LdapLoginAuthenticationManagerBuilder anLdapManager() {
        return new LdapLoginAuthenticationManagerBuilder()
                .withIdProviderProvisioning(mock(IdentityProviderProvisioning.class))
                .withProviderDefinition(mock(LdapIdentityProviderDefinition.class))
                .withProvider(mock(IdentityProvider.class));
    }

    public ExternalLoginAuthenticationManager build() {
        return buildManagerType(LdapLoginAuthenticationManager.class);
    }

}
