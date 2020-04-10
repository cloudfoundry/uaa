package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.stereotype.Component;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;

@Component
public class LdapIdentityProviderConfigValidator extends BaseIdentityProviderValidator {

    @Override
    public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        super.validate(provider);
        if (!LDAP.equals(provider.getOriginKey())) {
            throw new IllegalArgumentException(String.format("LDAP provider originKey must be set to '%s'", LDAP));
        }
    }

    @Override
    public void validate(AbstractIdentityProviderDefinition definition) {
        //not yet implemented
    }
}
