package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.springframework.stereotype.Component;

import java.util.Set;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

@Component("identityProviderConfigValidator")
public class IdentityProviderConfigValidationDelegator implements IdentityProviderConfigValidator {

    private final IdentityProviderConfigValidator externalOAuthIdentityProviderConfigValidator;
    private final IdentityProviderConfigValidator uaaIdentityProviderConfigValidator;
    private final IdentityProviderConfigValidator ldapIdentityProviderConfigValidator;
    private final Set<String> reservedOriginKeys = Set.of(UAA, LDAP);

    public IdentityProviderConfigValidationDelegator(
            final ExternalOAuthIdentityProviderConfigValidator externalOAuthIdentityProviderConfigValidator,
            final UaaIdentityProviderConfigValidator uaaIdentityProviderConfigValidator,
            final LdapIdentityProviderConfigValidator ldapIdentityProviderConfigValidator
    ) {
        this.externalOAuthIdentityProviderConfigValidator = externalOAuthIdentityProviderConfigValidator;
        this.uaaIdentityProviderConfigValidator = uaaIdentityProviderConfigValidator;
        this.ldapIdentityProviderConfigValidator = ldapIdentityProviderConfigValidator;
    }

    private void checkReservedOriginKeys(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        if (provider.getOriginKey() != null && reservedOriginKeys.contains(provider.getOriginKey())) {
            throw new IllegalArgumentException(
                    "Origin \"" + provider.getOriginKey() + "\" not allowed for type \"" + provider.getType() + "\"");
        }
    }

    @Override
    public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null");
        }
        String type = provider.getType();
        switch (type) {
            case OAUTH20:
            case OIDC10:
                checkReservedOriginKeys(provider);
                this.externalOAuthIdentityProviderConfigValidator.validate(provider);
                break;
            case UAA:
                this.uaaIdentityProviderConfigValidator.validate(provider);
                break;
            case LDAP:
                this.ldapIdentityProviderConfigValidator.validate(provider);
                break;
            case SAML:
                checkReservedOriginKeys(provider);
                break;
        }
    }
}
