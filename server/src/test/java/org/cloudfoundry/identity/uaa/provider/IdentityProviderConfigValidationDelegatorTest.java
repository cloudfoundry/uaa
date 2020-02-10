package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class IdentityProviderConfigValidationDelegatorTest {

    private IdentityProviderConfigValidationDelegator validator;
    private UaaIdentityProviderConfigValidator uaaValidator;
    private LdapIdentityProviderConfigValidator ldapValidator;
    private IdentityProvider<AbstractIdentityProviderDefinition> provider;
    private ExternalOAuthIdentityProviderConfigValidator externalOAuthValidator;

    @BeforeEach
    void setup() {
        uaaValidator = mock(UaaIdentityProviderConfigValidator.class);
        externalOAuthValidator = mock(ExternalOAuthIdentityProviderConfigValidator.class);
        ldapValidator = mock(LdapIdentityProviderConfigValidator.class);
        provider = new IdentityProvider<>();
        validator = new IdentityProviderConfigValidationDelegator(
                externalOAuthValidator,
                uaaValidator,
                ldapValidator
        );
    }

    @Test
    void null_identity_provider() {
        assertThrowsWithMessageThat(
                IllegalArgumentException.class,
                () -> validator.validate(null),
                org.hamcrest.Matchers.is("Provider cannot be null")
        );
    }

    @Test
    void uaa_validator_with_nodefinition_is_invoked() {
        provider.setType(UAA);
        provider.setOriginKey(UAA);
        validator.validate(provider);
        verify(uaaValidator, times(1)).validate(same(provider));
        verifyNoInteractions(externalOAuthValidator);
        verifyNoInteractions(ldapValidator);
    }

    @Test
    void ldap_validator_with_definition_is_invoked() {
        provider.setType(LDAP);
        provider.setOriginKey(LDAP);
        validator.validate(provider);
        verify(ldapValidator, times(1)).validate(same(provider));
        verifyNoInteractions(uaaValidator);
        verifyNoInteractions(externalOAuthValidator);
    }

    @Test
    void externalOAuth_validator_with_definition_is_invoked() {
        for (String type : Arrays.asList(OAUTH20, OIDC10)) {
            provider.setType(type);
            provider.setOriginKey("any");
            validator.validate(provider);
            verify(externalOAuthValidator, times(1)).validate(same(provider));
            verifyNoInteractions(uaaValidator);
            verifyNoInteractions(ldapValidator);
            Mockito.reset(externalOAuthValidator);
        }
    }
}