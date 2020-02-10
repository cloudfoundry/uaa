package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityProviderConfigValidationDelegatorTest {

    @Mock
    private UaaIdentityProviderConfigValidator mockUaaIdentityProviderConfigValidator;

    @Mock
    private LdapIdentityProviderConfigValidator mockLdapIdentityProviderConfigValidator;

    @Mock
    private ExternalOAuthIdentityProviderConfigValidator mockExternalOAuthIdentityProviderConfigValidator;

    @InjectMocks
    private IdentityProviderConfigValidationDelegator identityProviderConfigValidationDelegator;

    private IdentityProvider<AbstractIdentityProviderDefinition> identityProvider;

    @BeforeEach
    void setup() {
        identityProvider = new IdentityProvider<>();
    }

    @Test
    void null_identity_provider() {
        assertThrowsWithMessageThat(
                IllegalArgumentException.class,
                () -> identityProviderConfigValidationDelegator.validate(null),
                org.hamcrest.Matchers.is("Provider cannot be null")
        );
    }

    @Test
    void uaa_validator_with_nodefinition_is_invoked() {
        identityProvider.setType(UAA);
        identityProvider.setOriginKey(UAA);
        identityProviderConfigValidationDelegator.validate(identityProvider);
        verify(mockUaaIdentityProviderConfigValidator, times(1)).validate(same(identityProvider));
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
        verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
    }

    @Test
    void ldap_validator_with_definition_is_invoked() {
        identityProvider.setType(LDAP);
        identityProvider.setOriginKey(LDAP);
        identityProviderConfigValidationDelegator.validate(identityProvider);
        verify(mockLdapIdentityProviderConfigValidator, times(1)).validate(same(identityProvider));
        verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
    }

    @Test
    void externalOAuth_validator_with_definition_is_invoked() {
        for (String type : Arrays.asList(OAUTH20, OIDC10)) {
            identityProvider.setType(type);
            identityProvider.setOriginKey("any");
            identityProviderConfigValidationDelegator.validate(identityProvider);
            verify(mockExternalOAuthIdentityProviderConfigValidator, times(1)).validate(same(identityProvider));
            verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
            verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
            Mockito.reset(mockExternalOAuthIdentityProviderConfigValidator);
        }
    }
}