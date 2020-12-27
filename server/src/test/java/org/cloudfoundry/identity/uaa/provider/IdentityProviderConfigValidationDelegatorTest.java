package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
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

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verify(mockUaaIdentityProviderConfigValidator).validate(identityProvider);
        verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
    }

    @Test
    void ldap_validator_with_definition_is_invoked() {
        identityProvider.setType(LDAP);

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
        verify(mockLdapIdentityProviderConfigValidator).validate(identityProvider);
        verifyNoInteractions(mockExternalOAuthIdentityProviderConfigValidator);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            OAUTH20,
            OIDC10
    })
    void externalOAuth_validator_with_definition_is_invoked(final String type) {
        identityProvider.setType(type);

        identityProviderConfigValidationDelegator.validate(identityProvider);

        verifyNoInteractions(mockUaaIdentityProviderConfigValidator);
        verifyNoInteractions(mockLdapIdentityProviderConfigValidator);
        verify(mockExternalOAuthIdentityProviderConfigValidator).validate(identityProvider);
    }
}