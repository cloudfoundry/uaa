package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.ZoneEndpointsClientDetailsValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class ZoneEndpointsClientDetailsValidatorTests {

    @Mock
    private ClientSecretValidator mockClientSecretValidator;

    @InjectMocks
    private ZoneEndpointsClientDetailsValidator zoneEndpointsClientDetailsValidator;

    @Test
    void createLimitedClient() {
        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "authorization_code,password", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getClientId()).isEqualTo(clientDetails.getClientId());
        assertThat(validatedClientDetails.getScope()).isEqualTo(clientDetails.getScope());
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).isEqualTo(clientDetails.getAuthorizedGrantTypes());
        assertThat(validatedClientDetails.getAuthorities()).isEqualTo(clientDetails.getAuthorities());
        assertThat(validatedClientDetails.getResourceIds()).isEqualTo(Collections.singleton("none"));
        assertThat(validatedClientDetails.getAdditionalInformation()).containsEntry(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
    }

    @Test
    void createClientNoNameIsInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("secret");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "password",
            "client_credentials",
            GRANT_TYPE_AUTHORIZATION_CODE,
            GRANT_TYPE_USER_TOKEN,
            GRANT_TYPE_REFRESH_TOKEN,
            GRANT_TYPE_SAML2_BEARER,
            GRANT_TYPE_JWT_BEARER,
            GRANT_TYPE_TOKEN_EXCHANGE
    })
    void createClientNoSecretIsInvalid(final String grantType) {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", grantType, "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("client_secret cannot be blank");
    }

    @Test
    void createClientNoSecretForImplicitIsValid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "implicit", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).isEqualTo(clientDetails.getAuthorizedGrantTypes());
    }

    @Test
    void reject_invalid_grant_type() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "invalid_grant_type", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void createAdminScopeClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "uaa.admin", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void createAdminAuthorityClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.admin");
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }
}
