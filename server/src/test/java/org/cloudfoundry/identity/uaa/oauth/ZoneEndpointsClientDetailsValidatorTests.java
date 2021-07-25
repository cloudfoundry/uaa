package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.ZoneEndpointsClientDetailsValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class ZoneEndpointsClientDetailsValidatorTests {

    @Mock
    private ClientSecretValidator mockClientSecretValidator;

    @InjectMocks
    private ZoneEndpointsClientDetailsValidator zoneEndpointsClientDetailsValidator;

    @Test
    void testCreateLimitedClient() {
        BaseClientDetails clientDetails = new BaseClientDetails("valid-client", null, "openid", "authorization_code,password", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getClientId(), validatedClientDetails.getClientId());
        assertEquals(clientDetails.getScope(), validatedClientDetails.getScope());
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
        assertEquals(clientDetails.getAuthorities(), validatedClientDetails.getAuthorities());
        assertEquals(Collections.singleton("none"), validatedClientDetails.getResourceIds());
        assertEquals(Collections.singletonList(OriginKeys.UAA), validatedClientDetails.getAdditionalInformation().get(ALLOWED_PROVIDERS));
    }

    @Test
    void testCreateClientNoNameIsInvalid() {
        BaseClientDetails clientDetails = new BaseClientDetails("", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("secret");
        assertThrows(InvalidClientDetailsException.class,
                () -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
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
    })
    void testCreateClientNoSecretIsInvalid(final String grantType) {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", grantType, "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThrowsWithMessageThat(
                InvalidClientDetailsException.class,
                () -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE),
                containsString("client_secret cannot be blank")
        );
    }

    @Test
    void testCreateClientNoSecretForImplicitIsValid() {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "implicit", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
    }

    @Test
    void reject_invalid_grant_type() {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "invalid_grant_type", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        assertThrows(InvalidClientDetailsException.class,
                () -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void testCreateAdminScopeClientIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("admin-client", null, "uaa.admin", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        assertThrows(InvalidClientDetailsException.class,
                () -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }

    @Test
    void testCreateAdminAuthorityClientIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("admin-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.admin");
        assertThrows(InvalidClientDetailsException.class,
                () -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE));
    }
}
