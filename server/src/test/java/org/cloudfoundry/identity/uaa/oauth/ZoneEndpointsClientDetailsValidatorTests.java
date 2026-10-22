package org.cloudfoundry.identity.uaa.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
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
        UaaClientDetails clientDetails = new UaaClientDetails("valid-client", null, "openid", "authorization_code,password", "uaa.resource", "http://localhost:8080/callback");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getClientId()).isEqualTo(clientDetails.getClientId());
        assertThat(validatedClientDetails.getScope()).hasSameElementsAs(clientDetails.getScope());
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).hasSameElementsAs(clientDetails.getAuthorizedGrantTypes());
        assertThat(validatedClientDetails.getAuthorities()).isEqualTo(clientDetails.getAuthorities());
        assertThat(validatedClientDetails.getResourceIds()).hasSameElementsAs(Collections.singleton("none"));
        assertThat(validatedClientDetails.getAdditionalInformation()).containsEntry(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        assertThat(validatedClientDetails.getRegisteredRedirectUri()).containsExactly("http://localhost:8080/callback");
    }

    @Test
    void createClientNoNameIsInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("secret");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
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
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "implicit", "uaa.resource", "http://localhost:8080/callback");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).hasSameElementsAs(clientDetails.getAuthorizedGrantTypes());
    }

    @ParameterizedTest
    @ValueSource(strings = {GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
    void createClient_withoutRedirectUri_isInvalid(final String grantType) {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", grantType, "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage(grantType + " grant type requires at least one redirect URL.");
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-url", "javascript:alert(1)", "*", "http://a.example.com,http://b.example.com"})
    void createClient_withInvalidRedirectUri_isInvalid(final String redirectUri) {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setRegisteredRedirectUri(Collections.singleton(redirectUri));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("One of the redirect_uri is invalid: " + redirectUri);
    }

    @Test
    void createClient_withMixedGrantTypesWithoutRedirectUri_isInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "password,authorization_code", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage(GRANT_TYPE_AUTHORIZATION_CODE + " grant type requires at least one redirect URL.");
    }

    @Test
    void createClient_implicitWithoutSecretOrRedirectUri_isInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_IMPLICIT, "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage(GRANT_TYPE_IMPLICIT + " grant type requires at least one redirect URL.");
    }

    @Test
    void createClient_withValidAndInvalidRedirectUris_isInvalid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setRegisteredRedirectUri(new LinkedHashSet<>(List.of("https://ok.example.com/callback", "not-a-url")));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("One of the redirect_uri is invalid: not-a-url");
    }

    @Test
    void createClient_withNullRedirectUri_isInvalid() {
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add(null);
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setRegisteredRedirectUri(redirectUris);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("One of the redirect_uri is invalid: null");
    }

    @Test
    void createClient_withWildcardRedirectUri_isValid() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", "https://*.example.com/**");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);

        assertThat(validatedClientDetails.getRegisteredRedirectUri()).containsExactly("https://*.example.com/**");
    }

    @Test
    void createClient_withoutAllowedProvidersOrRedirectUri_reportsAllowedProvidersFirst() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("secret");

        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessage("only the internal IdP ('uaa') is allowed");
    }

    @Test
    void createClient_withoutRedirectUri_isValidForGrantTypeWithoutRedirect() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "password", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));

        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);

        assertThat(validatedClientDetails.getAuthorizedGrantTypes()).containsExactly("password");
    }

    @Test
    void reject_invalid_grant_type() {
        UaaClientDetails clientDetails = new UaaClientDetails("client", null, "openid", "invalid_grant_type", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void createAdminScopeClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "uaa.admin", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void createAdminAuthorityClientIsInvalid() {
        ClientDetails clientDetails = new UaaClientDetails("admin-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.admin");
        assertThatThrownBy(() -> zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }
}
