package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.cloudfoundry.identity.uaa.zone.ZoneEndpointsClientDetailsValidator;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.ALLOWED_PROVIDERS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class ZoneEndpointsClientDetailsValidatorTests {

    private ZoneEndpointsClientDetailsValidator zoneEndpointsClientDetailsValidator;

    @Before
    public void setUp() throws Exception {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator("zones.write");
        zoneEndpointsClientDetailsValidator.setClientSecretValidator(
                new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0,255,0,0,0,0,6)));

    }

    @Test
    public void testCreateLimitedClient() {
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

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientNoNameIsInvalid() {
        BaseClientDetails clientDetails = new BaseClientDetails("", null, "openid", "authorization_code", "uaa.resource");
        clientDetails.setClientSecret("secret");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }

    @Test
    public void testCreateClientNoSecretIsInvalid() {
        for (String grantType : Arrays.asList("password", "client_credentials", "authorization_code", GRANT_TYPE_USER_TOKEN, GRANT_TYPE_REFRESH_TOKEN, GRANT_TYPE_SAML2_BEARER)) {
            try {
                BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", grantType, "uaa.resource");
                clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
                zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
                fail("Grant type:"+grantType + " must require a secret");
            } catch (InvalidClientDetailsException e) {
                assertThat(e.getMessage(), containsString("client_secret cannot be blank"));
            }
        }
    }

    @Test
    public void testCreateClientNoSecretForImplicitIsValid() {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "implicit", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void reject_invalid_grant_type() {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "invalid_grant_type", "uaa.resource");
        clientDetails.addAdditionalInformation(ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateAdminScopeClientIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("admin-client", null, "uaa.admin", "authorization_code", "uaa.resource");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateAdminAuthorityClientIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("admin-client", null, "openid", "authorization_code", "uaa.admin");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }
}
