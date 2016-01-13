package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.*;

import java.util.Collections;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.zone.ZoneEndpointsClientDetailsValidator;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class ZoneEndpointsClientDetailsValidatorTests {

    private ZoneEndpointsClientDetailsValidator zoneEndpointsClientDetailsValidator;

    @Before
    public void setUp() throws Exception {
        zoneEndpointsClientDetailsValidator = new ZoneEndpointsClientDetailsValidator("zones.write");
    }

    @Test
    public void testCreateLimitedClient() {
        BaseClientDetails clientDetails = new BaseClientDetails("valid-client", null, "openid", "authorization_code,password", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getClientId(), validatedClientDetails.getClientId());
        assertEquals(clientDetails.getScope(), validatedClientDetails.getScope());
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
        assertEquals(clientDetails.getAuthorities(), validatedClientDetails.getAuthorities());
        assertEquals(Collections.singleton("none"), validatedClientDetails.getResourceIds());
        assertEquals(Collections.singletonList(OriginKeys.UAA), validatedClientDetails.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
    }
    
    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientNoNameIsInvalid() {
        BaseClientDetails clientDetails = new BaseClientDetails("", null, "openid", "authorization_code", "uaa.resource");
        clientDetails.setClientSecret("secret");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }
    
    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientNoSecretIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "authorization_code", "uaa.resource");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }

    @Test
    public void testCreateClientNoSecretForImplicitIsValid() {
        BaseClientDetails clientDetails = new BaseClientDetails("client", null, "openid", "implicit", "uaa.resource");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(OriginKeys.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
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
