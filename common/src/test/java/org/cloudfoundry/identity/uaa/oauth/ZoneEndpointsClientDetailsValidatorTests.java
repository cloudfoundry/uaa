package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.*;

import java.util.Collections;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.ClientDetailsValidator.Mode;
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
        BaseClientDetails clientDetails = new BaseClientDetails("valid-client", null, "openid", "authorization_code", "uaa.resource");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(Origin.UAA));
        ClientDetails validatedClientDetails = zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
        assertEquals(clientDetails.getClientId(), validatedClientDetails.getClientId());
        assertEquals(clientDetails.getScope(), validatedClientDetails.getScope());
        assertEquals(clientDetails.getAuthorizedGrantTypes(), validatedClientDetails.getAuthorizedGrantTypes());
        assertEquals(clientDetails.getAuthorities(), validatedClientDetails.getAuthorities());
        assertEquals(Collections.singleton("none"), validatedClientDetails.getResourceIds());
        assertEquals(Collections.singletonList(Origin.UAA), validatedClientDetails.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
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
    
    @Test(expected = InvalidClientDetailsException.class)
    public void testCreateClientCredentialsClientIsInvalid() {
        ClientDetails clientDetails = new BaseClientDetails("admin-client", null, "openid", "client_credentials", "uaa.resource");
        zoneEndpointsClientDetailsValidator.validate(clientDetails, Mode.CREATE);
    }
}
