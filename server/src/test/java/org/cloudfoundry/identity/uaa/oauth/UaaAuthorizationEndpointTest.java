package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

public class UaaAuthorizationEndpointTest {
    @Test
    public void testGetGrantType(){
        Set<String> responseTypes = new HashSet<>();

        responseTypes.add("id_token");
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint();
        assertEquals("implicit", uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("token");
        assertEquals("implicit", uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("code");
        assertEquals("authorization_code", uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("code");
        responseTypes.add("token");
        assertEquals("implicit",  uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals("implicit",  uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("code");
        responseTypes.add("id_token");
        assertEquals("authorization_code",  uaaAuthorizationEndpoint.getGrantType(responseTypes));

        responseTypes.clear();
        responseTypes.add("code");
        responseTypes.add("id_token");
        responseTypes.add("token");
        assertEquals("implicit",  uaaAuthorizationEndpoint.getGrantType(responseTypes));
    }
}