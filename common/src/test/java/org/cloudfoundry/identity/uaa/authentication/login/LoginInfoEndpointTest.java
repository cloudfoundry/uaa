package org.cloudfoundry.identity.uaa.authentication.login;

import java.util.ArrayList;
import java.util.Collections;

import junit.framework.TestCase;

import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

public class LoginInfoEndpointTest extends TestCase {

    @Before
    public void setUp() {
        IdentityZoneHolder.clear();
    }

    @After
    public void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLoginReturnsSystemZone() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        Model model = new ExtendedModelMap();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null);
        assertEquals("uaa", model.asMap().get("zone_name"));
    }

    @Test
    public void testLoginReturnsOtherZone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint();
        Model model = new ExtendedModelMap();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null);
        assertEquals("some_other_zone", model.asMap().get("zone_name"));
    }
    
    private LoginInfoEndpoint getEndpoint() {
        LoginInfoEndpoint endpoint = new LoginInfoEndpoint();
        endpoint.setBaseUrl("http://someurl");
        endpoint.setIdpDefinitions(new ArrayList<IdentityProviderDefinition>());
        endpoint.setEnvironment(new MockEnvironment());
        return endpoint;
    }
}