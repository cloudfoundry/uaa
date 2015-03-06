package org.cloudfoundry.identity.uaa.authentication.login;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LoginInfoEndpointTest  {

    private UaaPrincipal marissa;

    @Before
    public void setUpPrincipal() {
        marissa = new UaaPrincipal("marissa-id","marissa","marissa@test.org","origin",null, IdentityZoneHolder.get().getId());
    }

    @Before
    @After
    public void clearZoneHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLoginReturnsSystemZone() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        Model model = new ExtendedModelMap();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertEquals(Origin.UAA, model.asMap().get("zone_name"));
    }

    @Test
    public void testLoginReturnsOtherZone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint();
        Model model = new ExtendedModelMap();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertEquals("some_other_zone", model.asMap().get("zone_name"));
    }

    @Test
    public void testGeneratePasscodeForKnownUaaPrincipal() throws Exception {
        Map<String,Object> model = new HashMap<>();
        ExpiringCodeStore store = new InMemoryExpiringCodeStore();
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setExpiringCodeStore(store);
        assertEquals("passcode", endpoint.generatePasscode(model, marissa));
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<GrantedAuthority>(),new UaaAuthenticationDetails(new MockHttpServletRequest()));
        assertEquals("passcode", endpoint.generatePasscode(model, uaaAuthentication));
        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken = new ExpiringUsernameAuthenticationToken(marissa,"");
        LoginSamlAuthenticationToken samlAuthenticationToken = new LoginSamlAuthenticationToken(marissa, expiringUsernameAuthenticationToken);
        assertEquals("passcode", endpoint.generatePasscode(model, samlAuthenticationToken));
        //token with a UaaPrincipal should always work
        assertEquals("passcode", endpoint.generatePasscode(model, expiringUsernameAuthenticationToken));

    }

    @Test(expected = LoginInfoEndpoint.UnknownPrincipalException.class)
    public void testGeneratePasscodeForUnknownUaaPrincipal() throws Exception {
        Map<String,Object> model = new HashMap<>();
        LoginInfoEndpoint endpoint = getEndpoint();
        ExpiringUsernameAuthenticationToken token = new ExpiringUsernameAuthenticationToken("princpal", "");
        assertEquals("passcode", endpoint.generatePasscode(model, token));
    }

    @Test
    public void testFilterIdpsForZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl()).thenReturn("http://localhost:8080/uaa");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        request.setSession(session);
        // mock IdentityProviderConfigurator
        List<IdentityProviderDefinition> idps = getIdps();
        IdentityProviderConfigurator mockIDPConfigurator = mock(IdentityProviderConfigurator.class);
        when(mockIDPConfigurator.getIdentityProviderDefinitionsForZone(IdentityZoneHolder.get())).thenReturn(idps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        Model model = new ExtendedModelMap();
        endpoint.loginForHtml(model, null, request);

        List<IdentityProviderDefinition> idpDefinitions = (List<IdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<IdentityProviderDefinition> iterator = idpDefinitions.iterator();
        IdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
    }

    @Test
    public void testFilterIdpsWithNoSavedRequest() throws Exception {
        // mock IdentityProviderConfigurator
        List<IdentityProviderDefinition> idps = getIdps();
        IdentityProviderConfigurator mockIDPConfigurator = mock(IdentityProviderConfigurator.class);
        when(mockIDPConfigurator.getIdentityProviderDefinitionsForZone(IdentityZoneHolder.get())).thenReturn(idps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        Model model = new ExtendedModelMap();
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());

        List<IdentityProviderDefinition> idpDefinitions = (List<IdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<IdentityProviderDefinition> iterator = idpDefinitions.iterator();
        IdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
    }

    @Test
    public void testFilterIDPsForAuthcodeClient() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl())
            .thenReturn("http://localhost:8080/uaa/oauth/authorize?client_id=identity&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        request.setSession(session);
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation("allowedproviders", Arrays.asList("my-client-awesome-idp"));
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId("client-id")).thenReturn(clientDetails);

        // mock IdentityProviderConfigurator
        List<IdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(getIdentityProviderDefinition("my-client-awesome-idp"));
        IdentityProviderConfigurator mockIDPConfigurator = mock(IdentityProviderConfigurator.class);
        when(mockIDPConfigurator.getIdentityProviderDefinitionsForClient(Arrays.asList("my-client-awesome-idp"), IdentityZoneHolder.get(), false)).thenReturn(clientIDPs);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setClientDetailsService(clientDetailsService);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        Model model = new ExtendedModelMap();
        endpoint.loginForHtml(model, null, request);

        List<IdentityProviderDefinition> idpDefinitions = (List<IdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(1, idpDefinitions.size());

        IdentityProviderDefinition clientIdp = idpDefinitions.iterator().next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
    }

    private LoginInfoEndpoint getEndpoint() {
        LoginInfoEndpoint endpoint = new LoginInfoEndpoint();
        endpoint.setBaseUrl("http://someurl");
        IdentityProviderConfigurator emptyConfigurator = new IdentityProviderConfigurator();
        endpoint.setIdpDefinitions(emptyConfigurator);
        endpoint.setEnvironment(new MockEnvironment());
        return endpoint;
    }

    private List<IdentityProviderDefinition> getIdps() {
        List<IdentityProviderDefinition> idps = new LinkedList<>();

        idps.add(getIdentityProviderDefinition("awesome-idp"));
        idps.add(getIdentityProviderDefinition("my-client-awesome-idp"));

        return idps;
    }

    private IdentityProviderDefinition getIdentityProviderDefinition(String idpEntityAlias) {
        IdentityProviderDefinition idp1 = new IdentityProviderDefinition();
        idp1.setIdpEntityAlias(idpEntityAlias);
        idp1.setShowSamlLink(true);
        idp1.setZoneId("uaa");
        return idp1;
    }
}
