package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.ui.ExtendedModelMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class LoginInfoEndpointTests {

    public static final String HTTP_LOCALHOST_8080_UAA = "http://localhost:8080/uaa";
    private UaaPrincipal marissa;
    private List<Prompt> prompts;
    private ExtendedModelMap model = new ExtendedModelMap();
    private SamlIdentityProviderConfigurator mockIDPConfigurator;
    private List<SamlIdentityProviderDefinition> idps;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityProvider uaaProvider;
    private IdentityZoneConfiguration originalConfiguration;

    @Before
    public void setUpPrincipal() {
        IdentityZoneHolder.clear();
        marissa = new UaaPrincipal("marissa-id","marissa","marissa@test.org","origin",null, IdentityZoneHolder.get().getId());
        prompts = new LinkedList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "text", "One Time Code ( Get one at "+HTTP_LOCALHOST_8080_UAA+"/passcode )"));
        mockIDPConfigurator = mock(SamlIdentityProviderConfigurator.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        uaaProvider = new IdentityProvider();
        when(identityProviderProvisioning.retrieveByOrigin(eq(OriginKeys.UAA), anyString())).thenReturn(uaaProvider);
        when(identityProviderProvisioning.retrieveByOrigin(eq(OriginKeys.LDAP), anyString())).thenReturn(new IdentityProvider());
        idps = getIdps();
        originalConfiguration = IdentityZoneHolder.get().getConfig();
        IdentityZoneHolder.get().setConfig(new IdentityZoneConfiguration());
    }

    @After
    public void clearZoneHolder() {
        IdentityZoneHolder.clear();
        IdentityZoneHolder.get().setConfig(originalConfiguration);
    }

    @Test
    public void testLoginReturnsSystemZone() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertEquals(OriginKeys.UAA, model.asMap().get("zone_name"));
    }

    @Test
    public void testLoginReturnsOtherZone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("other-zone-id");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint();
        assertFalse(model.containsAttribute("zone_name"));
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertEquals("some_other_zone", model.asMap().get("zone_name"));
    }

    @Test
    public void customSelfserviceLinks_OnlyApplyToDefaultZone_Html() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSignup("http://custom_signup_link");
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setPasswd("http://custom_passwd_link");
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertEquals("http://custom_signup_link", ((Map<String, String>) model.asMap().get("links")).get("createAccountLink"));
        assertEquals("http://custom_passwd_link", ((Map<String, String>) model.asMap().get("links")).get("forgotPasswordLink"));

        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("some_id");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        assertNull(model.asMap().get("createAccountLink"));
        assertNull(model.asMap().get("forgotPasswordLink"));
        //ui links
        assertEquals("/create_account", ((Map<String, String>) model.asMap().get("links")).get("createAccountLink"));
        assertEquals("/forgot_password", ((Map<String, String>) model.asMap().get("links")).get("forgotPasswordLink"));
        //json links
        assertEquals("/create_account", ((Map<String, String>) model.asMap().get("links")).get("register"));
        assertEquals("/forgot_password", ((Map<String, String>) model.asMap().get("links")).get("passwd"));
    }

    @Test
    public void customSelfserviceLinks_OnlyApplyToDefaultZone_Json() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSignup("http://custom_signup_link");
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setPasswd("http://custom_passwd_link");
        endpoint.loginForJson(model, null);
        assertNull(((Map<String, String>) model.asMap().get("links")).get("createAccountLink"));
        assertNull(((Map<String, String>) model.asMap().get("links")).get("forgotPasswordLink"));
        assertEquals("http://custom_signup_link", ((Map<String, String>) model.asMap().get("links")).get("register"));
        assertEquals("http://custom_passwd_link", ((Map<String, String>) model.asMap().get("links")).get("passwd"));

        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("some_id");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        endpoint.loginForJson(model, null);
        assertNull(model.asMap().get("createAccountLink"));
        assertNull(model.asMap().get("forgotPasswordLink"));
        //ui links
        assertNull("/create_account", ((Map<String, String>) model.asMap().get("links")).get("createAccountLink"));
        assertNull("/forgot_password", ((Map<String, String>) model.asMap().get("links")).get("forgotPasswordLink"));
        //json links
        assertEquals("/create_account", ((Map<String, String>) model.asMap().get("links")).get("register"));
        assertEquals("/forgot_password", ((Map<String, String>) model.asMap().get("links")).get("passwd"));
    }



    @Test
    public void use_login_url_if_present() throws Exception {
        check_links_urls(IdentityZone.getUaa());

    }

    @Test
    public void use_login_url_if_present_in_zone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test","test");
        check_links_urls(zone);
    }

    public void check_links_urls(IdentityZone zone) throws Exception {
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint();
        String baseUrl = "http://uaa.domain.com";
        endpoint.setBaseUrl(baseUrl);
        endpoint.infoForJson(model, null);
        assertEquals(addSubdomainToUrl(baseUrl), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(addSubdomainToUrl(baseUrl.replace("uaa", "login")), ((Map<String, String>) model.asMap().get("links")).get("login"));

        String loginBaseUrl = "http://external-login.domain.com";
        endpoint.setExternalLoginUrl(loginBaseUrl);
        endpoint.infoForJson(model, null);
        assertEquals(addSubdomainToUrl(baseUrl), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(loginBaseUrl, ((Map<String, String>) model.asMap().get("links")).get("login"));

        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(zone))).thenReturn(idps);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.infoForJson(model, null);
        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));
        assertEquals("One Time Code ( Get one at "+addSubdomainToUrl(HTTP_LOCALHOST_8080_UAA) + "/passcode )", ((String[])mapPrompts.get("passcode"))[1]);
    }

    @Test
    public void no_self_service_links_if_self_service_disabled() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("zone","zone");
        zone.setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForJson(model, null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
    }

    @Test
    public void no_ui_links_for_json() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForJson(model, null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("linkCreateAccountShow"));
        assertNull(links.get("fieldUsernameShow"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(links.get("createAccountLink"));
        assertEquals("http://someurl", links.get("login"));
        assertEquals("http://someurl", links.get("uaa"));
        assertEquals("/create_account", links.get("register"));
        assertEquals("/forgot_password", links.get("passwd"));
    }

    @Test
    public void saml_links_for_json() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        when(mockIDPConfigurator.getIdentityProviderDefinitions(anyObject(), anyObject())).thenReturn(idps);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.infoForJson(model, null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertEquals("http://someurl", links.get("login"));
        assertTrue(model.get(LoginInfoEndpoint.IDP_DEFINITIONS) instanceof Map);
        Map<String,String> idpDefinitions = (Map<String,String>)model.get(LoginInfoEndpoint.IDP_DEFINITIONS);
        for (SamlIdentityProviderDefinition def : idps) {
            assertEquals(
                "http://someurl/saml/discovery?returnIDParam=idp&entityID=" + endpoint.getZonifiedEntityId() + "&idp="+def.getIdpEntityAlias()+"&isPassive=true",
                idpDefinitions.get(def.getIdpEntityAlias())
            );
        }
    }

    @Test
    public void saml_links_for_html() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.infoForHtml(model, null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertEquals("http://someurl", links.get("login"));
        assertTrue(model.get(LoginInfoEndpoint.IDP_DEFINITIONS) instanceof List);
    }


    @Test
    public void no_self_service_links_if_internal_user_management_disabled() throws Exception {
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDefinition.setDisableInternalUserManagement(true);
        uaaProvider.setConfig(uaaIdentityProviderDefinition);
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForJson(model, null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
        assertNull(links.get("createAccountLink"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(model.asMap().get("createAccountLink"));
        assertNull(model.asMap().get("forgotPasswordLink"));
    }

    @Test
    public void no_usernamePasswordBoxes_if_internalAuth_and_ldap_disabled() throws Exception {
        when(mockIDPConfigurator.getIdentityProviderDefinitions(anyList(), anyObject())).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(identityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, "uaa")).thenReturn(uaaIdentityProvider);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);

        endpoint.infoForHtml(model, null);
        assertFalse((Boolean) model.get("fieldUsernameShow"));
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
    public void test_PromptLogic() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForHtml(model, null);
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        assertTrue("prompts should be a Map for Html content", model.get("prompts") instanceof Map);
        Map mapPrompts = (Map)model.get("prompts");
        assertEquals("there should be two prompts for html", 2, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNull(mapPrompts.get("passcode"));

        endpoint.infoForJson(model, null);
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        assertTrue("prompts should be a Map for JSON content", model.get("prompts") instanceof Map);
        mapPrompts = (Map)model.get("prompts");
        assertEquals("there should be two prompts for html", 2, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNull(mapPrompts.get("passcode"));

        //add a SAML IDP, should make the passcode prompt appear
        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.infoForJson(model, null);
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        assertTrue("prompts should be a Map for JSON content", model.get("prompts") instanceof Map);
        mapPrompts = (Map)model.get("prompts");
        assertEquals("there should be three prompts for html", 3, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));
    }

    @Test
    public void testFilterIdpsForDefaultZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl()).thenReturn("http://localhost:8080/uaa");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        request.setSession(session);
        // mock SamlIdentityProviderConfigurator
        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, request);

        List<SamlIdentityProviderDefinition> idpDefinitions = (List<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(true, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    public void testFilterIdpsWithNoSavedRequest() throws Exception {
        // mock SamlIdentityProviderConfigurator

        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());

        List<SamlIdentityProviderDefinition> idpDefinitions = (List<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(true, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    public void testFilterIDPsForAuthcodeClientInDefaultZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId("client-id")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        when(mockIDPConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(IdentityZone.getUaa()))).thenReturn(clientIDPs);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setClientDetailsService(clientDetailsService);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, request);

        List<SamlIdentityProviderDefinition> idpDefinitions = (List<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        SamlIdentityProviderDefinition clientIdp = idpDefinitions.iterator().next();
        assertEquals("my-client-awesome-idp1", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(false, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    public void testFilterIDPsForAuthcodeClientInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        IdentityZoneHolder.set(zone);

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2");

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId("client-id")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        SamlIdentityProviderConfigurator mockIDPConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(mockIDPConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(zone))).thenReturn(clientIDPs);


        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setClientDetailsService(clientDetailsService);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, request);

        List<SamlIdentityProviderDefinition> idpDefinitions = (List<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        SamlIdentityProviderDefinition clientIdp = idpDefinitions.iterator().next();
        assertEquals("my-client-awesome-idp1", clientIdp.getIdpEntityAlias());
        assertEquals(true, clientIdp.isShowSamlLink());
        assertEquals(false, model.asMap().get("fieldUsernameShow"));
        assertEquals(false, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    public void testFilterIDPsForAuthcodeClientWithNoAllowedIDPsInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId("client-id")).thenReturn(clientDetails);

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        IdentityZoneHolder.set(zone);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setClientDetailsService(clientDetailsService);
        // mock SamlIdentityProviderConfigurator
        SamlIdentityProviderConfigurator mockIDPConfigurator = mock(SamlIdentityProviderConfigurator.class);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, request);
        verify(mockIDPConfigurator).getIdentityProviderDefinitions(null, zone);
    }

    private MockHttpServletRequest getMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl())
            .thenReturn("http://localhost:8080/uaa/oauth/authorize?client_id=identity&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        request.setSession(session);
        return request;
    }

    private LoginInfoEndpoint getEndpoint() {
        LoginInfoEndpoint endpoint = new LoginInfoEndpoint();
        endpoint.setBaseUrl("http://someurl");
        SamlIdentityProviderConfigurator emptyConfigurator = new SamlIdentityProviderConfigurator();
        endpoint.setIdpDefinitions(emptyConfigurator);
        IdentityZoneHolder.get().getConfig().setPrompts(prompts);
        endpoint.setProviderProvisioning(identityProviderProvisioning);
        return endpoint;
    }

    private List<SamlIdentityProviderDefinition> getIdps() {
        List<SamlIdentityProviderDefinition> idps = new LinkedList<>();
        idps.add(createIdentityProviderDefinition("awesome-idp", "uaa"));
        idps.add(createIdentityProviderDefinition("my-client-awesome-idp", "uaa"));
        return idps;
    }

    private SamlIdentityProviderDefinition createIdentityProviderDefinition(String idpEntityAlias, String zoneId) {
        SamlIdentityProviderDefinition idp1 = new SamlIdentityProviderDefinition()
            .setMetaDataLocation("metadataLocation for " + idpEntityAlias)
            .setIdpEntityAlias(idpEntityAlias)
            .setNameID("nameID for " + idpEntityAlias)
            .setMetadataTrustCheck(true)
            .setLinkText("link text for " + idpEntityAlias)
            .setIconUrl("icon url for " + idpEntityAlias)
            .setZoneId(zoneId);
        idp1.setIdpEntityAlias(idpEntityAlias);
        idp1.setShowSamlLink(true);
        idp1.setZoneId(zoneId);
        return idp1;
    }
}
