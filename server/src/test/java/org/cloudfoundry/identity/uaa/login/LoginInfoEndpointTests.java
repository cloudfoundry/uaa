/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.util.RestTemplateFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cloudfoundry.identity.uaa.login.LoginInfoEndpoint.OAUTH_LINKS;
import static org.cloudfoundry.identity.uaa.login.LoginInfoEndpoint.SHOW_LOGIN_LINKS;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyBoolean;
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
    private XOAuthProviderConfigurator configurator;

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
        configurator = new XOAuthProviderConfigurator(identityProviderProvisioning, mock(UrlContentCache.class), mock(RestTemplateFactory.class));
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
    public void testAlreadyLoggedInRedirectsToHome() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        UaaAuthentication authentication = mock(UaaAuthentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        String result = endpoint.loginForHtml(model, authentication, new MockHttpServletRequest());
        assertEquals("redirect:/home", result);
    }

    @Test
    public void testDeleteSavedAccount() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        LoginInfoEndpoint endpoint = getEndpoint();
        String userId = "testUserId";
        String result = endpoint.deleteSavedAccount(request, response, userId);
        Cookie[] cookies = response.getCookies();
        assertEquals(cookies.length, 1);
        assertEquals(cookies[0].getName(), "Saved-Account-" + userId);
        assertEquals(cookies[0].getMaxAge(), 0);
        assertEquals("redirect:/login", result);
    }
    @Test
    public void testSavedAccountsPopulatedOnModel() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(model, null, request);

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));

        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bob", savedAccount0.getUsername());
        assertEquals("bob@example.com", savedAccount0.getEmail());
        assertEquals("uaa", savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("tim", savedAccount1.getUsername());
        assertEquals("tim@example.org", savedAccount1.getEmail());
        assertEquals("ldap", savedAccount1.getOrigin());
        assertEquals("zzzz", savedAccount1.getUserId());
    }

    @Test
    public void testSavedAccountsEncodedAndUnEncoded() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        // write Cookie1 without URLencode into value, situation before this correction
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", JsonUtils.writeValueAsString(savedAccount));

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        // write Cookie2 with URLencode into value, situation after this correction
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(model, null, request);

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));
        // evaluate that both cookies can be parsed out has have same values
        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bill", savedAccount0.getUsername());
        assertEquals("bill@example.com", savedAccount0.getEmail());
        assertEquals("uaa", savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("bill", savedAccount1.getUsername());
        assertEquals("bill@example.com", savedAccount1.getEmail());
        assertEquals("uaa", savedAccount1.getOrigin());
        assertEquals("xxxx", savedAccount1.getUserId());
    }

    @Test(expected=NullPointerException.class)
    public void testSavedAccountsInvalidCookie() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", "%2");

        request.setCookies(cookie1);
        endpoint.loginForHtml(model, null, request);
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
    public void customSelfserviceLinks_ApplyToAllZone_Html() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("some_id");
        zone.setSubdomain(zone.getName());
        IdentityZoneConfiguration config = zone.getConfig();
        IdentityZoneHolder.set(zone);
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSignup("http://custom_signup_link");
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setPasswd("http://custom_passwd_link");
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", model);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", endpoint.getSelfServiceLinks());

        //null config
        zone.setConfig(null);
        validateSelfServiceLinks("/create_account", "/forgot_password", endpoint.getSelfServiceLinks());

        //null config with globals
        endpoint.setGlobalLinks(new Links().setSelfService(new Links.SelfService().setSignup("/signup").setPasswd("/passwd")));
        validateSelfServiceLinks("/signup", "/passwd", endpoint.getSelfServiceLinks());

        //null links with globals
        IdentityZoneConfiguration otherConfig = new IdentityZoneConfiguration(null);
        otherConfig.getLinks().setSelfService(new Links.SelfService().setSignup(null).setPasswd(null));
        validateSelfServiceLinks("/signup", "/passwd", endpoint.getSelfServiceLinks());

        //null links with globals using variables
        endpoint.setGlobalLinks(new Links().setSelfService(new Links.SelfService().setSignup("/signup?domain={zone.subdomain}").setPasswd("/passwd?id={zone.id}")));
        validateSelfServiceLinks("/signup?domain="+zone.getSubdomain(), "/passwd?id="+zone.getId(), endpoint.getSelfServiceLinks());

        //zone config overrides global
        zone.setConfig(config);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", endpoint.getSelfServiceLinks());

        //zone config supports variables too
        config.getLinks().getSelfService().setSignup("/local_signup?domain={zone.subdomain}");
        config.getLinks().getSelfService().setPasswd("/local_passwd?id={zone.id}");
        validateSelfServiceLinks("/local_signup?domain="+zone.getSubdomain(), "/local_passwd?id="+zone.getId(), endpoint.getSelfServiceLinks());
    }

    public void validateSelfServiceLinks(String signup, String passwd, Model model) {
        Map<String, String> links = (Map<String, String>) model.asMap().get("links");
        validateSelfServiceLinks(signup, passwd, links);
    }

    public void validateSelfServiceLinks(String signup, String passwd, Map<String,String> links) {
        assertEquals(signup, links.get("createAccountLink"));
        assertEquals(passwd, links.get("forgotPasswordLink"));
        //json links
        assertEquals(signup, links.get("register"));
        assertEquals(passwd, links.get("passwd"));
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
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        assertEquals(addSubdomainToUrl(baseUrl), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(addSubdomainToUrl(baseUrl.replace("uaa", "login")), ((Map<String, String>) model.asMap().get("links")).get("login"));

        String loginBaseUrl = "http://external-login.domain.com";
        endpoint.setExternalLoginUrl(loginBaseUrl);
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        assertEquals(addSubdomainToUrl(baseUrl), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(loginBaseUrl, ((Map<String, String>) model.asMap().get("links")).get("login"));

        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(zone))).thenReturn(idps);
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
    }

    @Test
    public void no_ui_links_for_json() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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
        endpoint.infoForHtml(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertEquals("http://someurl", links.get("login"));
        assertTrue(model.get(LoginInfoEndpoint.IDP_DEFINITIONS) instanceof Collection);
    }

    @Test
    public void no_self_service_links_if_internal_user_management_disabled() throws Exception {
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDefinition.setDisableInternalUserManagement(true);
        uaaProvider.setConfig(uaaIdentityProviderDefinition);
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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

        endpoint.infoForHtml(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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
        endpoint.infoForHtml(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        assertTrue("prompts should be a Map for Html content", model.get("prompts") instanceof Map);
        Map mapPrompts = (Map)model.get("prompts");
        assertEquals("there should be two prompts for html", 2, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNull(mapPrompts.get("passcode"));

        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
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
        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        assertTrue("prompts should be a Map for JSON content", model.get("prompts") instanceof Map);
        mapPrompts = (Map)model.get("prompts");
        assertEquals("there should be three prompts for html", 3, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));

        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(identityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, "uaa")).thenReturn(uaaIdentityProvider);

        endpoint.infoForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));
        assertNotNull("prompts attribute should be present", model.get("prompts"));
        mapPrompts = (Map)model.get("prompts");
        assertNull(mapPrompts.get("username"));
        assertNull(mapPrompts.get("password"));
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
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        request.setSession(session);
        // mock SamlIdentityProviderConfigurator
        when(mockIDPConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setIdpDefinitions(mockIDPConfigurator);
        endpoint.loginForHtml(model, null, request);

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
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

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
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

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.isShowSamlLink()));
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

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.isShowSamlLink()));
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

    @Test
    public void allowedIdpsforClientOIDCProvider() throws MalformedURLException {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId("client-id")).thenReturn(clientDetails);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp3"));

        when(identityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.setClientDetailsService(clientDetailsService);
        endpoint.loginForHtml(model, null, request);

        Map<String, AbstractXOAuthIdentityProviderDefinition> idpDefinitions = (Map<String, AbstractXOAuthIdentityProviderDefinition>) model.asMap().get(OAUTH_LINKS);
        assertEquals(2, idpDefinitions.size());
    }

    @Test
    public void oauth_provider_links_shown() throws Exception {
        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(identityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Collections.singletonList(identityProvider));
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.loginForHtml(model, null, new MockHttpServletRequest());

        assertThat(model.get(SHOW_LOGIN_LINKS), equalTo(true));
    }

    @Test
    public void passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider() throws Exception {
        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition()
            .setAuthUrl(new URL("http://auth.url"))
            .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(identityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Collections.singletonList(identityProvider));
        LoginInfoEndpoint endpoint = getEndpoint();
        endpoint.loginForJson(model, null, new MockHttpServletRequest("GET", endpoint.getBaseUrl()));

        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));

    }

    @Test
    public void we_return_both_oauth_and_oidc_providers() throws Exception {
        RawXOAuthIdentityProviderDefinition oauthDefinition = new RawXOAuthIdentityProviderDefinition()
            .setAuthUrl(new URL("http://auth.url"))
            .setTokenUrl(new URL("http://token.url"));
        OIDCIdentityProviderDefinition oidcDefinition = new OIDCIdentityProviderDefinition()
            .setAuthUrl(new URL("http://auth.url"))
            .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauthProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        oauthProvider.setConfig(oauthDefinition);

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcProvider = MultitenancyFixture.identityProvider("oidc-idp-alias", "uaa");
        oidcProvider.setConfig(oidcDefinition);

        when(identityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Arrays.asList(oauthProvider, oidcProvider));
        LoginInfoEndpoint endpoint = getEndpoint();
        assertEquals(2, endpoint.getOauthIdentityProviderDefinitions(null).size());
    }

    @Test
    public void xoauthCallback_redirectsToHomeIfNoSavedRequest() throws Exception {
        HttpSession session = new MockHttpSession();
        LoginInfoEndpoint endpoint = getEndpoint();
        String redirectUrl = endpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/home", redirectUrl);
    }

    @Test
    public void xoauthCallback_redirectsToSavedRequestIfPresent() throws Exception {
        HttpSession session = new MockHttpSession();
        DefaultSavedRequest savedRequest = Mockito.mock(DefaultSavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn("/some.redirect.url");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        LoginInfoEndpoint endpoint = getEndpoint();
        String redirectUrl = endpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/some.redirect.url", redirectUrl);
    }

    private MockHttpServletRequest getMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl())
            .thenReturn("http://localhost:8080/uaa/oauth/authorize?client_id=identity&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        request.setSession(session);
        return request;
    }

    private LoginInfoEndpoint getEndpoint() {
        LoginInfoEndpoint endpoint = new LoginInfoEndpoint();
        endpoint.setBaseUrl("http://someurl");
        SamlIdentityProviderConfigurator emptyConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(emptyConfigurator.getIdentityProviderDefinitions()).thenReturn(Collections.EMPTY_LIST);
        when(emptyConfigurator.getIdentityProviderDefinitionsForZone(anyObject())).thenReturn(Collections.EMPTY_LIST);
        endpoint.setIdpDefinitions(emptyConfigurator);
        IdentityZoneHolder.get().getConfig().setPrompts(prompts);
        endpoint.setProviderProvisioning(identityProviderProvisioning);
        endpoint.setXoAuthProviderConfigurator(configurator);
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

    private IdentityProvider createOIDCIdentityProvider(String originKey) throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcIdentityProvider= new IdentityProvider<>();
        oidcIdentityProvider.setOriginKey(originKey);
        oidcIdentityProvider.setType(OriginKeys.OIDC10);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("https://"+originKey+".com"));
        oidcIdentityProvider.setConfig(definition);

        return oidcIdentityProvider;

    }
}
