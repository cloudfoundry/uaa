/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authorization.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.SignerProvider;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenMvcMockTests extends InjectedMockContextTest {

    private String SECRET = "secret";
    private String GRANT_TYPES = "password,implicit,client_credentials,authorization_code";
    private String TEST_REDIRECT_URI = "http://test.example.org/redirect";

    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private JdbcClientDetailsService clientDetailsService;
    private JdbcScimUserProvisioning userProvisioning;
    private JdbcScimGroupProvisioning groupProvisioning;
    private JdbcScimGroupMembershipManager groupMembershipManager;
    private UaaTokenServices tokenServices;
    private Set<String> defaultAuthorities;
    private SignerProvider signerProvider;
    private UaaTokenServices uaaTokenServices;

    private IdentityZoneProvisioning identityZoneProvisioning;
    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;

    @Before
    public void setUpContext() throws Exception {
        testClient = new TestClient(getMockMvc());
        testAccounts = UaaTestAccounts.standard(null);
        clientDetailsService = (JdbcClientDetailsService) getWebApplicationContext().getBean("jdbcClientDetailsService");
        userProvisioning = (JdbcScimUserProvisioning) getWebApplicationContext().getBean("scimUserProvisioning");
        groupProvisioning = (JdbcScimGroupProvisioning) getWebApplicationContext().getBean("scimGroupProvisioning");
        groupMembershipManager = (JdbcScimGroupMembershipManager) getWebApplicationContext().getBean("groupMembershipManager");
        tokenServices = (UaaTokenServices) getWebApplicationContext().getBean("tokenServices");
        defaultAuthorities = (Set<String>) getWebApplicationContext().getBean("defaultUserAuthorities");
        signerProvider = getWebApplicationContext().getBean(SignerProvider.class);
        uaaTokenServices = getWebApplicationContext().getBean(UaaTokenServices.class);
        identityZoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        jdbcScimUserProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        uaaAuthorizationEndpoint = getWebApplicationContext().getBean(UaaAuthorizationEndpoint.class);
        IdentityZoneHolder.clear();
        uaaAuthorizationEndpoint.setFallbackToAuthcode(false);
    }

    private IdentityZone setupIdentityZone(String subdomain) {
        IdentityZone zone = new IdentityZone();
        zone.setId(UUID.randomUUID().toString());
        zone.setName(subdomain);
        zone.setSubdomain(subdomain);
        zone.setDescription(subdomain);
        identityZoneProvisioning.create(zone);
        return zone;
    }

    private IdentityProvider setupIdentityProvider() {
        return setupIdentityProvider(Origin.UAA);
    }
    private IdentityProvider setupIdentityProvider(String origin) {
        IdentityProvider defaultIdp = new IdentityProvider();
        defaultIdp.setName(origin);
        defaultIdp.setType(origin);
        defaultIdp.setOriginKey(origin);
        defaultIdp.setIdentityZoneId(IdentityZoneHolder.get().getId());
        return identityProviderProvisioning.create(defaultIdp);
    }

    protected void setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove) {
        setUpClients(id, authorities, scopes, grantTypes, autoapprove, null);
    }
    protected void setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri) {
        setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, null);
    }
    protected void setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps) {
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        c.setClientSecret(SECRET);
        c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(TEST_REDIRECT_URI)));
        Map<String, Object> additional = new HashMap<>();
        additional.put(ClientConstants.AUTO_APPROVE, autoapprove.toString());
        if (allowedIdps!=null && !allowedIdps.isEmpty()) {
            additional.put(ClientConstants.ALLOWED_PROVIDERS, allowedIdps);
        }
        c.setAdditionalInformation(additional);
        if (StringUtils.hasText(redirectUri)) {
            c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUri)));
        }
        clientDetailsService.addClientDetails(c);
    }

    protected ScimUser setUpUser(String username, String scopes) {
        return setUpUser(username, scopes, Origin.UAA);
    }
    protected ScimUser setUpUser(String username, String scopes, String origin) {
        ScimUser user = new ScimUser(null, username, "GivenName", "FamilyName");
        user.setPassword(SECRET);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("test@test.org");
        email.setPrimary(true);
        user.setEmails(Arrays.asList(email));
        user.setVerified(true);
        user.setOrigin(origin);

        user = userProvisioning.createUser(user, SECRET);

        Set<String> scopeSet = StringUtils.commaDelimitedListToSet(scopes);
        Set<ScimGroup> groups = new HashSet<>();
        for (String scope : scopeSet) {
            ScimGroup g = createIfNotExist(scope);
            groups.add(g);
            addMember(user, g);
        }

        return userProvisioning.retrieve(user.getId());
    }

    protected ScimGroupMember addMember(ScimUser user, ScimGroup group) {
        ScimGroupMember gm = new ScimGroupMember(user.getId());
        return groupMembershipManager.addMember(group.getId(), gm);
    }

    protected ScimGroup createIfNotExist(String scope) {
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \"" + scope + "\"");
        if (exists.size() > 0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(scope));
        }
    }

    @Test
    public void testClientIdentityProviderWithoutAllowedProvidersForPasswordGrantWorksInOtherZone() throws Exception {
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(Origin.UAA);

        String clientId2 = "testclient"+new RandomValueStringGenerator().generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));

        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isOk());

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId2 + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId2))
            .andExpect(status().isOk());


    }


    @Test
    public void testClientIdentityProviderClientWithoutAllowedProvidersForAuthCodeAlreadyLoggedInWorksInAnotherZone() throws Exception {
        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(Origin.UAA);

        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String clientId2 = "testclient"+new RandomValueStringGenerator().generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));

        String clientId3 = "testclient"+new RandomValueStringGenerator().generate();
        setUpClients(clientId3, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(Origin.LOGIN_SERVER));

        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();
        IdentityZoneHolder.clear();

        //no providers is ok
        getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isFound());

        //correct provider is ok
        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId2)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isFound())
            .andReturn();

        //other provider, not ok
        getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId3)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isUnauthorized())
            .andExpect(model().attributeExists("error"))
            .andExpect(model().attribute("error_message_code","login.invalid_idp"));


        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);

    }

    @Test
    public void testClientIdentityProviderRestrictionForPasswordGrant() throws Exception {
        //a client with allowed providers in the default zone should be rejected if the client is not allowed
        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String clientId2 = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String idpOrigin = "origin-"+new RandomValueStringGenerator().generate();
        IdentityProvider provider = setupIdentityProvider(idpOrigin);

        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        //create a user in the UAA identity provider
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);


        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isUnauthorized());

        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId2 + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId2))
            .andExpect(status().isOk());
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenLenient() throws Exception {
        uaaAuthorizationEndpoint.setFallbackToAuthcode(true);
        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", true);
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();

        MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(OAuth2Utils.SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenStrict() throws Exception {
        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", true);
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();

        MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(OAuth2Utils.SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertEquals("invalid_client", ((List<String>) query.get("error")).get(0));
        assertEquals("Unauthorized grant type: implicit", ((List<String>) query.get("error_description")).get(0));
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenLenientWhenAppNotApproved() throws Exception {
        uaaAuthorizationEndpoint.setFallbackToAuthcode(true);

        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", false);
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Arrays.asList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code id_token")));
        authorizationRequest.setState(state);

        session.setAttribute("authorizationRequest", authorizationRequest);

        MvcResult result  = getMockMvc().perform(post("/oauth/authorize")
            .session(session)
            .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenStrictWhenAppNotApproved() throws Exception {
        uaaAuthorizationEndpoint.setFallbackToAuthcode(false);

        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", false);
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Arrays.asList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code", "id_token")));
        authorizationRequest.setState(state);
        session.setAttribute("authorizationRequest", authorizationRequest);

        MvcResult result  = getMockMvc().perform(post("/oauth/authorize")
            .session(session)
            .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertEquals("invalid_client", ((List<String>) query.get("error")).get(0));
        assertEquals("Unauthorized grant type: implicit", ((List<String>) query.get("error_description")).get(0));
    }

    @Test
    public void testAuthorizationCodeGrantWithEncodedRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=%7B%22orgGuid%22%3A%22org-guid%22%2C%22spaceGuid%22%3A%22space-guid%22%2C%22appGuid%22%3A%22app-guid%22%2C%22redirect%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
        //String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String clientId = "authclient-"+new RandomValueStringGenerator().generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+new RandomValueStringGenerator().generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes);
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        location = location.substring(0,location.indexOf("&code="));
        assertEquals(redirectUri, location);
    }

    @Test
    public void testImplicitGrantWithFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, "&");
    }

    @Test
    public void testImplicitGrantWithNoFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, "#");
    }

    protected void testImplicitGrantRedirectUri(String redirectUri, String delim) throws Exception {
        String clientId = "authclient-"+new RandomValueStringGenerator().generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+new RandomValueStringGenerator().generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes);
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        assertTrue(location.startsWith(redirectUri + delim + "token_type=bearer&access_token"));
    }


    @Test
    public void testOpenIdToken() throws Exception {
        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String username = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes);

        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));


        //password grant - request for id_token
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param(OAuth2Utils.RESPONSE_TYPE,"token id_token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param("username", username)
            .param("password", SECRET)
            .param(OAuth2Utils.SCOPE, "openid");
        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get("refresh_token"));
        assertNotNull(token.get("id_token"));
        assertEquals(token.get("access_token"), token.get("id_token"));
        validateOpenIdConnectToken((String)token.get("id_token"), developer.getId(), clientId);

        //implicit grant - request for id_token using our old-style direct authentication
        //this returns a redirect with a fragment in the URL/Location header
        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", username, SECRET);
        oauthTokenPost = post("/oauth/authorize")
            .header("Accept", "application/json")
            .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
            .param(OAuth2Utils.GRANT_TYPE, "implicit")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
            .param("credentials", credentials)
            .param(OAuth2Utils.STATE, new RandomValueStringGenerator().generate())
            .param(OAuth2Utils.SCOPE, "openid");
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(((List<String>)token.get("access_token")).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        assertEquals(((List<String>)token.get("access_token")).get(0), ((List<String>)token.get("id_token")).get(0));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), clientId);

        //authorization_code grant - requesting id_token
        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        String state = new RandomValueStringGenerator().generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        String code = ((List<String>) token.get("code")).get(0);

        oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param("code", code)
            .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get("refresh_token"));
        assertNotNull(token.get("id_token"));
        assertEquals(token.get("access_token"), token.get("id_token"));
        validateOpenIdConnectToken((String)token.get("id_token"), developer.getId(), clientId);


        //hybrid flow defined in - response_types=code token id_token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        SecurityContextHolder.getContext().setAuthentication(auth);
        session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        state = new RandomValueStringGenerator().generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token token")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("access_token")).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        assertEquals(((List<String>)token.get("access_token")).get(0), ((List<String>)token.get("id_token")).get(0));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), clientId);

        //hybrid flow defined in - response_types=code token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        SecurityContextHolder.getContext().setAuthentication(auth);
        session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        state = new RandomValueStringGenerator().generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token token")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("access_token")).get(0));

        //hybrid flow defined in - reesponse_types=code id_token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        SecurityContextHolder.getContext().setAuthentication(auth);
        session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );

        state = new RandomValueStringGenerator().generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token token")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), clientId);
    }

    private void validateOpenIdConnectToken(String token, String userId, String clientId) {
        Map<String,Object> result = getClaimsForToken(token);
        String iss = (String)result.get(Claims.ISS);
        assertEquals(uaaTokenServices.getTokenEndpoint(), iss);
        String sub = (String)result.get(Claims.SUB);
        assertEquals(userId, sub);
        List<String> aud = (List<String>)result.get(Claims.AUD);
        assertTrue(aud.contains(clientId));
        Integer exp = (Integer)result.get(Claims.EXP);
        assertNotNull(exp);
        Integer iat = (Integer)result.get(Claims.IAT);
        assertNotNull(iat);
        assertTrue(exp>iat);

        //TODO OpenID
//        Integer auth_time = (Integer)result.get(Claims.AUTH_TIME);
//        assertNotNull(auth_time);


    }

    private Map<String, Object> getClaimsForToken(String token) {
        Jwt tokenJwt = null;
        try {
            tokenJwt = JwtHelper.decodeAndVerify(token, signerProvider.getVerifier());
        } catch (Throwable t) {
            throw new InvalidTokenException("Invalid token (could not decode): " + token);
        }

        Map<String, Object> claims = null;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }

        return claims;
    }

    public static Map<String, List<String>> splitQuery(URL url) throws UnsupportedEncodingException {
        Map<String, List<String>> params = new LinkedHashMap<>();
        String[] kv = url.getQuery().split("&");
        for (String pair : kv) {
            int i = pair.indexOf("=");
            String key = i > 0 ? URLDecoder.decode(pair.substring(0, i), "UTF-8") : pair;
            if (!params.containsKey(key)) {
                params.put(key, new LinkedList<String>());
            }
            String value = i > 0 && pair.length() > i + 1 ? URLDecoder.decode(pair.substring(i + 1), "UTF-8") : null;
            params.get(key).add(value);
        }
        return params;
    }

    @Test
    public void testWildcardPasswordGrant() throws Exception {
        String clientId = "testclient"+new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser"+new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        Set<String> allUserScopes = new HashSet<>();
        allUserScopes.addAll(defaultAuthorities);
        allUserScopes.addAll(StringUtils.commaDelimitedListToSet(userScopes));

        validatePasswordGrantToken(
            clientId,
            userId,
            "",
            allUserScopes.toArray(new String[0])
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "space.*.developer",
            "space.1.developer",
            "space.2.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "space.2.developer",
            "space.2.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin",
            "org.12345.admin"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.1.developer",
            "org.12345.admin",
            "space.1.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.*.developer",
            "org.12345.admin",
            "space.1.developer",
            "space.2.developer"
        );
        Set<String> set1 = new HashSet<>(defaultAuthorities);
        set1.addAll(Arrays.asList("org.12345.admin",
            "space.1.developer",
            "space.2.developer",
            "scope.one",
            "scope.two",
            "scope.three"));

        set1.remove("openid");//not matched here
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.*.developer,*.*",
            set1.toArray(new String[0])
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.*.developer,scope.*",
            "org.12345.admin",
            "space.1.developer",
            "space.2.developer",
            "scope.one",
            "scope.two",
            "scope.three"
        );


    }

    public String validatePasswordGrantToken(String clientId, String username, String requestedScopes, String... expectedScopes) throws Exception {
        String t1 = testClient.getUserOAuthAccessToken(clientId, SECRET, username, SECRET, requestedScopes);
        OAuth2Authentication a1 = tokenServices.loadAuthentication(t1);
        assertEquals(expectedScopes.length, a1.getOAuth2Request().getScope().size());
        assertThat(
            a1.getOAuth2Request().getScope(),
            containsInAnyOrder(expectedScopes)
        );
        return t1;
    }

    @Test
    public void testLoginAddNewUserForOauthTokenPasswordGrant() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");
        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a external login-server request
        String username = new RandomValueStringGenerator().generate();
        String email = username + "@addnew.test.org";
        String first = "firstName";
        String last = "lastName";
        //success - contains everything we need
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "true")
            .param("grant_type", "password")
            .param("client_id", "cf")
            .param("client_secret", "")
            .param("username", username)
            .param("family_name", last)
            .param("given_name", first)
            .param("email", email)
            .param(Origin.ORIGIN, Origin.UAA))
            .andExpect(status().isOk());
        UaaUserDatabase db = getWebApplicationContext().getBean(UaaUserDatabase.class);
        UaaUser user = db.retrieveUserByName(username, Origin.UAA);
        assertNotNull(user);
        assertEquals(username, user.getUsername());
        assertEquals(email, user.getEmail());
        assertEquals(first, user.getGivenName());
        assertEquals(last, user.getFamilyName());
    }

    @Test
    public void testLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");

        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a external login-server request

        //success - contains everything we need
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isOk());

        //success - user_id only, contains everything we need
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isOk());

        //success - username/origin only, contains everything we need
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isOk());

        //failure - missing client ID
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isUnauthorized());

        //failure - invalid client ID
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", "dasdasdadas")
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - invalid client secret
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET + "dasdasasas")
            .param("user_id", developer.getId()))
            .andExpect(status().isUnauthorized());

        //failure - missing client_id and secret
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId() + "1dsda")
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - no user ID and an invalid origin must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param(Origin.ORIGIN, developer.getOrigin() + "dasda"))
            .andExpect(status().isUnauthorized());

        //failure - no user ID, invalid username must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "asdasdas")
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());


        //success - pretend to be login server - add new user is true - any username will be added
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "true")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isOk());

        //failure - pretend to be login server - add new user is false
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - source=login missing, so missing user password should trigger a failure
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - add_new is missing, so missing user password should trigger a failure
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testOtherOauthResourceLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);


        String oauthClientId = "testclient" + new RandomValueStringGenerator().generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);


        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //failure - success only if token has oauth.login
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - success only if token has oauth.login
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isForbidden());

        //failure - success only if token has oauth.login
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - missing client ID
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isForbidden());

        //failure - invalid client ID
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", "dasdasdadas")
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - invalid client secret
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET + "dasdasasas")
            .param("user_id", developer.getId()))
            .andExpect(status().isForbidden());

        //failure - missing client_id and secret
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId() + "1dsda")
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - no user ID and an invalid origin must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param(Origin.ORIGIN, developer.getOrigin() + "dasda"))
            .andExpect(status().isForbidden());

        //failure - no user ID, invalid username must fail
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "asdasdas")
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());


        //failure - success only if token has oauth.login
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "true")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - pretend to be login server - add new user is false
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param(Origin.ORIGIN, developer.getOrigin()))
            .andExpect(status().isForbidden());
    }

    @Test
    public void testOtherClientAuthenticationMethods() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);


        String oauthClientId = "testclient" + new RandomValueStringGenerator().generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);


        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //success - regular password grant but client is authenticated using POST parameters
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //success - regular password grant but client is authenticated using token
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", oauthClientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((oauthClientId + ":" + SECRET).getBytes())))
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetClientCredentialsTokenForDefaultIdentityZone() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk());
    }

    @Test
    public void testGetClientCredentialsTokenForOtherIdentityZone() throws Exception {
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        getMockMvc().perform(post("http://" + subdomain + ".localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk());
    }

    @Test
    public void testGetClientCredentialsTokenForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        getMockMvc().perform(post("http://localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            //.header("Host", subdomain + ".localhost") - with updated Spring, this now works for request.getServerName
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetClientCredentialsTokenForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        setupIdentityZone(subdomain);
        getMockMvc().perform(post("http://" + subdomain + ".localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetPasswordGrantTokenForOtherZone() throws Exception {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider();
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));

        setUpUser(username);

        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isOk());
    }

    @Test
    public void testGetPasswordGrantForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetPasswordGrantForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        String subdomain = "testzone"+new RandomValueStringGenerator().generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);

        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetTokenScopesNotInAuthentication() throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64(("identity:identitysecret").getBytes()));

        ScimUser user = setUpUser(new RandomValueStringGenerator().generate()+"@test.org");

        String zoneadmingroup = "zones."+new RandomValueStringGenerator().generate()+".admin";
        ScimGroup group = new ScimGroup(zoneadmingroup);
        group = groupProvisioning.create(group);
        ScimGroupMember member = new ScimGroupMember(user.getId());
        groupMembershipManager.addMember(group.getId(),member);

        UaaPrincipal p = new UaaPrincipal(user.getId(),user.getUserName(),user.getPrimaryEmail(), Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);

        Assert.assertTrue(auth.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );


        String state = new RandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            .session(session)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, "identity")
            .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(location);
        String code = builder.build().getQueryParams().get("code").get(0);

        authRequest = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param("code", code)
            .param(OAuth2Utils.CLIENT_ID, "identity")
            .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        result = getMockMvc().perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), TestClient.OAuthToken.class);

        OAuth2Authentication a1 = tokenServices.loadAuthentication(oauthToken.accessToken);

        assertEquals(4, a1.getOAuth2Request().getScope().size());
        assertThat(
            a1.getOAuth2Request().getScope(),
            containsInAnyOrder(new String[]{zoneadmingroup, "openid", "cloud_controller.read", "cloud_controller.write"})
        );

    }

    @Test
    public void testRevocablePasswordGrantTokenForDefaultZone() throws Exception {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        String tokenKey = "access_token";
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(Origin.UAA));
        setUpUser(username);

        Map<String,Object> tokenResponse =
            JsonUtils.readValue(
                getMockMvc().perform(post("/oauth/token")
                    .param("username", username)
                    .param("password", "secret")
                    .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                    .param(OAuth2Utils.RESPONSE_TYPE, "token")
                    .param(OAuth2Utils.GRANT_TYPE, "password")
                    .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {
                });
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String)tokenResponse.get(tokenKey);
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>(){});
        assertNotNull("Token revocation signature must exist", claims.get(Claims.REVOCATION_SIGNATURE));
        assertTrue("Token revocation signature must be a string", claims.get(Claims.REVOCATION_SIGNATURE) instanceof String);
        assertTrue("Token revocation signature must have data", StringUtils.hasText((String) claims.get(Claims.REVOCATION_SIGNATURE)));
    }

    private ScimUser setUpUser(String username) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Arrays.asList(email));
        return jdbcScimUserProvisioning.createUser(scimUser, "secret");
    }

    public static class MockSecurityContext implements SecurityContext {

        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        public MockSecurityContext(Authentication authentication) {
            this.authentication = authentication;
        }

        @Override
        public Authentication getAuthentication() {
            return this.authentication;
        }

        @Override
        public void setAuthentication(Authentication authentication) {
            this.authentication = authentication;
        }
    }
}
