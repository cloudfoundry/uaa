/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.TestClient.OAuthToken;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Assert;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MockMvcUtils {

    public static MockMvcUtils utils() {
        return new MockMvcUtils();
    }

    public IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = UUID.randomUUID().toString();
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, zoneId);

        MvcResult result = mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
    }

    public static class IdentityZoneCreationResult {
        private final IdentityZone identityZone;
        private final UaaPrincipal zoneAdmin;
        private final String zoneAdminToken;

        public IdentityZoneCreationResult(IdentityZone identityZone, UaaPrincipal zoneAdmin, String zoneAdminToken) {
            super();
            this.identityZone = identityZone;
            this.zoneAdmin = zoneAdmin;
            this.zoneAdminToken = zoneAdminToken;
        }

        public IdentityZone getIdentityZone() {
            return identityZone;
        }

        public UaaPrincipal getZoneAdminUser() {
            return zoneAdmin;
        }

        public String getZoneAdminToken() {
            return zoneAdminToken;
        }
    }

    public IdentityZoneCreationResult createOtherIdentityZoneAndReturnResult(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {
        String identityToken = getClientCredentialsOAuthAccessToken(mockMvc, "identity", "identitysecret",
                "zones.write,scim.zones", null);

        IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain, subdomain);

        mockMvc.perform(post("/identity-zones")
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        // use the identity client to grant the zones.<id>.admin scope to a user
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        UaaPrincipal marissa = new UaaPrincipal(db.retrieveUserByName("marissa", Origin.UAA));
        ScimGroup group = new ScimGroup();
        String zoneAdminScope = "zones." + identityZone.getId() + ".admin";
        group.setDisplayName(zoneAdminScope);
        group.setMembers(Collections.singletonList(new ScimGroupMember(marissa.getId())));
        mockMvc.perform(post("/Groups/zones")
                .header("Authorization", "Bearer " + identityToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isCreated());

        // use that user to create an admin client in the new zone
        String zoneAdminAuthcodeToken = getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret",
                marissa.getId(), "marissa", "koala", zoneAdminScope);

        mockMvc.perform(post("/oauth/clients")
                .header("Authorization", "Bearer " + zoneAdminAuthcodeToken)
                .header("X-Identity-Zone-Id", identityZone.getId())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(bootstrapClient)))
                .andExpect(status().isCreated());

        return new IdentityZoneCreationResult(identityZone, marissa, zoneAdminAuthcodeToken);
    }

    public IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext, ClientDetails bootstrapClient) throws Exception {
        return createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, bootstrapClient).getIdentityZone();

    }

    public IdentityZone createOtherIdentityZone(String subdomain, MockMvc mockMvc,
            ApplicationContext webApplicationContext) throws Exception {

        BaseClientDetails client = new BaseClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write");
        client.setClientSecret("admin-secret");

        return createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, client);
    }

    public IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
                                                     IdentityProvider identityProvider, ResultMatcher resultMatcher) throws Exception {
        return createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher, false);
    }
    public IdentityProvider createIdpUsingWebRequest(MockMvc mockMvc, String zoneId, String token,
            IdentityProvider identityProvider, ResultMatcher resultMatcher, boolean update) throws Exception {
        MockHttpServletRequestBuilder requestBuilder =
            update ?
                put("/identity-providers/"+identityProvider.getId())
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityProvider))
            :
                post("/identity-providers/")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityProvider));

        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        MvcResult result = mockMvc.perform(requestBuilder)
                .andExpect(resultMatcher)
                .andReturn();
        if (StringUtils.hasText(result.getResponse().getContentAsString())) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        } else {
            return null;
        }

    }

    public ScimUser createUser(MockMvc mockMvc, String accessToken, ScimUser user) throws Exception {
        MvcResult userResult = mockMvc.perform(post("/Users")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public ScimGroup getGroup(MockMvc mockMvc, String accessToken, String displayName) throws Exception {
        String filter = "displayName eq \""+displayName+"\"";
        SearchResults<ScimGroup> results = JsonUtils.readValue(
            mockMvc.perform(get("/Groups")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .param("filter", filter))
                .andReturn().getResponse().getContentAsString(),
            new TypeReference<SearchResults<ScimGroup>>() {});
        if (results==null || results.getResources()==null || results.getResources().isEmpty()) {
            return null;
        } else {
            return results.getResources().iterator().next();
        }
    }

    public ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return JsonUtils.readValue(
            mockMvc.perform(post("/Groups")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);
    }

    public ScimGroup updateGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return JsonUtils.readValue(
            mockMvc.perform(put("/Groups/" + group.getId())
                .header("If-Match", group.getVersion())
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);
    }
    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails) throws Exception {
        return createClient(mockMvc, accessToken, clientDetails, IdentityZone.getUaa());
    }

    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
            throws Exception {
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        if (! zone.equals(IdentityZone.getUaa())) {
            createClientPost = createClientPost.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }
        return JsonUtils.readValue(
            mockMvc.perform(createClientPost)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
    }

    public BaseClientDetails updateClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails, IdentityZone zone)
        throws Exception {
        MockHttpServletRequestBuilder updateClientPut =
            put("/oauth/clients/" + clientDetails.getClientId())
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        if (! zone.equals(IdentityZone.getUaa())) {
            updateClientPut = updateClientPut.header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        return JsonUtils.readValue(
            mockMvc.perform(updateClientPut)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
    }

    public String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new RandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName() + "@test.org");
        user.setPassword("secret");
        user = MockMvcUtils.utils().createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup("zones." + zoneId + ".admin");
        group.setMembers(Arrays.asList(new ScimGroupMember(user.getId())));
        MockMvcUtils.utils().createGroup(mockMvc, adminToken, group);
        return getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(),
            "secret", group.getDisplayName());
    }

    public String getUserOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String username,
            String password, String scope)
            throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("username", username)
                .param("password", password)
                .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getClientOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String scope)
        throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope) throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + clientSecret)
                        .getBytes()));
        UaaPrincipal p = new UaaPrincipal(userId, username, "test@test.org", Origin.UAA, "", IdentityZoneHolder.get()
                .getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "",
                UaaAuthority.USER_AUTHORITIES);
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
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(location);
        String code = builder.build().getQueryParams().get("code").get(0);

        authRequest = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param("code", code)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        result = mockMvc.perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        TestClient.OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(),
            TestClient.OAuthToken.class);
        return oauthToken.accessToken;

    }

    public String getClientCredentialsOAuthAccessToken(MockMvc mockMvc, String username, String password, String scope,
            String subdomain)
            throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((username + ":" + password).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", username)
                .param("scope", scope);
        if (subdomain != null && !subdomain.equals(""))
            oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        MvcResult result = mockMvc.perform(oauthTokenPost)
                .andExpect(status().isOk())
                .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public SecurityContext getMarissaSecurityContext(ApplicationContext context) {
        return getUaaSecurityContext("marissa", context);
    }

    public SecurityContext getUaaSecurityContext(String username, ApplicationContext context) {
        ScimUserProvisioning userProvisioning = context.getBean(JdbcScimUserProvisioning.class);
        ScimUser user = userProvisioning.query("username eq \""+username+"\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), user.getOrigin(), user.getExternalId(), IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")));
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        return securityContext;
    }


    public <T extends ApplicationEvent>  TestApplicationEventListener<T> addEventListener(ConfigurableApplicationContext applicationContext, Class<T> clazz) {
        TestApplicationEventListener<T> listener = TestApplicationEventListener.forEventClass(clazz);
        applicationContext.addApplicationListener(listener);
        return listener;
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
