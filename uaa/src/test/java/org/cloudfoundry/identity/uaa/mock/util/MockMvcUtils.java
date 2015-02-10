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


import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import junit.framework.Assert;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneCreationRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import scala.actors.threadpool.Arrays;

public class MockMvcUtils {

    public static MockMvcUtils utils() {
        return new MockMvcUtils();
    }

    public IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = UUID.randomUUID().toString();
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, zoneId);

        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);

        MvcResult result = mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated()).andReturn();
        return new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), IdentityZone.class);
    }

    public ScimUser createUser(MockMvc mockMvc, String accessToken, ScimUser user) throws Exception {
        MvcResult userResult = mockMvc.perform(post("/Users")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsBytes(user)))
            .andExpect(status().isCreated()).andReturn();
        return new ObjectMapper().readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return new ObjectMapper().readValue(
            mockMvc.perform(post("/Groups")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsBytes(group)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsByteArray(),
            ScimGroup.class);
    }

    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails) throws Exception {
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + accessToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(clientDetails));
        return new ObjectMapper().readValue(
            mockMvc.perform(createClientPost)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsByteArray(),BaseClientDetails.class);
    }

    public String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new RandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName()+"@test.org");
        user.setPassword("secret");
        user = MockMvcUtils.utils().createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup("zones."+zoneId+".admin");
        group.setMembers(Arrays.asList(new ScimGroupMember[]{new ScimGroupMember(user.getId())}));
        MockMvcUtils.utils().createGroup(mockMvc, adminToken, group);
        return getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secret", group.getDisplayName());
    }

    public String getUserOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String username, String password, String scope)
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
        TestClient.OAuthToken oauthToken = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessTokenAuthCode(MockMvc mockMvc, String clientId, String clientSecret, String userId, String username, String password, String scope) throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        UaaPrincipal p = new UaaPrincipal(userId,username,"test@test.org", Origin.UAA,"", IdentityZoneHolder.get().getId());
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
        result = mockMvc.perform(authRequest).andDo(print()).andExpect(status().is2xxSuccessful()).andReturn();
        TestClient.OAuthToken oauthToken = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), TestClient.OAuthToken.class);
        return oauthToken.accessToken;

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
