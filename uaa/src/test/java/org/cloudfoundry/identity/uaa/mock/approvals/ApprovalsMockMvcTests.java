/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.approvals;


import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class ApprovalsMockMvcTests extends AbstractTokenMockMvcTests {

    private String scopes = "test.scope1,test.scope2,test.scope3";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private ScimUser user1;
    private ClientDetails client1;

    @BeforeEach
    public void createData() {
        user1 = syncGroups(setUpUser(generator.generate(), scopes, OriginKeys.UAA, IdentityZone.getUaaZoneId()));
        client1 = setUpClients(generator.generate(), null, scopes, GRANT_TYPE_AUTHORIZATION_CODE, false);
    }

    @Test
    public void revoke() throws Exception {
        test_oauth_authorize_without_csrf();
        MockHttpSession session = getAuthenticatedSession(user1);
        mockMvc.perform(
            post("/profile")
                .with(cookieCsrf())
                .param("delete", "true")
                .param("clientId", client1.getClientId())
                .session(session)
        )
            .andExpect(status().isFound())
            .andExpect(header().string("Location", "profile"));

    }

    @Test
    public void revoke_invalid_client() throws Exception {
        test_oauth_authorize_without_csrf();
        MockHttpSession session = getAuthenticatedSession(user1);
        mockMvc.perform(
            post("/profile")
                .with(cookieCsrf())
                .param("delete", "true")
                .param("clientId", "invalid_id")
                .session(session)
        )
            .andExpect(status().isFound())
            .andExpect(header().string("Location", "profile?error_message_code=request.invalid_parameter"));
    }

    @Test
    public void test_oauth_authorize_without_csrf() throws Exception {
        String state = generator.generate();

        MockHttpSession session = getAuthenticatedSession(user1);
        mockMvc.perform(
            get("/oauth/authorize")
                .session(session)
                .param(RESPONSE_TYPE, "code")
                .param(STATE, state)
                .param(CLIENT_ID, client1.getClientId()))
            .andExpect(status().isOk()); //200 means the approvals page


        assertNotNull(session.getAttribute("authorizationRequest"));
        assertNotNull(session.getAttribute("org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST"));

        //no token
        mockMvc.perform(
            post("/oauth/authorize")
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","scope.test.scope1")
        )
            .andExpect(status().is4xxClientError());

        //invalid token
        mockMvc.perform(
            post("/oauth/authorize")
                .with(cookieCsrf().useInvalidToken())
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","scope.test.scope1")
        )
            .andExpect(status().is4xxClientError());

        assertNotNull(session.getAttribute("authorizationRequest"));
        assertNotNull(session.getAttribute("org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST"));

        //valid token
        mockMvc.perform(
            post("/oauth/authorize")
                .with(cookieCsrf())
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","scope.test.scope1")
                .param("scope.1","scope.test.scope2")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrlPattern("**/*code=*"));

        assertNull(session.getAttribute("authorizationRequest"));
        assertNull(session.getAttribute("org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST"));

        mockMvc.perform(
            get("/oauth/authorize")
                .session(session)
                .param(RESPONSE_TYPE, "code")
                .param(STATE, state)
                .param(CLIENT_ID, client1.getClientId()))
            .andExpect(status().isFound()); //approval page no longer showing up
    }

    @Test
    public void test_oauth_authorize_modified_scope() throws Exception {
        String state = generator.generate();

        MockHttpSession session = getAuthenticatedSession(user1);
        mockMvc.perform(
            get("/oauth/authorize")
                .session(session)
                .param(RESPONSE_TYPE, "code")
                .param(STATE, state)
                .param(CLIENT_ID, client1.getClientId()))
            .andExpect(status().isOk()); //200 means the approvals page


        assertNotNull(session.getAttribute("authorizationRequest"));
        assertNotNull(session.getAttribute("org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST"));

        mockMvc.perform(
            post("/oauth/authorize")
                .with(cookieCsrf())
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","scope.different.scope")
                .param("scope.1","scope.test.scope2")
        )
        .andDo(print())
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrlPattern("http://test.example.org/redirect?error=invalid_scope&error_description=The%20requested%20scopes%20are%20invalid.%20Please%20use%20valid%20scope%20names%20in%20the%20request*"));

        assertNull(session.getAttribute("authorizationRequest"));
        assertNull(session.getAttribute("org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST"));
    }

    @Test
    public void test_get_approvals() throws Exception {
        test_oauth_authorize_without_csrf();
        MockHttpSession session = getAuthenticatedSession(user1);
        mockMvc.perform(
            get("/profile")
                .session(session)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(client1.getClientId() + "-test.scope1")));
    }

    @Test
    public void test_post_approval_csrf() throws Exception {
        test_get_approvals();
        MockHttpSession session = getAuthenticatedSession(user1);
        MockHttpServletRequestBuilder post = post("/profile")
            .session(session)
            .param("checkScopes", client1.getClientId() + "-test.scope1", client1.getClientId() + "-test.scope2");
        mockMvc.perform(
            post
        )
            .andDo(print())
            .andExpect(status().isForbidden());

        mockMvc.perform(
            post.with(cookieCsrf().useInvalidToken())
        ).andExpect(status().isForbidden());

        mockMvc.perform(
            post.with(cookieCsrf())
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrlPattern("**/profile"));
    }

    public MockHttpSession getAuthenticatedSession(ScimUser user) {
        List<SimpleGrantedAuthority> authorities = user.getGroups().stream().map(g -> new SimpleGrantedAuthority(g.getValue())).collect(Collectors.toList());
        UaaPrincipal p = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), OriginKeys.UAA, "", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, authorities, null);
        Assert.assertTrue(auth.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockMvcUtils.MockSecurityContext(auth)
        );
        return session;
    }

}
