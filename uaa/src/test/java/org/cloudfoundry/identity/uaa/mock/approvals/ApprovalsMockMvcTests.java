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


import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServicesTests.AUTHORIZATION_CODE;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ApprovalsMockMvcTests extends InjectedMockContextTest {

    public static final String SECRET = "secret";
    public static final String GRANT_TYPES = "password,implicit,client_credentials,authorization_code";
    public static final String TEST_REDIRECT_URI = "http://test.example.org/redirect";

    protected TestClient testClient;
    protected JdbcClientDetailsService clientDetailsService;
    protected JdbcScimUserProvisioning userProvisioning;
    protected JdbcScimGroupProvisioning groupProvisioning;
    private JdbcScimGroupMembershipManager groupMembershipManager;
    protected UaaTokenServices tokenServices;
    protected Set<String> defaultAuthorities;

    protected IdentityZoneProvisioning identityZoneProvisioning;
    protected JdbcScimUserProvisioning jdbcScimUserProvisioning;
    protected IdentityProviderProvisioning identityProviderProvisioning;
    protected String adminToken;

    private String scopes = "test.scope1,test.scope2,test.scope3";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private ScimUser user1;
    private ClientDetails client1;


    @Before
    public void createData() throws Exception {

        testClient = new TestClient(getMockMvc());
        clientDetailsService = (JdbcClientDetailsService) getWebApplicationContext().getBean("jdbcClientDetailsService");
        userProvisioning = (JdbcScimUserProvisioning) getWebApplicationContext().getBean("scimUserProvisioning");
        groupProvisioning = (JdbcScimGroupProvisioning) getWebApplicationContext().getBean("scimGroupProvisioning");
        groupMembershipManager = (JdbcScimGroupMembershipManager) getWebApplicationContext().getBean("groupMembershipManager");
        tokenServices = (UaaTokenServices) getWebApplicationContext().getBean("tokenServices");
        defaultAuthorities = (Set<String>) getWebApplicationContext().getBean("defaultUserAuthorities");
        identityZoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        jdbcScimUserProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityZoneHolder.clear();

        adminToken =
            utils().getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "uaa.admin",
                null
            );

        user1= syncGroups(setUpUser(generator.generate(), scopes, Origin.UAA, IdentityZone.getUaa().getId()));
        client1 = setUpClients(generator.generate(), null, scopes, AUTHORIZATION_CODE, false);
    }


    @Test
    public void test_oauth_authorize_without_csrf() throws Exception {
        String state = generator.generate();

        MockHttpSession session = getAuthenticatedSession(user1);
        getMockMvc().perform(
            get("/oauth/authorize")
                .session(session)
                .param(RESPONSE_TYPE, "code")
                .param(STATE, state)
                .param(CLIENT_ID, client1.getClientId()))
            .andExpect(status().isOk()); //200 means the approvals page


        assertNotNull(session.getAttribute("authorizationRequest"));

        //no token
        getMockMvc().perform(
            post("/oauth/authorize")
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","test.scope1")
        )
            .andExpect(status().is4xxClientError());

        //invalid token
        getMockMvc().perform(
            post("/oauth/authorize")
                .with(cookieCsrf().useInvalidToken())
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","test.scope1")
        )
            .andExpect(status().is4xxClientError());

        assertNotNull(session.getAttribute("authorizationRequest"));

        //valid token
        getMockMvc().perform(
            post("/oauth/authorize")
                .with(cookieCsrf())
                .session(session)
                .param(USER_OAUTH_APPROVAL, "true")
                .param("scope.0","test.scope1")
                .param("scope.1","test.scope2")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrlPattern("**/*code=*"));

        assertNull(session.getAttribute("authorizationRequest"));

        getMockMvc().perform(
            get("/oauth/authorize")
                .session(session)
                .param(RESPONSE_TYPE, "code")
                .param(STATE, state)
                .param(CLIENT_ID, client1.getClientId()))
            .andExpect(status().isFound()); //approval page no longer showing up
    }

    @Test
    public void revoke() throws Exception {
        test_oauth_authorize_without_csrf();
        MockHttpSession session = getAuthenticatedSession(user1);
        getMockMvc().perform(
            post("/profile")
                .with(cookieCsrf())
                .param("delete","true")
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
        getMockMvc().perform(
            post("/profile")
                .with(cookieCsrf())
                .param("delete","true")
                .param("clientId", "invalid_id")
                .session(session)
        )
            .andExpect(status().isFound())
            .andExpect(header().string("Location", "profile?error_message_code=request.invalid_parameter"));
    }

    @Test
    public void test_get_approvals() throws Exception {
        test_oauth_authorize_without_csrf();
        MockHttpSession session = getAuthenticatedSession(user1);
        getMockMvc().perform(
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
        getMockMvc().perform(
            post
        )
            .andDo(print())
            .andExpect(status().isForbidden());

        getMockMvc().perform(
            post.with(cookieCsrf().useInvalidToken())
        ).andExpect(status().isForbidden());

        getMockMvc().perform(
            post.with(cookieCsrf())
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrlPattern("**/profile"));
    }

    public MockHttpSession getAuthenticatedSession(ScimUser user) {
        List<SimpleGrantedAuthority> authorities = user.getGroups().stream().map(g -> new SimpleGrantedAuthority(g.getValue())).collect(Collectors.toList());
        UaaPrincipal p = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), Origin.UAA, "", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", authorities);
        Assert.assertTrue(auth.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockMvcUtils.MockSecurityContext(auth)
        );
        return session;
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, null);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, null);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, -1);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity) {
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        if (!"implicit".equals(grantTypes)) {
            c.setClientSecret(SECRET);
        }
        c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(TEST_REDIRECT_URI)));
        c.setAutoApproveScopes(Collections.singleton(autoapprove.toString()));
        Map<String, Object> additional = new HashMap<>();
        if (allowedIdps!=null && !allowedIdps.isEmpty()) {
            additional.put(ClientConstants.ALLOWED_PROVIDERS, allowedIdps);
        }
        c.setAdditionalInformation(additional);
        if (StringUtils.hasText(redirectUri)) {
            c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUri)));
        }
        if (accessTokenValidity>0) {
            c.setAccessTokenValiditySeconds(accessTokenValidity);
        }
        clientDetailsService.addClientDetails(c);
        return (BaseClientDetails) clientDetailsService.loadClientByClientId(c.getClientId());
    }

    protected ScimUser setUpUser(String username, String scopes, String origin, String zoneId) {
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
            ScimGroup g = createIfNotExist(scope,zoneId);
            groups.add(g);
            addMember(user, g);
        }

        return userProvisioning.retrieve(user.getId());
    }

    protected ScimUser syncGroups(ScimUser user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroup> directGroups = groupMembershipManager.getGroupsWithMember(user.getId(), false);
        Set<ScimGroup> indirectGroups = groupMembershipManager.getGroupsWithMember(user.getId(), true);
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<ScimUser.Group>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    protected ScimGroupMember addMember(ScimUser user, ScimGroup group) {
        ScimGroupMember gm = new ScimGroupMember(user.getId());
        try {
            return groupMembershipManager.addMember(group.getId(), gm);
        }catch (MemberAlreadyExistsException x) {
            return gm;
        }
    }

    protected ScimGroup createIfNotExist(String scope, String zoneId) {
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \"" + scope + "\" and identity_zone_id eq \""+zoneId+"\"");
        if (exists.size() > 0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(null,scope,zoneId));
        }
    }

}
