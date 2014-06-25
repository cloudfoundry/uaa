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

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class TokenMvcMockTests {

    private static String SECRET = "secret";
    private static String GRANT_TYPES="password,implicit,client_credentials,authorization_code";

    AnnotationConfigWebApplicationContext webApplicationContext;
    ClientRegistrationService clientRegistrationService;
    private MockMvc mockMvc;
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private JdbcClientDetailsService clientDetailsService;
    private JdbcScimUserProvisioning userProvisioning;
    private JdbcScimGroupProvisioning groupProvisioning;
    private JdbcScimGroupMembershipManager groupMembershipManager;
    private UaaTokenServices tokenServices;
    private Set<String> defaultAuthorities;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new AnnotationConfigWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.register(DefaultIntegrationTestConfig.class);
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        clientRegistrationService = (ClientRegistrationService)webApplicationContext.getBean("clientRegistrationService");
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
        clientDetailsService = (JdbcClientDetailsService)webApplicationContext.getBean("jdbcClientDetailsService");
        userProvisioning = (JdbcScimUserProvisioning)webApplicationContext.getBean("scimUserProvisioning");
        groupProvisioning = (JdbcScimGroupProvisioning)webApplicationContext.getBean("scimGroupProvisioning");
        groupMembershipManager = (JdbcScimGroupMembershipManager)webApplicationContext.getBean("groupMembershipManager");
        tokenServices = (UaaTokenServices)webApplicationContext.getBean("tokenServices");
        defaultAuthorities = (Set<String>)webApplicationContext.getBean("defaultUserAuthorities");
    }

    protected void setUpClients(String id, String authorities, String scopes, String grantTypes) {
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        c.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(c);
    }

    protected ScimUser setUpUser(String username, String scopes) {
        ScimUser user = new ScimUser(null, username, "GivenName","FamilyName");
        user.setPassword(SECRET);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("test@test.org");
        email.setPrimary(true);
        user.setEmails(Arrays.asList(email));

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
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \""+scope+"\"");
        if (exists.size()>0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(scope));
        }
    }

    @After
    public void tearDown() throws Exception{
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }

    @Test
    public void testWildcardPasswordGrant() throws Exception {
        String clientId="testclient";
        String scopes="space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId,scopes,scopes,GRANT_TYPES);
        String userId = "testuser";
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

    public void validatePasswordGrantToken(String clientId, String username, String requestedScopes, String... expectedScopes) throws Exception {
        String t1 = testClient.getUserOAuthAccessToken(clientId, SECRET, username, SECRET, requestedScopes);
        OAuth2Authentication a1 = tokenServices.loadAuthentication(t1);
        assertEquals(expectedScopes.length, a1.getAuthorizationRequest().getScope().size());
        assertThat(
            a1.getAuthorizationRequest().getScope(),
            containsInAnyOrder(expectedScopes)
        );
    }


}
