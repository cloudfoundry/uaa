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
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
public class TokenMvcMockTests {

    private static String SECRET = "secret";
    private static String GRANT_TYPES = "password,implicit,client_credentials,authorization_code";

    XmlWebApplicationContext webApplicationContext;
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
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        clientRegistrationService = (ClientRegistrationService) webApplicationContext.getBean("clientRegistrationService");
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
        clientDetailsService = (JdbcClientDetailsService) webApplicationContext.getBean("jdbcClientDetailsService");
        userProvisioning = (JdbcScimUserProvisioning) webApplicationContext.getBean("scimUserProvisioning");
        groupProvisioning = (JdbcScimGroupProvisioning) webApplicationContext.getBean("scimGroupProvisioning");
        groupMembershipManager = (JdbcScimGroupMembershipManager) webApplicationContext.getBean("groupMembershipManager");
        tokenServices = (UaaTokenServices) webApplicationContext.getBean("tokenServices");
        defaultAuthorities = (Set<String>) webApplicationContext.getBean("defaultUserAuthorities");
    }

    protected void setUpClients(String id, String authorities, String scopes, String grantTypes) {
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        c.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(c);
    }

    protected ScimUser setUpUser(String username, String scopes) {
        ScimUser user = new ScimUser(null, username, "GivenName", "FamilyName");
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
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \"" + scope + "\"");
        if (exists.size() > 0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(scope));
        }
    }

    @After
    public void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }

    @Test
    public void testWildcardPasswordGrant() throws Exception {
        String clientId = "testclient";
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES);
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

    public String validatePasswordGrantToken(String clientId, String username, String requestedScopes, String... expectedScopes) throws Exception {
        String t1 = testClient.getUserOAuthAccessToken(clientId, SECRET, username, SECRET, requestedScopes);
        OAuth2Authentication a1 = tokenServices.loadAuthentication(t1);
        assertEquals(expectedScopes.length, a1.getAuthorizationRequest().getScope().size());
        assertThat(
            a1.getAuthorizationRequest().getScope(),
            containsInAnyOrder(expectedScopes)
        );
        return t1;
    }

    @Test
    public void testLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES);
        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");

        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a login-server request

        //success - contains everything we need
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isOk());

        //success - user_id only, contains everything we need
        mockMvc.perform(post("/oauth/token")
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
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isOk());

        //failure - missing client ID
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isUnauthorized());

        //failure - invalid client ID
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", "dasdasdadas")
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - invalid client secret
        mockMvc.perform(post("/oauth/token")
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
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId() + "1dsda")
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - no user ID and an invalid origin must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("origin", developer.getOrigin() + "dasda"))
            .andExpect(status().isUnauthorized());

        //failure - no user ID, invalid username must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "asdasdas")
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());


        //success - pretend to be login server - add new user is true - any username will be added
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "true")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param("origin", developer.getOrigin()))
            .andExpect(status().isOk());

        //failure - pretend to be login server - add new user is false
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - source=login missing, so missing user password should trigger a failure
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - add_new is missing, so missing user password should trigger a failure
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testOtherOauthResourceLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES);


        String oauthClientId = "testclient" + new RandomValueStringGenerator().generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES);


        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
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
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - missing client ID
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isForbidden());

        //failure - invalid client ID
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", "dasdasdadas")
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - invalid client secret
        mockMvc.perform(post("/oauth/token")
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
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId() + "1dsda")
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - no user ID and an invalid origin must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("origin", developer.getOrigin() + "dasda"))
            .andExpect(status().isForbidden());

        //failure - no user ID, invalid username must fail
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "asdasdas")
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());


        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "true")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());

        //failure - pretend to be login server - add new user is false
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName() + "AddNew" + (new RandomValueStringGenerator().generate()))
            .param("origin", developer.getOrigin()))
            .andExpect(status().isForbidden());
    }

    @Test
    @Ignore
    public void testOtherClientAuthenticationMethods() throws Exception {
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES);


        String oauthClientId = "testclient" + new RandomValueStringGenerator().generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES);


        String userId = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //success - regular password grant but client is authenticated using POST parameters
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //success - regular password grant but client is authenticated using token
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", oauthClientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic "+new String(Base64.encode((oauthClientId + ":" + SECRET).getBytes())))
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        mockMvc.perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());
    }
}