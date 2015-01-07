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
package org.cloudfoundry.identity.uaa.mock.audit;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.googlecode.flyway.core.Flyway;

import junit.framework.Assert;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.audit.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.password.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

public class AuditCheckMvcMockTests {

    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    ClientRegistrationService clientRegistrationService;
    private ApplicationListener<AbstractUaaEvent> listener;
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private JdbcTemplate jdbcTemplate;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ScimUser testUser;
    private String testPassword = "secret";

    @BeforeClass
    public static void setUpContext() throws Exception {
        MockEnvironment mockEnvironment = new MockEnvironment();

        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.setEnvironment(mockEnvironment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
    }

    @Before
    public void setUp() throws Exception {
        clientRegistrationService = webApplicationContext.getBean(ClientRegistrationService.class);
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());

        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
        webApplicationContext.addApplicationListener(listener);
        webApplicationContext.addApplicationListener(authSuccessListener);
        webApplicationContext.addApplicationListener(testListener);

        jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);
        testUser = createUser(adminToken, "testUser", "Test", "User", "testuser@test.com", testPassword);

        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());
        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        webApplicationContext.addApplicationListener(listener);
        webApplicationContext.addApplicationListener(authSuccessListener);
        webApplicationContext.addApplicationListener(testListener);
    }

    @AfterClass
    public static void tearDownContext() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }

    @Test
    public void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testUser.getUserName())
            .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(listener).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(testUser.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void userLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testUser.getUserName())
            .param("password", testPassword);

        mockMvc.perform(loginPost)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("\"username\":\"" + testUser.getUserName())))
            .andExpect(content().string(containsString("\"email\":\"" + testUser.getPrimaryEmail())));

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(listener).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(testUser.getUserName(), event.getUser().getUsername());
    }


    @Test
    public void invalidPasswordLoginFailedTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testUser.getUserName())
            .param("password", "");
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(2)).onApplicationEvent(captor.capture());

        UserAuthenticationFailureEvent event1 = (UserAuthenticationFailureEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(testUser.getUserName(), event1.getUser().getUsername());
        assertEquals(testUser.getUserName(), event2.getName());
    }

    @Test
    public void unverifiedUserAuthenticationWhenAllowedTest() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write", null);

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobble");

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobble");
        mockMvc.perform(loginPost)
                .andExpect(status().isOk());

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void unverifiedUserAuthenticationWhenNotAllowedTest() throws Exception {
        try {
            for (Map.Entry<String,AuthzAuthenticationManager > mgr : webApplicationContext.getBeansOfType(AuthzAuthenticationManager.class).entrySet()) {
                mgr.getValue().setAllowUnverifiedUsers(false);
            }

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

            ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobble");

            MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobble");
            mockMvc.perform(loginPost)
                .andExpect(status().isForbidden());

            ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
            verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

            List<AbstractUaaEvent> allValues = captor.getAllValues();
            UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
            assertEquals(molly.getUserName(), event.getUser().getUsername());
        } finally {
            for (Map.Entry<String,AuthzAuthenticationManager > mgr : webApplicationContext.getBeansOfType(AuthzAuthenticationManager.class).entrySet()) {
                mgr.getValue().setAllowUnverifiedUsers(true);
            }
        }
    }

    @Test
    public void invalidPasswordLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testUser.getUserName())
            .param("password", "");
        mockMvc.perform(loginPost)
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("{\"error\":\"authentication failed\"}"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(2)).onApplicationEvent(captor.capture());

        UserAuthenticationFailureEvent event1 = (UserAuthenticationFailureEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(testUser.getUserName(), event1.getUser().getUsername());
        assertEquals(testUser.getUserName(), event2.getName());
    }

    @Test
    public void findAuditHistory() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", null);
        String jacobId = jacob.getId();

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", jacob.getUserName())
            .param("password", "notvalid");
        int attempts = 8;
        UaaAuditService auditService = webApplicationContext.getBean(JdbcAuditService.class);
        for (int i=0; i<attempts; i++) {
            mockMvc.perform(loginPost)
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("{\"error\":\"authentication failed\"}"));
        }

        //after we reach our max attempts, 5, the system stops logging them until the period is over
        List<AuditEvent> events = auditService.find(jacobId, System.currentTimeMillis()-10000);
        assertEquals(5, events.size());
    }

    @Test
    public void userNotFoundLoginFailedTest() throws Exception {
        String username = "test1234";

        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", username)
            .param("password", testPassword);
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(2)).onApplicationEvent(captor.capture());
        UserNotFoundEvent event1 = (UserNotFoundEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(username, ((Authentication)event1.getSource()).getName());
        assertEquals(username, event2.getName());
    }

    @Test
    public void userChangePasswordTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testUser.getUserName())
            .param("password", testPassword);
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(4)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"koala2\",\n" +
                    "  \"oldPassword\": \"" + testPassword + "\"\n" +
                    "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isOk());

        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(5)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof PasswordChangeEvent);
        PasswordChangeEvent pw = (PasswordChangeEvent)captor.getValue();
        assertEquals(testUser.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
    }

    @Test
    public void userChangeInvalidPasswordTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testUser.getUserName())
            .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(4)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"koala2\",\n" +
                    "  \"oldPassword\": \"invalid\"\n" +
                    "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isUnauthorized());

        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(5)).onApplicationEvent(captor.capture());

        assertTrue(captor.getValue() instanceof PasswordChangeFailureEvent);
        PasswordChangeFailureEvent pwfe = (PasswordChangeFailureEvent)captor.getValue();
        assertEquals(testUser.getUserName(), pwfe.getUser().getUsername());
        assertEquals("Old password is incorrect", pwfe.getMessage());
    }

    @Test
    public void loginServerPasswordChange() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login", null);

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testUser.getUserName());
        pwch.setCurrentPassword(testPassword);
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(new ObjectMapper().writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isOk());

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        PasswordChangeEvent pce = (PasswordChangeEvent)captor.getValue();
        assertEquals(testUser.getUserName(), pce.getUser().getUsername());
        assertEquals("Password changed", pce.getMessage());

        pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testUser.getUserName());
        pwch.setNewPassword(testPassword);
        pwch.setCurrentPassword("koala2");
        changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(new ObjectMapper().writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
            .andExpect(status().isOk());
    }

    @Test
    public void loginServerInvalidPasswordChange() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login", null);

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testUser.getUserName());
        pwch.setCurrentPassword("dsadasda");
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(new ObjectMapper().writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
            .andExpect(status().isUnauthorized());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        PasswordChangeFailureEvent pce = (PasswordChangeFailureEvent) captor.getValue();
        assertEquals(testUser.getUserName(), pce.getUser().getUsername());
        assertEquals("Old password is incorrect", pce.getMessage());
    }

    @Test
    public void clientAuthenticationSuccess() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login", null);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent)captor.getAllValues().get(0);
        assertEquals("login", event.getClientId());
    }

    @Test
    public void clientAuthenticationFailure() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("login:loginsecretwrong").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("client_id", "login")
            .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent)captor.getValue();
        assertEquals("login", event.getClientId());
    }

    @Test
    public void clientAuthenticationFailureClientNotFound() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("login2:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("client_id", "login")
            .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent)captor.getValue();
        assertEquals("login", event.getClientId());
    }
    @Test
    public void testUserApprovalAdded() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "password", "oauth.login"));

        String marissaToken = testClient.getUserOAuthAccessToken("login", "loginsecret", testUser.getUserName(), testPassword, "oauth.approvals");
        Approval[] approvals = {new Approval(null, "app", "cloud_controller.read", 1000, Approval.ApprovalStatus.APPROVED)};

        MockHttpServletRequestBuilder approvalsPut = put("/approvals")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + marissaToken)
                .content(new ObjectMapper().writeValueAsBytes(approvals));

        testListener.clearEvents();

        mockMvc.perform(approvalsPut)
                .andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testUser.getUserName(), approvalModifiedEvent.getAuthentication().getName());
    }

    @Test
    public void testUserCreatedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

        String username = "jacob"+new RandomValueStringGenerator().generate(), firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        testListener.clearEvents();

        mockMvc.perform(userPost)
            .andExpect(status().isCreated());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void testUserCreatedEventDuringLoginServerAuthorize() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login"));
        String username = "jacob"+new RandomValueStringGenerator().generate();
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(
            "login",
            "loginsecret",
            "oauth.login", null);
        MockHttpServletRequestBuilder userPost = post("/oauth/authorize")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param(UaaAuthenticationDetails.ADD_NEW, "true")
            .param("username", username)
            .param("name", "Jacob Gyllenhammer")
            .param("email", "jacob@gyllenhammer.non")
            .param("external_id","jacob")
            .param("response_type","code")
            .param("client_id","login")
            .param("redirect_uri", "http://localhost:8080/uaa")
            .param("state","erw342");

        testListener.clearEvents();

        mockMvc.perform(userPost)
            .andExpect(status().isOk());

        Assert.assertEquals(2, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getEvents().get(0);
        Assert.assertEquals("login", userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());

    }


    @Test
    public void testUserModifiedAndDeleteEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

        String username = "jacob"+new RandomValueStringGenerator().generate(), firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        String modifiedFirstName = firstName+lastName;
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
            .andExpect(status().isCreated());

        user = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsByteArray(), ScimUser.class);
        testListener.clearEvents();

        user.setName(new ScimUser.Name(modifiedFirstName, lastName));
        MockHttpServletRequestBuilder userPut = put("/Users/"+user.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion())
            .content(new ObjectMapper().writeValueAsBytes(user));

        mockMvc.perform(userPut).andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserModifiedEvent, userModifiedEvent.getAuditEvent().getType());

        //delete the user
        testListener.clearEvents();
        MockHttpServletRequestBuilder userDelete = delete("/Users/"+user.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion()+1);

        mockMvc.perform(userDelete).andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserDeletedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void testUserVerifiedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

        String username = "jacob", firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
            .andExpect(status().isCreated());
        user = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsByteArray(), ScimUser.class);

        testListener.clearEvents();

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion());

        mockMvc.perform(verifyGet).andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserVerifiedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void passwordResetRequestEvent() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login", null);

        testListener.clearEvents();
        MockHttpServletRequestBuilder changePasswordPost = post("/password_resets")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(testUser.getUserName());

        mockMvc.perform(changePasswordPost)
            .andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());
        assertEquals(ResetPasswordRequestEvent.class, testListener.getLatestEvent().getClass());
        ResetPasswordRequestEvent event = (ResetPasswordRequestEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), event.getAuditEvent().getPrincipalId());
        assertEquals(null, event.getAuditEvent().getData());
    }

    @Test
    public void testGroupEvents() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write", null);

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", null);
        ScimUser emily = createUser(adminToken, "emily", "Emily", "Gyllenhammer", "emily@gyllenhammer.non", null);
        ScimUser jonas = createUser(adminToken, "jonas", "Jonas", "Gyllenhammer", "jonas@gyllenhammer.non", null);


        ScimGroup group = new ScimGroup("testgroup");
        ScimGroupMember mjacob = new ScimGroupMember(
            jacob.getId(),
            ScimGroupMember.Type.USER,
            Arrays.asList(new ScimGroupMember.Role[]{ScimGroupMember.Role.MEMBER}));

        ScimGroupMember memily = new ScimGroupMember(
            emily.getId(),
            ScimGroupMember.Type.USER,
            Arrays.asList(new ScimGroupMember.Role[] {ScimGroupMember.Role.MEMBER}));

        ScimGroupMember mjonas = new ScimGroupMember(
            jonas.getId(),
            ScimGroupMember.Type.USER,
            Arrays.asList(new ScimGroupMember.Role[] {ScimGroupMember.Role.MEMBER}));

        group.setMembers(Arrays.asList(new ScimGroupMember[] {mjacob, memily}));

        testListener.clearEvents();

        MockHttpServletRequestBuilder groupPost = post("/Groups")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(group));

        ResultActions result = mockMvc.perform(groupPost).andExpect(status().isCreated());
        group = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        GroupModifiedEvent event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupCreatedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            new ObjectMapper().readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));

        //update the group with one additional member
        List<ScimGroupMember> members = group.getMembers();
        members.add(mjonas);
        group.setMembers(members);
        MockHttpServletRequestBuilder groupPut = put("/Groups/"+group.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", group.getVersion())
            .content(new ObjectMapper().writeValueAsBytes(group));

        testListener.clearEvents();
        result = mockMvc.perform(groupPut).andExpect(status().isOk());
        group = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupModifiedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            new ObjectMapper().readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));


        //delete the group
        MockHttpServletRequestBuilder groupDelete = delete("/Groups/" + group.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", group.getVersion())
            .content(new ObjectMapper().writeValueAsBytes(group));

        testListener.clearEvents();
        result = mockMvc.perform(groupDelete).andExpect(status().isOk());
        group = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupDeletedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            new ObjectMapper().readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));


    }

    private ScimUser createUser(String adminToken, String username, String firstname, String lastname, String email, String password) throws Exception {
        ScimUser user = new ScimUser();
        username+=new RandomValueStringGenerator().generate();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstname, lastname));
        user.addEmail(email);
        user.setPassword(password);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        testListener.clearEvents();

        ResultActions result = mockMvc.perform(userPost).andExpect(status().isCreated());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());

        return new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

    }

    private class DefaultApplicationListener<T extends ApplicationEvent> implements ApplicationListener<T> {
        @Override
        public void onApplicationEvent(T event) {
        }
    }

}
