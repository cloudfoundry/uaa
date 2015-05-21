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
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
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
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

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

public class AuditCheckMockMvcTests extends InjectedMockContextTest {

    private ClientRegistrationService clientRegistrationService;
    private ApplicationListener<AbstractUaaEvent> listener;
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ScimUser testUser;
    private String testPassword = "secret";
    ClientDetails originalLoginClient;
    @Before
    public void setUp() throws Exception {
        clientRegistrationService = getWebApplicationContext().getBean(ClientRegistrationService.class);
        originalLoginClient = ((MultitenantJdbcClientDetailsService)clientRegistrationService).loadClientByClientId("login");
        testClient = new TestClient(getMockMvc());
        testAccounts = UaaTestAccounts.standard(null);

        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());
        getWebApplicationContext().addApplicationListener(listener);
        getWebApplicationContext().addApplicationListener(authSuccessListener);
        getWebApplicationContext().addApplicationListener(testListener);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");
        testUser = createUser(adminToken, "testUser", "Test", "User", "testuser@test.com", testPassword);

        testListener.clearEvents();
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {}.getClass());
        getWebApplicationContext().addApplicationListener(listener);
        getWebApplicationContext().addApplicationListener(authSuccessListener);
    }

    @After
    public void resetLoginClient() {
        clientRegistrationService.updateClientDetails(originalLoginClient);
    }


    @Test
    public void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testUser.getUserName())
            .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        getMockMvc().perform(loginPost)
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

        getMockMvc().perform(loginPost)
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
        getMockMvc().perform(loginPost)
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
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobble");

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobble");
        getMockMvc().perform(loginPost)
                .andExpect(status().isOk());

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void unverifiedUserAuthenticationWhenNotAllowedTest() throws Exception {
        try {
            for (Map.Entry<String,AuthzAuthenticationManager > mgr : getWebApplicationContext().getBeansOfType(AuthzAuthenticationManager.class).entrySet()) {
                mgr.getValue().setAllowUnverifiedUsers(false);
            }

            String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

            ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobble");

            MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobble");
            getMockMvc().perform(loginPost)
                .andExpect(status().isForbidden());

            ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
            verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

            List<AbstractUaaEvent> allValues = captor.getAllValues();
            UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
            assertEquals(molly.getUserName(), event.getUser().getUsername());
        } finally {
            for (Map.Entry<String,AuthzAuthenticationManager > mgr : getWebApplicationContext().getBeansOfType(AuthzAuthenticationManager.class).entrySet()) {
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
        getMockMvc().perform(loginPost)
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
            "uaa.admin,scim.write");

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", null);
        String jacobId = jacob.getId();

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", jacob.getUserName())
            .param("password", "notvalid");
        int attempts = 8;
        UaaAuditService auditService = getWebApplicationContext().getBean(JdbcAuditService.class);
        for (int i=0; i<attempts; i++) {
            getMockMvc().perform(loginPost)
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
        getMockMvc().perform(loginPost)
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
        getMockMvc().perform(loginPost)
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

        getMockMvc().perform(changePasswordPut)
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
        getMockMvc().perform(loginPost)
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

        getMockMvc().perform(changePasswordPut)
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
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testUser.getUserName());
        pwch.setCurrentPassword(testPassword);
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(JsonUtils.writeValueAsBytes(pwch));

        getMockMvc().perform(changePasswordPost)
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
            .content(JsonUtils.writeValueAsBytes(pwch));

        getMockMvc().perform(changePasswordPost)
            .andExpect(status().isOk());
    }

    @Test
    public void loginServerInvalidPasswordChange() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testUser.getUserName());
        pwch.setCurrentPassword("dsadasda");
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(JsonUtils.writeValueAsBytes(pwch));

        getMockMvc().perform(changePasswordPost)
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
        testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
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
        getMockMvc().perform(oauthTokenPost).andExpect(status().isUnauthorized());
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
        getMockMvc().perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, atLeast(1)).onApplicationEvent(captor.capture());
        PrincipalAuthenticationFailureEvent event0 = (PrincipalAuthenticationFailureEvent) captor.getAllValues().get(0);
        assertEquals("login2", event0.getAuditEvent().getPrincipalId());
        ClientAuthenticationFailureEvent event1 = (ClientAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals("login", event1.getClientId());
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
                .content(JsonUtils.writeValueAsBytes(approvals));

        testListener.clearEvents();

        getMockMvc().perform(approvalsPut)
                .andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), approvalModifiedEvent.getAuthentication().getName());
    }

    @Test
    public void testUserCreatedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

        String username = "jacob"+new RandomValueStringGenerator().generate(), firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(JsonUtils.writeValueAsBytes(user));

        testListener.clearEvents();

        getMockMvc().perform(userPost)
            .andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void testUserCreatedEventDuringLoginServerAuthorize() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login"));
        String username = "jacob"+new RandomValueStringGenerator().generate();
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(
            "login",
            "loginsecret",
            "oauth.login");
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

        getMockMvc().perform(userPost)
            .andExpect(status().isOk());

        assertEquals(2, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getEvents().get(0);
        assertEquals("login", userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());

    }


    @Test
    public void testUserModifiedAndDeleteEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

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
            .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = getMockMvc().perform(userPost)
            .andExpect(status().isCreated());

        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
        testListener.clearEvents();

        user.setName(new ScimUser.Name(modifiedFirstName, lastName));
        MockHttpServletRequestBuilder userPut = put("/Users/"+user.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion())
            .content(JsonUtils.writeValueAsBytes(user));

        getMockMvc().perform(userPut).andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserModifiedEvent, userModifiedEvent.getAuditEvent().getType());

        //delete the user
        testListener.clearEvents();
        MockHttpServletRequestBuilder userDelete = delete("/Users/"+user.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion()+1);

        getMockMvc().perform(userDelete).andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserDeletedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void testUserVerifiedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

        String username = "jacob", firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = getMockMvc().perform(userPost)
            .andExpect(status().isCreated());
        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        testListener.clearEvents();

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion());

        getMockMvc().perform(verifyGet).andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserVerifiedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void passwordResetRequestEvent() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        testListener.clearEvents();
        MockHttpServletRequestBuilder changePasswordPost = post("/password_resets")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(testUser.getUserName());

        getMockMvc().perform(changePasswordPost)
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
            "uaa.admin,scim.write");

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
            .content(JsonUtils.writeValueAsBytes(group));

        ResultActions result = getMockMvc().perform(groupPost).andExpect(status().isCreated());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        GroupModifiedEvent event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupCreatedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));

        //update the group with one additional member
        List<ScimGroupMember> members = group.getMembers();
        members.add(mjonas);
        group.setMembers(members);
        MockHttpServletRequestBuilder groupPut = put("/Groups/"+group.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", group.getVersion())
            .content(JsonUtils.writeValueAsBytes(group));

        testListener.clearEvents();
        result = getMockMvc().perform(groupPut).andExpect(status().isOk());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupModifiedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));


        //delete the group
        MockHttpServletRequestBuilder groupDelete = delete("/Groups/" + group.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", group.getVersion())
            .content(JsonUtils.writeValueAsBytes(group));

        testListener.clearEvents();
        result = getMockMvc().perform(groupDelete).andExpect(status().isOk());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(AuditEventType.GroupDeletedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), ScimEventPublisher.getMembers(group)),
            JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));


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
            .content(JsonUtils.writeValueAsBytes(user));

        testListener.clearEvents();

        ResultActions result = getMockMvc().perform(userPost).andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());

        return JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

    }

    private class DefaultApplicationListener<T extends ApplicationEvent> implements ApplicationListener<T> {
        @Override
        public void onApplicationEvent(T event) {
        }
    }

}
