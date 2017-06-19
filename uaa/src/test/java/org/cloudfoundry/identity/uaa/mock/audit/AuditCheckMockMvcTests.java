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
package org.cloudfoundry.identity.uaa.mock.audit;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.account.LostPasswordChangeRequest;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.account.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.AuditListener;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.event.AbstractClientAdminEvent;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SQLServerLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientCreateSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientUpdateSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.GroupCreatedEvent;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuditCheckMockMvcTests extends InjectedMockContextTest {

    private ClientRegistrationService clientRegistrationService;
    private UaaTestAccounts testAccounts;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener2;
    private ApplicationListener<AbstractUaaEvent> listener2;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ApplicationListener<AbstractUaaEvent> listener;
    private ScimUser testUser;
    private String testPassword = "secr3T";
    ClientDetails originalLoginClient;
    private AuthzAuthenticationManager mgr;
    String dbTrueString;
    RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private String adminToken;
    private AuditListener auditListener;
    private UaaAuditService mockAuditService;

    @Before
    public void setUp() throws Exception {
        clientRegistrationService = getWebApplicationContext().getBean(ClientRegistrationService.class);
        originalLoginClient = ((MultitenantJdbcClientDetailsService)clientRegistrationService).loadClientByClientId("login");
        testAccounts = UaaTestAccounts.standard(null);
        mockAuditService = mock(UaaAuditService.class);
        auditListener = new AuditListener(mockAuditService);
        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {
        }.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());
        getWebApplicationContext().addApplicationListener(listener);
        getWebApplicationContext().addApplicationListener(authSuccessListener);
        getWebApplicationContext().addApplicationListener(testListener);
        getWebApplicationContext().addApplicationListener(auditListener);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");
        testUser = createUser(adminToken, "testUser", "Test", "User", "testuser@test.com", testPassword, true);

        testListener.clearEvents();
        listener2 = listener;
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        authSuccessListener2 = authSuccessListener;
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {}.getClass());
        getWebApplicationContext().addApplicationListener(listener);
        getWebApplicationContext().addApplicationListener(authSuccessListener);

        this.mgr = getWebApplicationContext().getBean("uaaUserDatabaseAuthenticationManager", AuthzAuthenticationManager.class);
        this.mgr.setAllowUnverifiedUsers(false);
        dbTrueString = LimitSqlAdapterFactory.getLimitSqlAdapter().getClass().equals(SQLServerLimitSqlAdapter.class) ? "1" : "true";
    }

    @After
    public void resetLoginClient() throws Exception {
        clientRegistrationService.updateClientDetails(originalLoginClient);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), testListener);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), listener);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), authSuccessListener);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), listener2);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), authSuccessListener2);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), auditListener);
        SecurityContextHolder.clearContext();
    }

    @Test
    public void client_modification_logs_authorities_and_scopes() throws Exception {
        String clientId = generator.generate();
        String clientSecret = generator.generate();
        String resource = "uaa,cloud_controller";
        String scopes = "scope1,scope2,scope3";
        String grantTypes = "client_credentials,password";
        String authorities = "uaa.resource,uaa.admin";
        BaseClientDetails client = new BaseClientDetails(clientId, resource, scopes, grantTypes, authorities);
        client.setClientSecret(clientSecret);

        getMockMvc().perform(
            post("/oauth/clients")
                .header(AUTHORIZATION, "Bearer " + adminToken)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(client))
        )
            .andExpect(status().isCreated());
        assertClientEvents(ClientCreateSuccess, new String[]{"scope1", "scope2", "scope3"}, new String[]{"uaa.resource", "uaa.admin"});

        client.setScope(Arrays.asList("scope4","scope5"));
        client.setAuthorities(Arrays.asList(new SimpleGrantedAuthority("authority1"), new SimpleGrantedAuthority("authority2")));

        getMockMvc().perform(
            put("/oauth/clients/"+clientId)
                .header(AUTHORIZATION, "Bearer " + adminToken)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(client))
        )
            .andExpect(status().isOk());

        assertClientEvents(ClientUpdateSuccess, new String[]{"scope4", "scope5"}, new String[]{"authority1", "authority2"});
    }

    public void assertClientEvents(AuditEventType eventType, String[] scopes, String[] authorities) {
        List<AbstractUaaEvent> events = testListener.getEvents().stream().filter(e -> e instanceof AbstractClientAdminEvent).collect(Collectors.toList());
        assertNotNull(events);
        assertEquals(1, events.size());
        AbstractUaaEvent event = events.get(0);
        assertEquals(eventType, event.getAuditEvent().getType());

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture());
        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType()== eventType).collect(Collectors.toList());
        assertNotNull(auditEvents);
        assertEquals(1, auditEvents.size());
        AuditEvent auditEvent = auditEvents.get(0);
        String auditEventData = auditEvent.getData();
        assertNotNull(auditEventData);
        Map<String, Object> map = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {});
        List<String> auditScopes = (List<String>) map.get("scopes");
        assertNotNull(auditScopes);
        List<String> auditAuthorities = (List<String>) map.get("authorities");
        assertNotNull(auditAuthorities);
        assertThat(auditScopes, containsInAnyOrder(scopes));
        assertThat(auditAuthorities, containsInAnyOrder(authorities));
        testListener.clearEvents();
    }


    @Test
    public void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .with(cookieCsrf())
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
            .accept(APPLICATION_JSON_VALUE)
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
            .with(cookieCsrf())
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
    public void unverifiedLegacyUserAuthenticationWhenAllowedTest() throws Exception {
        mgr.setAllowUnverifiedUsers(true);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);
        getWebApplicationContext().getBeansOfType(JdbcTemplate.class).values().stream().forEach(jdbc -> jdbc.execute("update users set legacy_verification_behavior = "+dbTrueString+" where origin='uaa' and username = '" + molly.getUserName() + "'"));

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        getMockMvc().perform(loginPost)
                .andExpect(status().isOk());

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void unverifiedPostLegacyUserAuthenticationWhenAllowedTest() throws Exception {
        mgr.setAllowUnverifiedUsers(true);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        getMockMvc().perform(loginPost)
                .andExpect(status().isForbidden());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

        List<AbstractUaaEvent> allValues = captor.getAllValues();
        UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
        assertEquals(molly.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void unverifiedUserAuthenticationWhenNotAllowedTest() throws Exception {
            String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

            ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

            MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
            getMockMvc().perform(loginPost)
                .andExpect(status().isForbidden());

            ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
            verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

            List<AbstractUaaEvent> allValues = captor.getAllValues();
            UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
            assertEquals(molly.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void invalidPasswordLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(APPLICATION_JSON_VALUE)
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

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", "password", true);
        String jacobId = jacob.getId();

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(APPLICATION_JSON_VALUE)
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
            .with(cookieCsrf())
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
            .with(cookieCsrf())
            .accept(APPLICATION_JSON_VALUE)
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
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"Koala2\",\n" +
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
            .with(cookieCsrf())
            .accept(APPLICATION_JSON_VALUE)
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
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"Koala2\",\n" +
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

    private String requestExpiringCode(String email, String token) throws Exception {
        MockHttpServletRequestBuilder resetPasswordPost = post("/password_resets")
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + token)
            .content(email);
        MvcResult mvcResult = getMockMvc().perform(resetPasswordPost)
            .andExpect(status().isCreated()).andReturn();

        return ((Map<String, String>) JsonUtils.readValue(mvcResult.getResponse().getContentAsString(),
            new TypeReference<Map<String, String>>() {})).get("code");
    }

    @Test
    public void changePassword_ReturnsSuccess_WithValidExpiringCode() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        String expiringCode = requestExpiringCode(testUser.getUserName(), loginToken);

        LostPasswordChangeRequest pwch = new LostPasswordChangeRequest(expiringCode, "Koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(JsonUtils.writeValueAsBytes(pwch));

        getMockMvc().perform(changePasswordPost)
                .andExpect(status().isOk());

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeastOnce()).onApplicationEvent(captor.capture());
        PasswordChangeEvent pce = (PasswordChangeEvent)captor.getValue();
        assertEquals(testUser.getUserName(), pce.getUser().getUsername());
        assertEquals("Password changed", pce.getMessage());
    }

    @Test
    public void clientAuthenticationSuccess() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        getMockMvc().perform(oauthTokenPost).andExpect(status().isOk());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent)captor.getAllValues().get(0);
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());
    }

    @Test
    public void clientAuthenticationFailure() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("login:loginsecretwrong").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("scope", "oauth.login");
        getMockMvc().perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent)captor.getValue();
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());
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
        Approval[] approvals = {new Approval()
            .setUserId(null)
            .setClientId("app")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(1000))
            .setStatus(Approval.ApprovalStatus.APPROVED)};

        MockHttpServletRequestBuilder approvalsPut = put("/approvals")
                .accept(APPLICATION_JSON_VALUE)
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
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(APPLICATION_JSON_VALUE)
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
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login","http://localhost:8080/uaa"));
        String username = "jacob"+new RandomValueStringGenerator().generate();
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(
            "login",
            "loginsecret",
            "oauth.login");
        MockHttpServletRequestBuilder userPost = post("/oauth/authorize")
            .with(cookieCsrf())
            .accept(APPLICATION_JSON_VALUE)
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
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = getMockMvc().perform(userPost)
            .andExpect(status().isCreated());

        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
        testListener.clearEvents();

        user.setName(new ScimUser.Name(modifiedFirstName, lastName));
        MockHttpServletRequestBuilder userPut = put("/Users/"+user.getId())
            .accept(APPLICATION_JSON_VALUE)
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
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion()+1);

        getMockMvc().perform(userDelete).andExpect(status().isOk());

        assertEquals(2, testListener.getEventCount());

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
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = getMockMvc().perform(userPost)
            .andExpect(status().isCreated());
        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        testListener.clearEvents();

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
            .accept(APPLICATION_JSON_VALUE)
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
            .accept(APPLICATION_JSON_VALUE)
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

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", "password", true);
        ScimUser emily = createUser(adminToken, "emily", "Emily", "Gyllenhammer", "emily@gyllenhammer.non", "password", true);
        ScimUser jonas = createUser(adminToken, "jonas", "Jonas", "Gyllenhammer", "jonas@gyllenhammer.non", "password", true);


        ScimGroup group = new ScimGroup(null,"testgroup",IdentityZoneHolder.get().getId());
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
            .accept(APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(JsonUtils.writeValueAsBytes(group));

        ResultActions result = getMockMvc().perform(groupPost).andExpect(status().isCreated());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertEquals(1, testListener.getEventCount());
        assertEquals(GroupModifiedEvent.class, testListener.getLatestEvent().getClass());
        GroupModifiedEvent event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(GroupCreatedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(),
                                                      ScimEventPublisher.getMembers(group)),
                     JsonUtils.readValue(event.getAuditEvent().getData(),
                                         GroupModifiedEvent.GroupInfo.class)
        );

        verifyGroupAuditData(group, GroupCreatedEvent);

        //update the group with one additional member
        List<ScimGroupMember> members = group.getMembers();
        members.add(mjonas);
        group.setMembers(members);
        MockHttpServletRequestBuilder groupPut = put("/Groups/"+group.getId())
            .accept(APPLICATION_JSON_VALUE)
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

        verifyGroupAuditData(group, AuditEventType.GroupModifiedEvent);


        //delete the group
        MockHttpServletRequestBuilder groupDelete = delete("/Groups/" + group.getId())
            .accept(APPLICATION_JSON_VALUE)
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

        verifyGroupAuditData(group, AuditEventType.GroupDeletedEvent);
    }

    public void verifyGroupAuditData(ScimGroup group, AuditEventType eventType) {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture());
        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType()== eventType).collect(Collectors.toList());
        assertNotNull(auditEvents);
        assertEquals(1, auditEvents.size());
        AuditEvent auditEvent = auditEvents.get(0);
        String auditEventData = auditEvent.getData();
        assertNotNull(auditEventData);
        Map<String, Object> auditObjects = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {});
        assertEquals("testgroup", auditObjects.get("group_name"));
        assertThat((Collection<String>)auditObjects.get("members"), containsInAnyOrder(ScimEventPublisher.getMembers(group)));
    }

    private ScimUser createUser(String adminToken, String username, String firstname, String lastname, String email, String password, boolean verified) throws Exception {
        ScimUser user = new ScimUser();
        username+=new RandomValueStringGenerator().generate();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstname, lastname));
        user.addEmail(email);
        user.setPassword(password);
        user.setVerified(verified);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(APPLICATION_JSON_VALUE)
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
