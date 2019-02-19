/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
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
import org.cloudfoundry.identity.uaa.SpringServletAndHoneycombTestConfig;
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
import org.cloudfoundry.identity.uaa.authentication.event.*;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.event.AbstractClientAdminEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SQLServerLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.*;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getEventOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = SpringServletAndHoneycombTestConfig.class)
class AuditCheckMockMvcTests {

    @Autowired
    private ClientServicesExtension clientRegistrationService;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ApplicationListener<AbstractUaaEvent> listener;
    private ScimUser testUser;
    private final String testPassword = "secr3T";
    @Autowired
    @Qualifier("uaaUserDatabaseAuthenticationManager")
    private AuthzAuthenticationManager mgr;
    private String dbTrueString;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private String adminToken;
    private UaaAuditService mockAuditService;
    private AuditListener auditListener;
    private ClientDetails originalLoginClient;

    @Autowired
    private ConfigurableApplicationContext configurableApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @Value("${allowUnverifiedUsers:true}")
    private boolean allowUnverifiedUsers;

    @BeforeEach
    void setUp(@Autowired FilterChainProxy springSecurityFilterChain,
               @Autowired WebApplicationContext webApplicationContext) throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);

        originalLoginClient = clientRegistrationService.loadClientByClientId("login");
        testAccounts = UaaTestAccounts.standard(null);
        mockAuditService = mock(UaaAuditService.class);
        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        configurableApplicationContext.addApplicationListener(testListener);
        auditListener = new AuditListener(mockAuditService);
        configurableApplicationContext.addApplicationListener(auditListener);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");
        testUser = createUser(adminToken, "testUser", "Test", "User", "testuser@test.com", testPassword, true);

        testListener.clearEvents();
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {
        }.getClass());
        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());
        configurableApplicationContext.addApplicationListener(listener);
        configurableApplicationContext.addApplicationListener(authSuccessListener);

        mgr.setAllowUnverifiedUsers(false);
        dbTrueString = LimitSqlAdapterFactory.getLimitSqlAdapter().getClass().equals(SQLServerLimitSqlAdapter.class) ? "1" : "true";
    }

    @AfterEach
    void resetLoginClient(@Autowired WebApplicationContext webApplicationContext) {
        clientRegistrationService.updateClientDetails(originalLoginClient);
        MockMvcUtils.removeEventListener(webApplicationContext, testListener);
        MockMvcUtils.removeEventListener(webApplicationContext, listener);
        MockMvcUtils.removeEventListener(webApplicationContext, authSuccessListener);
        MockMvcUtils.removeEventListener(webApplicationContext, auditListener);
        SecurityContextHolder.clearContext();
        mgr.setAllowUnverifiedUsers(allowUnverifiedUsers);
    }

    @Test
    void client_modification_logs_authorities_and_scopes() throws Exception {
        String clientId = generator.generate();
        String clientSecret = generator.generate();
        String resource = "uaa,cloud_controller";
        String scopes = "scope1,scope2,scope3";
        String grantTypes = "client_credentials,password";
        String authorities = "uaa.resource,uaa.admin";
        BaseClientDetails client = new BaseClientDetails(clientId, resource, scopes, grantTypes, authorities);
        client.setClientSecret(clientSecret);

        mockMvc.perform(
                post("/oauth/clients")
                        .header(AUTHORIZATION, "Bearer " + adminToken)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                        .content(JsonUtils.writeValueAsString(client))
        )
                .andExpect(status().isCreated());
        assertClientEvents(ClientCreateSuccess, new String[]{"scope1", "scope2", "scope3"}, new String[]{"uaa.resource", "uaa.admin"});

        client.setScope(Arrays.asList("scope4", "scope5"));
        client.setAuthorities(Arrays.asList(new SimpleGrantedAuthority("authority1"), new SimpleGrantedAuthority("authority2")));

        mockMvc.perform(
                put("/oauth/clients/" + clientId)
                        .header(AUTHORIZATION, "Bearer " + adminToken)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                        .content(JsonUtils.writeValueAsString(client))
        )
                .andExpect(status().isOk());

        assertClientEvents(ClientUpdateSuccess, new String[]{"scope4", "scope5"}, new String[]{"authority1", "authority2"});
    }

    @Test
    void userLoginTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        IdentityProviderAuthenticationSuccessEvent passwordevent = getEventOfType(captor, IdentityProviderAuthenticationSuccessEvent.class);
        assertEquals(testUser.getUserName(), passwordevent.getUser().getUsername());
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = getEventOfType(captor, UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertEquals(testUser.getUserName(), userevent.getUser().getUsername());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());
    }

    @Test
    void userLoginAuthenticateEndpointTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + testUser.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + testUser.getPrimaryEmail())));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        IdentityProviderAuthenticationSuccessEvent passwordevent = getEventOfType(captor, IdentityProviderAuthenticationSuccessEvent.class);
        assertEquals(testUser.getUserName(), passwordevent.getUser().getUsername());
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = getEventOfType(captor, UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertEquals(testUser.getUserName(), userevent.getUser().getUsername());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());
    }


    @Test
    void invalidPasswordLoginUnsuccessfulTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", testUser.getUserName())
                .param("password", "");
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(3)).onApplicationEvent(captor.capture());

        IdentityProviderAuthenticationFailureEvent event1 = (IdentityProviderAuthenticationFailureEvent) captor.getAllValues().get(0);
        UserAuthenticationFailureEvent event2 = (UserAuthenticationFailureEvent) captor.getAllValues().get(1);
        PrincipalAuthenticationFailureEvent event3 = (PrincipalAuthenticationFailureEvent) captor.getAllValues().get(2);
        assertEquals(testUser.getUserName(), event1.getUsername());
        assertEquals(testUser.getUserName(), event2.getUser().getUsername());
        assertEquals(testUser.getUserName(), event3.getName());
        assertTrue(event1.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertTrue(event2.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertFalse(event3.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PrincipalAuthenticationFailureEvent does not contain sessionId at all
    }

    @Test
    void unverifiedLegacyUserAuthenticationWhenAllowedTest(
            @Autowired List<JdbcTemplate> jdbcTemplates
    ) throws Exception {
        mgr.setAllowUnverifiedUsers(true);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);
        jdbcTemplates.forEach(jdbc -> jdbc.execute("update users set legacy_verification_behavior = " + dbTrueString + " where origin='uaa' and username = '" + molly.getUserName() + "'"));

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isOk());

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void unverifiedPostLegacyUserAuthenticationWhenAllowedTest() throws Exception {
        mgr.setAllowUnverifiedUsers(true);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isForbidden());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

        List<AbstractUaaEvent> allValues = captor.getAllValues();
        UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
        assertEquals(molly.getUserName(), event.getUser().getUsername());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void unverifiedUserAuthenticationWhenNotAllowedTest() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isForbidden());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(captor.capture());

        List<AbstractUaaEvent> allValues = captor.getAllValues();
        UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) allValues.get(allValues.size() - 1);
        assertEquals(molly.getUserName(), event.getUser().getUsername());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void invalidPasswordLoginAuthenticateEndpointTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", testUser.getUserName())
                .param("password", "");
        mockMvc.perform(loginPost)
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("{\"error\":\"authentication failed\"}"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(3)).onApplicationEvent(captor.capture());

        IdentityProviderAuthenticationFailureEvent event1 = (IdentityProviderAuthenticationFailureEvent) captor.getAllValues().get(0);
        UserAuthenticationFailureEvent event2 = (UserAuthenticationFailureEvent) captor.getAllValues().get(1);
        PrincipalAuthenticationFailureEvent event3 = (PrincipalAuthenticationFailureEvent) captor.getAllValues().get(2);
        assertEquals(testUser.getUserName(), event1.getUsername());
        assertEquals(testUser.getUserName(), event2.getUser().getUsername());
        assertEquals(testUser.getUserName(), event3.getName());
        assertTrue(event1.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertTrue(event2.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertFalse(event3.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PrincipalAuthenticationFailureEvent does not contain sessionId at all
    }

    @Test
    void findAuditHistory(@Autowired JdbcAuditService auditService) throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", "password", true);
        String jacobId = jacob.getId();

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .param("username", jacob.getUserName())
                .param("password", "notvalid");
        int attempts = 8;
        for (int i = 0; i < attempts; i++) {
            mockMvc.perform(loginPost)
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().string("{\"error\":\"authentication failed\"}"));
        }

        //after we reach our max attempts, 5, the system stops logging them until the period is over
        List<AuditEvent> events = auditService.find(jacobId, System.currentTimeMillis() - 10000, IdentityZoneHolder.get().getId());
        assertEquals(5, events.size());
        for (AuditEvent event : events) {
            assertTrue(event.getOrigin().contains("sessionId=<SESSION>"));
        }
    }

    @Test
    void userNotFoundLoginUnsuccessfulTest() throws Exception {
        String username = "test1234";

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", username)
                .param("password", testPassword);
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(2)).onApplicationEvent(captor.capture());
        UserNotFoundEvent event1 = (UserNotFoundEvent) captor.getAllValues().get(0);
        assertTrue(event1.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent) captor.getAllValues().get(1);
        assertEquals(username, ((Authentication) event1.getSource()).getName());
        assertEquals(username, event2.getName());
        assertFalse(event2.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PrincipalAuthenticationFailureEvent does not contain sessionId at all
    }

    @Test
    void userChangePasswordTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(APPLICATION_JSON_VALUE)
                .param("username", testUser.getUserName())
                .param("password", testPassword);
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        IdentityProviderAuthenticationSuccessEvent passwordevent = getEventOfType(captor, IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = getEventOfType(captor, UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(6)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/" + userid + "/password")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content("{\n" +
                        "  \"password\": \"Koala2\",\n" +
                        "  \"oldPassword\": \"" + testPassword + "\"\n" +
                        "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isOk());

        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(7)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof PasswordChangeEvent);
        PasswordChangeEvent pw = (PasswordChangeEvent) captor.getValue();
        assertEquals(testUser.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
        assertTrue(pw.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void userChangeInvalidPasswordTest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(APPLICATION_JSON_VALUE)
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        IdentityProviderAuthenticationSuccessEvent passwordevent = getEventOfType(captor, IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = getEventOfType(captor, UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(6)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/" + userid + "/password")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content("{\n" +
                        "  \"password\": \"Koala2\",\n" +
                        "  \"oldPassword\": \"invalid\"\n" +
                        "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isUnauthorized());

        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(7)).onApplicationEvent(captor.capture());

        assertTrue(captor.getValue() instanceof PasswordChangeFailureEvent);
        PasswordChangeFailureEvent pwfe = (PasswordChangeFailureEvent) captor.getValue();
        assertEquals(testUser.getUserName(), pwfe.getUser().getUsername());
        assertEquals("Old password is incorrect", pwfe.getMessage());
        assertTrue(pwfe.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void password_change_recorded_at_dao(@Autowired ScimUserProvisioning provisioning) {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator().generate() + "@test.org", "first", "last");
        user.setPrimaryEmail(user.getUserName());
        user = provisioning.createUser(user, "oldpassword", IdentityZoneHolder.get().getId());
        provisioning.changePassword(user.getId(), "oldpassword", "newpassword", IdentityZoneHolder.get().getId());
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        //the last event should be our password modified event
        PasswordChangeEvent pw = (PasswordChangeEvent) captor.getValue();
        assertEquals(user.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
    }

    @Test
    void changePassword_ReturnsSuccess_WithValidExpiringCode() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        String expiringCode = requestExpiringCode(testUser.getUserName(), loginToken);

        LostPasswordChangeRequest pwch = new LostPasswordChangeRequest(expiringCode, "Koala2");

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + loginToken)
                .content(JsonUtils.writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isOk());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeastOnce()).onApplicationEvent(captor.capture());
        PasswordChangeEvent pce = (PasswordChangeEvent) captor.getValue();
        assertEquals(testUser.getUserName(), pce.getUser().getUsername());
        assertEquals("Password changed", pce.getMessage());
        assertFalse(pce.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PasswordChangeEvent does not contain session in this case
    }

    @Test
    void clientAuthenticationSuccess() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isOk());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent) captor.getAllValues().get(0);
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());
    }

    @Test
    void clientAuthenticationFailure() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login:loginsecretwrong").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent) captor.getValue();
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());
    }

    @Test
    void clientAuthenticationFailureClientNotFound() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login2:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", "login")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, atLeast(1)).onApplicationEvent(captor.capture());
        PrincipalAuthenticationFailureEvent event0 = (PrincipalAuthenticationFailureEvent) captor.getAllValues().get(0);
        assertEquals("login2", event0.getAuditEvent().getPrincipalId());
        ClientAuthenticationFailureEvent event1 = (ClientAuthenticationFailureEvent) captor.getAllValues().get(1);
        assertEquals("login", event1.getClientId());
    }

    @Test
    void testUserApprovalAdded() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "password", "oauth.login"));

        String marissaToken = testClient.getUserOAuthAccessToken("login", "loginsecret", testUser.getUserName(), testPassword, "oauth.approvals");
        Approval[] approvals = {new Approval()
                .setUserId(null)
                .setClientId("app")
                .setScope("cloud_controller.read")
                .setExpiresAt(Approval.timeFromNow(1000))
                .setStatus(Approval.ApprovalStatus.APPROVED)};

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder approvalsPut = put("/approvals")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content(JsonUtils.writeValueAsBytes(approvals));

        testListener.clearEvents();

        mockMvc.perform(approvalsPut)
                .andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), approvalModifiedEvent.getAuthentication().getName());
        assertTrue(approvalModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void testUserCreatedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        String username = "jacob" + new RandomValueStringGenerator().generate(), firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(user));

        testListener.clearEvents();

        mockMvc.perform(userPost)
                .andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void testUserCreatedEventDuringLoginServerAuthorize() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login", "http://localhost:8080/uaa"));
        String username = "jacob" + new RandomValueStringGenerator().generate();
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(
                "login",
                "loginsecret",
                "oauth.login");
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder userPost = post("/oauth/authorize")
                .with(cookieCsrf())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param(UaaAuthenticationDetails.ADD_NEW, "true")
                .param("username", username)
                .param("name", "Jacob Gyllenhammer")
                .param("email", "jacob@gyllenhammer.non")
                .param("external_id", "jacob")
                .param("response_type", "code")
                .param("client_id", "login")
                .param("redirect_uri", "http://localhost:8080/uaa")
                .param("state", "erw342");

        testListener.clearEvents();

        mockMvc.perform(userPost)
                .andExpect(status().isOk());

        assertEquals(3, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getEvents().get(0);
        assertEquals("login", userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void testUserModifiedAndDeleteEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        String username = "jacob" + new RandomValueStringGenerator().generate(), firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        String modifiedFirstName = firstName + lastName;
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
                .andExpect(status().isCreated());

        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
        testListener.clearEvents();

        user.setName(new ScimUser.Name(modifiedFirstName, lastName));
        MockHttpServletRequestBuilder userPut = put("/Users/" + user.getId())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsBytes(user));

        mockMvc.perform(userPut).andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserModifiedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        //delete the user
        testListener.clearEvents();
        MockHttpServletRequestBuilder userDelete = delete("/Users/" + user.getId())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", user.getVersion() + 1);

        mockMvc.perform(userDelete).andExpect(status().isOk());

        assertEquals(2, testListener.getEventCount());

        userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserDeletedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void testUserVerifiedEvent() throws Exception {
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

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
                .andExpect(status().isCreated());
        user = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        testListener.clearEvents();

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", user.getVersion());

        mockMvc.perform(verifyGet).andExpect(status().isOk());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserVerifiedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void passwordResetRequestEvent() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        testListener.clearEvents();
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder changePasswordPost = post("/password_resets")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + loginToken)
                .content(testUser.getUserName());

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());
        assertEquals(ResetPasswordRequestEvent.class, testListener.getLatestEvent().getClass());
        ResetPasswordRequestEvent event = (ResetPasswordRequestEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), event.getAuditEvent().getPrincipalId());
        assertEquals(testUser.getPrimaryEmail(), event.getAuditEvent().getData());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
    }

    @Test
    void testGroupEvents() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", "password", true);
        ScimUser emily = createUser(adminToken, "emily", "Emily", "Gyllenhammer", "emily@gyllenhammer.non", "password", true);
        ScimUser jonas = createUser(adminToken, "jonas", "Jonas", "Gyllenhammer", "jonas@gyllenhammer.non", "password", true);


        ScimGroup group = new ScimGroup(null, "testgroup", IdentityZoneHolder.get().getId());
        ScimGroupMember mjacob = new ScimGroupMember(
                jacob.getId(),
                ScimGroupMember.Type.USER);

        ScimGroupMember memily = new ScimGroupMember(
                emily.getId(),
                ScimGroupMember.Type.USER);

        ScimGroupMember mjonas = new ScimGroupMember(
                jonas.getId(),
                ScimGroupMember.Type.USER);

        group.setMembers(Arrays.asList(mjacob, memily));

        testListener.clearEvents();

        MockHttpServletRequestBuilder groupPost = post("/Groups")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(group));

        ResultActions result = mockMvc.perform(groupPost).andExpect(status().isCreated());
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
        MockHttpServletRequestBuilder groupPut = put("/Groups/" + group.getId())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", group.getVersion())
                .content(JsonUtils.writeValueAsBytes(group));

        testListener.clearEvents();
        result = mockMvc.perform(groupPut).andExpect(status().isOk());
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
        result = mockMvc.perform(groupDelete).andExpect(status().isOk());
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

    private void verifyGroupAuditData(ScimGroup group, AuditEventType eventType) {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture(), anyString());
        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType() == eventType).collect(Collectors.toList());
        assertNotNull(auditEvents);
        assertEquals(1, auditEvents.size());
        AuditEvent auditEvent = auditEvents.get(0);
        String auditEventData = auditEvent.getData();
        assertNotNull(auditEventData);
        Map<String, Object> auditObjects = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {
        });
        assertEquals("testgroup", auditObjects.get("group_name"));
        assertThat((Collection<String>) auditObjects.get("members"), containsInAnyOrder(ScimEventPublisher.getMembers(group)));
    }

    private ScimUser createUser(String adminToken, String username, String firstname, String lastname, String email, String password, boolean verified) throws Exception {
        ScimUser user = new ScimUser();
        username += new RandomValueStringGenerator().generate();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstname, lastname));
        user.addEmail(email);
        user.setPassword(password);
        user.setVerified(verified);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(user));

        testListener.clearEvents();

        ResultActions result = mockMvc.perform(userPost).andExpect(status().isCreated());

        assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        return JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

    }

    private class DefaultApplicationListener<T extends ApplicationEvent> implements ApplicationListener<T> {
        @Override
        public void onApplicationEvent(T event) {
        }
    }

    private String requestExpiringCode(String email, String token) throws Exception {
        MockHttpServletRequestBuilder resetPasswordPost = post("/password_resets")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + token)
                .content(email);
        MvcResult mvcResult = mockMvc.perform(resetPasswordPost)
                .andExpect(status().isCreated()).andReturn();

        return JsonUtils.readValue(mvcResult.getResponse().getContentAsString(),
                new TypeReference<Map<String, String>>() {
                }).get("code");
    }

    private void assertClientEvents(AuditEventType eventType, String[] scopes, String[] authorities) {
        List<AbstractUaaEvent> events = testListener.getEvents().stream().filter(e -> e instanceof AbstractClientAdminEvent).collect(Collectors.toList());
        assertNotNull(events);
        assertEquals(1, events.size());
        AbstractUaaEvent event = events.get(0);
        assertEquals(eventType, event.getAuditEvent().getType());

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture(), anyString());
        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType() == eventType).collect(Collectors.toList());
        assertNotNull(auditEvents);
        assertEquals(1, auditEvents.size());
        AuditEvent auditEvent = auditEvents.get(0);
        String auditEventData = auditEvent.getData();
        assertNotNull(auditEventData);
        Map<String, Object> map = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {
        });
        List<String> auditScopes = (List<String>) map.get("scopes");
        assertNotNull(auditScopes);
        List<String> auditAuthorities = (List<String>) map.get("authorities");
        assertNotNull(auditAuthorities);
        assertThat(auditScopes, containsInAnyOrder(scopes));
        assertThat(auditAuthorities, containsInAnyOrder(authorities));
        testListener.clearEvents();
    }
}
