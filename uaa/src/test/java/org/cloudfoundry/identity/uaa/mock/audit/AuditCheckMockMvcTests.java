package org.cloudfoundry.identity.uaa.mock.audit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.LostPasswordChangeRequest;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.account.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.audit.*;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.AuditListener;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.*;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.event.AbstractClientAdminEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
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
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.*;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.RegexMatcher.matchesRegex;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class AuditCheckMockMvcTests {

    @Autowired
    private MultitenantClientServices clientRegistrationService;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ScimUser testUser;
    private final String testPassword = "secr3T";
    @Autowired
    @Qualifier("uaaUserDatabaseAuthenticationManager")
    private AuthzAuthenticationManager mgr;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private String adminToken;
    private UaaAuditService mockAuditService;
    private AuditListener auditListener;
    private ClientDetails originalLoginClient;

    @Autowired
    private ConfigurableApplicationContext configurableApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;
    @Autowired
    private IdentityZoneManager identityZoneManager;

    @Value("${allowUnverifiedUsers:true}")
    private boolean allowUnverifiedUsers;
    @Autowired
    private LoggingAuditService loggingAuditService;
    private InterceptingLogger testLogger;
    private Logger originalAuditServiceLogger;

    @Autowired
    JdbcScimUserProvisioning jdbcScimUserProvisioning;

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

        testLogger = new InterceptingLogger();
        originalAuditServiceLogger = loggingAuditService.getLogger();
        loggingAuditService.setLogger(testLogger);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");
        testUser = createUser(adminToken, "testUser", "Test", "User", "testuser@test.com", testPassword, true);

        resetAuditTestReceivers();

        authSuccessListener = mock(new DefaultApplicationListener<UserAuthenticationSuccessEvent>() {
        }.getClass());
        configurableApplicationContext.addApplicationListener(authSuccessListener);

        mgr.setAllowUnverifiedUsers(false);
    }

    @AfterEach
    void resetLoginClient(@Autowired WebApplicationContext webApplicationContext) {
        clientRegistrationService.updateClientDetails(originalLoginClient);
        MockMvcUtils.removeEventListener(webApplicationContext, testListener);
        MockMvcUtils.removeEventListener(webApplicationContext, authSuccessListener);
        MockMvcUtils.removeEventListener(webApplicationContext, auditListener);
        SecurityContextHolder.clearContext();
        mgr.setAllowUnverifiedUsers(allowUnverifiedUsers);
    }

    @AfterEach
    void putBackOriginalLogger() {
        loggingAuditService.setLogger(originalAuditServiceLogger);
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
        assertSingleAuditEventFiredWith(ClientCreateSuccess, new String[]{"scope1", "scope2", "scope3"}, new String[]{"uaa.resource", "uaa.admin"});

        resetAuditTestReceivers();

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
        assertSingleAuditEventFiredWith(ClientUpdateSuccess, new String[]{"scope4", "scope5"}, new String[]{"authority1", "authority2"});
    }

    @Test
    void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(new MockHttpSession())
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        assertNumberOfAuditEventsReceived(2);

        IdentityProviderAuthenticationSuccessEvent passwordEvent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        assertEquals(testUser.getUserName(), passwordEvent.getUser().getUsername());
        assertTrue(passwordEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertEquals(passwordEvent.getUser().getId(), userEvent.getUser().getId());
        assertEquals(testUser.getUserName(), userEvent.getUser().getUsername());
        assertTrue(userEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordEvent.getAuthenticationType());

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());
    }

    @Test
    void userLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + testUser.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + testUser.getPrimaryEmail())));

        assertNumberOfAuditEventsReceived(2);

        IdentityProviderAuthenticationSuccessEvent passwordEvent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        assertEquals(testUser.getUserName(), passwordEvent.getUser().getUsername());
        assertTrue(passwordEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertEquals(passwordEvent.getUser().getId(), userEvent.getUser().getId());
        assertEquals(testUser.getUserName(), userEvent.getUser().getUsername());
        assertTrue(userEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordEvent.getAuthenticationType());

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());
    }

    @Test
    void invalidPasswordLoginUnsuccessfulTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(new MockHttpSession())
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", testUser.getUserName())
                .param("password", "");
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        assertNumberOfAuditEventsReceived(3);

        IdentityProviderAuthenticationFailureEvent idpAuthFailEvent = (IdentityProviderAuthenticationFailureEvent) testListener.getEvents().get(0);
        assertEquals(testUser.getUserName(), idpAuthFailEvent.getUsername());
        assertTrue(idpAuthFailEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        UserAuthenticationFailureEvent userAuthFailEvent = (UserAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertEquals(testUser.getUserName(), userAuthFailEvent.getUser().getUsername());
        assertTrue(userAuthFailEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        PrincipalAuthenticationFailureEvent principalAuthFailEvent = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(2);
        assertEquals(testUser.getUserName(), principalAuthFailEvent.getName());
        assertFalse(principalAuthFailEvent.getAuditEvent().getOrigin().contains("sessionId")); // PrincipalAuthenticationFailureEvent should not contain sessionId at all

        String idpAuthFailMsg = testLogger.getMessageAtIndex(0);
        assertLogMessageWithSession(idpAuthFailMsg, IdentityProviderAuthenticationFailure, "null", testUser.getUserName());

        String userAuthFailMsg = testLogger.getMessageAtIndex(1);
        assertLogMessageWithSession(userAuthFailMsg, UserAuthenticationFailure, testUser.getId(), testUser.getUserName());

        String principalAuthFailMsg = testLogger.getMessageAtIndex(2);
        assertLogMessageWithoutSession(principalAuthFailMsg, PrincipalAuthenticationFailure, testUser.getUserName(), "null");
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
        jdbcTemplates.forEach(jdbc -> jdbc.execute("update users set legacy_verification_behavior = true where origin='uaa' and username = '" + molly.getUserName() + "'"));

        resetAuditTestReceivers();

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(3);

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userAuthLogMsg, UserAuthenticationSuccess, molly.getId(), molly.getUserName());
    }

    @Test
    void unverifiedPostLegacyUserAuthenticationWhenAllowedTest() throws Exception {
        mgr.setAllowUnverifiedUsers(true);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isForbidden());

        assertNumberOfAuditEventsReceived(2);

        UnverifiedUserAuthenticationEvent unverifiedUserAuthEvent = testListener.getLatestEventOfType(UnverifiedUserAuthenticationEvent.class);
        assertEquals(molly.getUserName(), unverifiedUserAuthEvent.getUser().getUsername());
        assertTrue(unverifiedUserAuthEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UnverifiedUserAuthentication);
        assertLogMessageWithSession(userAuthLogMsg, UnverifiedUserAuthentication, molly.getId(), molly.getUserName());
    }

    @Test
    void unverifiedUserAuthenticationWhenNotAllowedTest() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser molly = createUser(adminToken, "molly", "Molly", "Collywobble", "molly@example.com", "wobblE3", false);

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", molly.getUserName())
                .param("password", "wobblE3");
        mockMvc.perform(loginPost)
                .andExpect(status().isForbidden());

        assertNumberOfAuditEventsReceived(2);

        UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) testListener.getLatestEvent();
        assertEquals(molly.getUserName(), event.getUser().getUsername());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UnverifiedUserAuthentication);
        assertLogMessageWithSession(userAuthLogMsg, UnverifiedUserAuthentication, molly.getId(), molly.getUserName());
    }

    @Test
    void invalidPasswordLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", testUser.getUserName())
                .param("password", "");
        mockMvc.perform(loginPost)
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("{\"error\":\"authentication failed\"}"));

        assertNumberOfAuditEventsReceived(3);

        IdentityProviderAuthenticationFailureEvent event1 = (IdentityProviderAuthenticationFailureEvent) testListener.getEvents().get(0);
        UserAuthenticationFailureEvent event2 = (UserAuthenticationFailureEvent) testListener.getEvents().get(1);
        PrincipalAuthenticationFailureEvent event3 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(2);
        assertEquals(testUser.getUserName(), event1.getUsername());
        assertEquals(testUser.getUserName(), event2.getUser().getUsername());
        assertEquals(testUser.getUserName(), event3.getName());
        assertTrue(event1.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertTrue(event2.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertFalse(event3.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PrincipalAuthenticationFailureEvent does not contain sessionId at all

        String idpAuthLogMsg = testLogger.getMessageAtIndex(0);
        assertLogMessageWithSession(idpAuthLogMsg, IdentityProviderAuthenticationFailure, "null", testUser.getUserName());

        String userAuthLogMsg = testLogger.getMessageAtIndex(1);
        assertLogMessageWithSession(userAuthLogMsg, UserAuthenticationFailure, testUser.getId(), testUser.getUserName());

        String principalAuthLogMsg = testLogger.getMessageAtIndex(2);
        assertLogMessageWithoutSession(principalAuthLogMsg, PrincipalAuthenticationFailure, testUser.getUserName(), "null");
    }

    @Test
    void findAuditHistory(@Autowired JdbcAuditService auditService) throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        ScimUser jacob = createUser(adminToken, "jacob", "Jacob", "Gyllenhammer", "jacob@gyllenhammer.non", "password", true);
        String jacobId = jacob.getId();

        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", jacob.getUserName())
                .param("password", "notvalid");
        int attempts = 8;
        for (int i = 0; i < attempts; i++) {
            mockMvc.perform(loginPost)
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().string("{\"error\":\"authentication failed\"}"));
        }

        //after we reach our max attempts, 5, the system stops logging them until the period is over
        List<AuditEvent> events = auditService.find(jacobId, System.currentTimeMillis() - 10000, identityZoneManager.getCurrentIdentityZoneId());
        assertEquals(5, events.size());
        for (AuditEvent event : events) {
            assertTrue(event.getOrigin().contains("sessionId=<SESSION>"));
        }
    }

    @Test
    void userNotFoundLoginUnsuccessfulTest() throws Exception {
        String username = "test1234";

        MockHttpServletRequestBuilder loginPost = post("/login.do")
                .with(cookieCsrf())
                .session(new MockHttpSession())
                .accept(MediaType.TEXT_HTML_VALUE)
                .param("username", username)
                .param("password", testPassword);
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=login_failure"));

        assertNumberOfAuditEventsReceived(2);

        UserNotFoundEvent event1 = (UserNotFoundEvent) testListener.getEvents().get(0);
        assertTrue(event1.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertEquals(username, ((Authentication) event1.getSource()).getName());
        assertEquals(username, event2.getName());
        assertFalse(event2.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PrincipalAuthenticationFailureEvent does not contain sessionId at all

        String encodedUsername = Utf8.decode(org.springframework.security.crypto.codec.Base64.encode(MessageDigest.getInstance("SHA-1").digest(Utf8.encode(username))));
        assertLogMessageWithSession(testLogger.getMessageAtIndex(0), UserNotFound, encodedUsername, "");
        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(1), PrincipalAuthenticationFailure, username, "null");
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

        assertNumberOfAuditEventsReceived(2);

        IdentityProviderAuthenticationSuccessEvent passwordevent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        resetAuditTestReceivers();
        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        assertNumberOfAuditEventsReceived(4);

        assertTrue(testListener.getLatestEvent() instanceof TokenIssuedEvent);
        assertThat(testLogger.getLatestMessage(), startsWith(TokenIssuedEvent.toString()));

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/" + userid + "/password")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content("{\n" +
                        "  \"password\": \"Koala2\",\n" +
                        "  \"oldPassword\": \"" + testPassword + "\"\n" +
                        "}");

        resetAuditTestReceivers();
        mockMvc.perform(changePasswordPut).andExpect(status().isOk());
        assertNumberOfAuditEventsReceived(1);

        PasswordChangeEvent pw = (PasswordChangeEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
        assertTrue(pw.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        assertLogMessageWithSession(testLogger.getLatestMessage(), PasswordChangeSuccess, testUser.getId(), "Password changed");
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

        assertNumberOfAuditEventsReceived(2);

        IdentityProviderAuthenticationSuccessEvent passwordevent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertTrue(passwordevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertEquals(passwordevent.getUser().getId(), userevent.getUser().getId());
        assertTrue(userevent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));
        assertEquals(OriginKeys.UAA, passwordevent.getAuthenticationType());

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        resetAuditTestReceivers();
        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        assertNumberOfAuditEventsReceived(4);

        assertTrue(testListener.getLatestEvent() instanceof TokenIssuedEvent);
        assertThat(testLogger.getLatestMessage(), startsWith(TokenIssuedEvent.toString()));

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/" + userid + "/password")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content("{\n" +
                        "  \"password\": \"Koala2\",\n" +
                        "  \"oldPassword\": \"invalid\"\n" +
                        "}");

        resetAuditTestReceivers();
        mockMvc.perform(changePasswordPut).andExpect(status().isUnauthorized());
        assertNumberOfAuditEventsReceived(1);

        PasswordChangeFailureEvent pwfe = (PasswordChangeFailureEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), pwfe.getUser().getUsername());
        assertEquals("Old password is incorrect", pwfe.getMessage());
        assertTrue(pwfe.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        assertLogMessageWithSession(testLogger.getLatestMessage(), PasswordChangeFailure, testUser.getUserName(), "Old password is incorrect");
    }

    @Test
    void password_change_recorded_at_dao(@Autowired ScimUserProvisioning provisioning) {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator().generate() + "@test.org", "first", "last");
        user.setPrimaryEmail(user.getUserName());
        user = provisioning.createUser(user, "oldpassword", identityZoneManager.getCurrentIdentityZoneId());
        provisioning.changePassword(user.getId(), "oldpassword", "newpassword", identityZoneManager.getCurrentIdentityZoneId());

        assertNumberOfAuditEventsReceived(2);

        //the last event should be our password modified event
        PasswordChangeEvent pw = (PasswordChangeEvent) testListener.getLatestEvent();
        assertEquals(user.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());

        assertLogMessageWithoutSession(testLogger.getLatestMessage(), PasswordChangeSuccess, user.getId(), "Password changed");
    }

    @Test
    void changePassword_ReturnsSuccess_WithValidExpiringCode() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        String expiringCode = requestExpiringCode(testUser.getUserName(), loginToken);

        LostPasswordChangeRequest pwch = new LostPasswordChangeRequest();
        pwch.setChangeCode(expiringCode);
        pwch.setNewPassword("Koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
                .header("Authorization", "Bearer " + loginToken)
                .content(JsonUtils.writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(5);

        PasswordChangeEvent pce = (PasswordChangeEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), pce.getUser().getUsername());
        assertEquals("Password changed", pce.getMessage());
        assertFalse(pce.getAuditEvent().getOrigin().contains("sessionId=<SESSION>")); //PasswordChangeEvent does not contain session in this case

        assertLogMessageWithoutSession(testLogger.getLatestMessage(), PasswordChangeSuccess, testUser.getId(), "Password changed");
    }

    @Test
    void clientAuthenticationSuccess() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(2);

        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent) testListener.getEvents().get(0);
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());

        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(0), ClientAuthenticationSuccess, "login", "Client authentication success");
    }

    @Test
    void clientAuthenticationFailure() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login:loginsecretwrong").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());

        assertNumberOfAuditEventsReceived(2);

        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent) testListener.getLatestEvent();
        assertEquals("login", event.getClientId());
        AuditEvent auditEvent = event.getAuditEvent();
        assertEquals("login", auditEvent.getPrincipalId());

        assertLogMessageWithoutSession(testLogger.getLatestMessage(), ClientAuthenticationFailure, "login", "Bad credentials");
    }

    @Test
    void clientAuthenticationFailureClientNotFound() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("login2:loginsecret").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", "login")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());

        assertNumberOfAuditEventsReceived(2);

        PrincipalAuthenticationFailureEvent event0 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(0);
        assertEquals("login2", event0.getAuditEvent().getPrincipalId());
        ClientAuthenticationFailureEvent event1 = (ClientAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertEquals("login", event1.getClientId());

        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(0), PrincipalAuthenticationFailure, "login2", "null");
        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(1), ClientAuthenticationFailure, "login", "Bad credentials");
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

        MockHttpServletRequestBuilder approvalsPut = put("/approvals")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
                .header("Authorization", "Bearer " + marissaToken)
                .content(JsonUtils.writeValueAsBytes(approvals));

        resetAuditTestReceivers();

        mockMvc.perform(approvalsPut)
                .andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(1);

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), approvalModifiedEvent.getAuthentication().getName());
        assertTrue(approvalModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        String latestMessage = testLogger.getLatestMessage();
        assertThat(latestMessage, containsString(" user=" + testUser.getUserName()));
        assertLogMessageWithSession(latestMessage, ApprovalModifiedEvent, testUser.getId(), "{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}");
    }

    @Test
    void generateUserModifiedEvent_whenUserCreatedByClient() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        resetAuditTestReceivers();

        ScimUser scimUser = buildRandomScimUser();

        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(scimUser));

        mockMvc.perform(userPost)
                .andExpect(status().isCreated());

        assertNumberOfAuditEventsReceived(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(scimUser.getUserName(), userModifiedEvent.getUsername());
        assertEquals(UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(scimUser.getUserName())).findFirst().get();
        String logMessage = format("[\"user_id=%s\",\"username=%s\",\"user_origin=uaa\",\"created_by_client_id=%s\"]",
                createdUser.getId(),
                scimUser.getUserName(),
                testAccounts.getAdminClientId());
        assertLogMessageWithSession(testLogger.getLatestMessage(),
                UserCreatedEvent, createdUser.getId(), logMessage);
    }

    @Nested
    @DefaultTestContext
    @ExtendWith(ZoneSeederExtension.class)
    class AsUserWithScimWrite {

        private ZoneSeeder zoneSeeder;
        private ScimUser scimWriteUser;
        private ClientDetails adminClient;
        private String scimWriteUserToken;
        private ScimUser scimUser;
        private MockHttpSession mockHttpSession;

        @BeforeEach
        void setUp(final ZoneSeeder zoneSeeder, @Autowired TestClient testClient) {
            this.zoneSeeder = zoneSeeder
                    .withDefaults()
                    .withClientWithImplicitPasswordRefreshTokenGrants("admin_client", "scim.write")
                    .withUserWhoBelongsToGroups("admin@test.org", Lists.newArrayList("scim.write"))
                    .afterSeeding(zs -> {
                        scimWriteUser = zs.getUserByEmail("admin@test.org");
                        adminClient = zs.getClientById("admin_client");

                        scimWriteUserToken = testClient.getUserOAuthAccessTokenForZone(
                                adminClient.getClientId(),
                                zoneSeeder.getPlainTextClientSecret(adminClient),
                                scimWriteUser.getUserName(),
                                zoneSeeder.getPlainTextPassword(scimWriteUser),
                                "scim.write",
                                zoneSeeder.getIdentityZoneSubdomain()
                        );

                    });
            scimUser = buildRandomScimUser();
            mockHttpSession = new MockHttpSession();
        }

        @Test
        void generateUserModifiedEvent_whenCreatingUser(
                @Autowired MockMvc mockMvc
        ) throws Exception {

            MockHttpServletRequestBuilder userPost = post("/Users")
                    .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                    .accept(APPLICATION_JSON_VALUE)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(mockHttpSession)
                    .with(httpBearer(scimWriteUserToken))
                    .content(JsonUtils.writeValueAsBytes(scimUser));

            mockMvc.perform(userPost)
                    .andExpect(status().isCreated());

            ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(zoneSeeder.getIdentityZoneId())
                    .stream().filter(dbUser -> dbUser.getUserName().equals(scimUser.getUserName())).findFirst().get();

            String logMessage = format(" ('[\"user_id=%s\",\"username=%s\",\"user_origin=uaa\",\"created_by_user_id=%s\",\"created_by_username=%s\"]'): ",
                    createdUser.getId(),
                    scimUser.getUserName(),
                    scimWriteUser.getId(),
                    scimWriteUser.getUserName());
            String actualLogMessage = testLogger.getLatestMessage();
            assertThat(actualLogMessage, startsWith(UserCreatedEvent.toString() + " "));
            assertThat(actualLogMessage, containsString(format("principal=%s,", createdUser.getId())));
            assertThat(actualLogMessage, containsString(logMessage));
            assertThat(actualLogMessage, containsString(format(", identityZoneId=[%s]", zoneSeeder.getIdentityZoneId())));
            assertThat(actualLogMessage, matchesRegex(".*origin=\\[.*sessionId=<SESSION>.*\\].*"));
        }

        @Test
        void generateUserDeletedEvent_whenDeletingUser(
                @Autowired MockMvc mockMvc
        ) throws Exception {
            MockHttpServletRequestBuilder userPost = post("/Users")
                    .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                    .accept(APPLICATION_JSON_VALUE)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(new MockHttpSession())
                    .with(httpBearer(scimWriteUserToken))
                    .content(JsonUtils.writeValueAsBytes(scimUser));

            mockMvc.perform(userPost)
                    .andExpect(status().isCreated());

            scimUser = jdbcScimUserProvisioning.retrieveAll(zoneSeeder.getIdentityZoneId())
                    .stream().filter(dbUser -> dbUser.getUserName().equals(scimUser.getUserName())).findFirst().get();

            MockHttpServletRequestBuilder userDelete = delete("/Users/" + scimUser.getId())
                    .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(mockHttpSession)
                    .with(httpBearer(scimWriteUserToken))
                    .header("If-Match", scimUser.getVersion());

            resetAuditTestReceivers();
            mockMvc.perform(userDelete).andExpect(status().isOk());

            assertNumberOfAuditEventsReceived(2);

            String logMessage = format("[\"user_id=%s\",\"username=%s\",\"user_origin=uaa\",\"deleted_by_user_id=%s\",\"deleted_by_username=%s\"]",
                    scimUser.getId(),
                    scimUser.getUserName(),
                    scimWriteUser.getId(),
                    scimWriteUser.getUserName());
            String actualLogMessage = testLogger.getLatestMessage();
            assertThat(actualLogMessage, startsWith(UserDeletedEvent.toString() + " "));
            assertThat(actualLogMessage, containsString(format("principal=%s,", scimUser.getId())));
            assertThat(actualLogMessage, containsString(format(" ('%s'): ", logMessage)));
            assertThat(actualLogMessage, containsString(format(", identityZoneId=[%s]", zoneSeeder.getIdentityZoneId())));
            assertThat(actualLogMessage, matchesRegex(".*origin=\\[.*sessionId=<SESSION>.*\\].*"));
        }

    }

    @Test
    void generateUserCreatedEvent_DuringLoginServerAuthorize() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login", "http://localhost:8080/uaa"));
        String username = "jacob" + new RandomValueStringGenerator().generate();
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(
                "login",
                "loginsecret",
                "oauth.login");

        resetAuditTestReceivers();

        MockHttpServletRequestBuilder userPost = post("/oauth/authorize")
                .with(cookieCsrf())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
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

        mockMvc.perform(userPost)
                .andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(3);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getEvents().get(0);
        assertEquals("login", userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(username)).findFirst().get();

        String logMessage = format("[\"user_id=%s\",\"username=%s\",\"user_origin=login-server\",\"created_by_client_id=%s\"]",
                createdUser.getId(),
                username,
                "login");

        assertLogMessageWithSession(testLogger.getMessageAtIndex(0),
                UserCreatedEvent, createdUser.getId(), logMessage);
    }

    @Nested
    @DefaultTestContext
    class AsClientWithScimWrite {

        private String scimWriteClientToken;
        private ScimUser scimUser;
        private MockHttpSession mockHttpSession;

        @BeforeEach
        void setUp(
                @Autowired MockMvc mockMvc,
                @Autowired TestClient testClient
        ) throws Exception {

            scimWriteClientToken = testClient.getClientCredentialsOAuthAccessToken(
                    testAccounts.getAdminClientId(),
                    testAccounts.getAdminClientSecret(),
                    "scim.write");

            scimUser = buildRandomScimUser();
            mockHttpSession = new MockHttpSession();

            MockHttpServletRequestBuilder userPost = post("/Users")
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(mockHttpSession)
                    .with(httpBearer(scimWriteClientToken))
                    .content(JsonUtils.writeValueAsBytes(scimUser));

            ResultActions result = mockMvc.perform(userPost)
                    .andExpect(status().isCreated());

            scimUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

            resetAuditTestReceivers();
        }

        @Test
        void generateUserModifiedEvent_whenModifyingUser(
                @Autowired MockMvc mockMvc
        ) throws Exception {

            scimUser.getName().setGivenName(scimUser.getName().getGivenName() + "modified");
            MockHttpServletRequestBuilder userPut = put("/Users/" + scimUser.getId())
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(mockHttpSession)
                    .with(httpBearer(scimWriteClientToken))
                    .header("If-Match", scimUser.getVersion())
                    .content(JsonUtils.writeValueAsBytes(scimUser));
            mockMvc.perform(userPut).andExpect(status().isOk());

            assertNumberOfAuditEventsReceived(1);

            UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
            assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
            assertEquals(scimUser.getUserName(), userModifiedEvent.getUsername());
            assertEquals(UserModifiedEvent, userModifiedEvent.getAuditEvent().getType());
            assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

            String logMessage = format("[\"user_id=%s\",\"username=%s\"]", scimUser.getId(), scimUser.getUserName());
            assertLogMessageWithSession(testLogger.getLatestMessage(),
                    UserModifiedEvent,
                    scimUser.getId(),
                    logMessage);
        }

        @Test
        void generateUserDeletedEvent_whenDeletingUser(
                @Autowired MockMvc mockMvc
        ) throws Exception {

            MockHttpServletRequestBuilder userDelete = delete("/Users/" + scimUser.getId())
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .session(mockHttpSession)
                    .with(httpBearer(scimWriteClientToken))
                    .header("If-Match", scimUser.getVersion());

            mockMvc.perform(userDelete).andExpect(status().isOk());

            assertNumberOfAuditEventsReceived(2);

            UserModifiedEvent userDeletedEvent = (UserModifiedEvent) testListener.getLatestEvent();
            assertEquals(testAccounts.getAdminClientId(), userDeletedEvent.getAuthentication().getName());
            assertEquals(scimUser.getUserName(), userDeletedEvent.getUsername());
            assertEquals(UserDeletedEvent, userDeletedEvent.getAuditEvent().getType());
            assertTrue(userDeletedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

            String logMessage = format("[\"user_id=%s\",\"username=%s\",\"user_origin=uaa\",\"deleted_by_client_id=%s\"]",
                    scimUser.getId(),
                    scimUser.getUserName(),
                    testAccounts.getAdminClientId());
            assertLogMessageWithSession(testLogger.getLatestMessage(),
                    UserDeletedEvent, scimUser.getId(), logMessage);
        }
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

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", user.getVersion());

        resetAuditTestReceivers();
        mockMvc.perform(verifyGet).andExpect(status().isOk());

        assertNumberOfAuditEventsReceived(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(UserVerifiedEvent, userModifiedEvent.getAuditEvent().getType());
        assertTrue(userModifiedEvent.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        assertLogMessageWithSession(testLogger.getLatestMessage(),
                UserVerifiedEvent, user.getId(), format("[\"user_id=%s\",\"username=%s\"]", user.getId(), username));
    }

    @Test
    void passwordResetRequestEvent() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        resetAuditTestReceivers();

        MockHttpServletRequestBuilder changePasswordPost = post("/password_resets")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
                .header("Authorization", "Bearer " + loginToken)
                .content(testUser.getUserName());

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isCreated());

        assertNumberOfAuditEventsReceived(1);

        ResetPasswordRequestEvent event = (ResetPasswordRequestEvent) testListener.getLatestEvent();
        assertEquals(testUser.getUserName(), event.getAuditEvent().getPrincipalId());
        assertEquals(testUser.getPrimaryEmail(), event.getAuditEvent().getData());
        assertTrue(event.getAuditEvent().getOrigin().contains("sessionId=<SESSION>"));

        assertLogMessageWithSession(testLogger.getLatestMessage(),
                PasswordResetRequest, testUser.getUserName(), testUser.getPrimaryEmail());
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


        ScimGroup group = new ScimGroup(null, "testgroup", identityZoneManager.getCurrentIdentityZoneId());
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
        String[] groupMemberIds = Stream.of(jacob, emily)
                .map(ScimCore::getId)
                .toArray(String[]::new);

        resetAuditTestReceivers();

        MockHttpServletRequestBuilder groupPost = post("/Groups")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(group));

        ResultActions result = mockMvc.perform(groupPost).andExpect(status().isCreated());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertNumberOfAuditEventsReceived(1);

        GroupModifiedEvent event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(GroupCreatedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds),
                JsonUtils.readValue(event.getAuditEvent().getData(),
                        GroupModifiedEvent.GroupInfo.class)
        );

        verifyGroupAuditData(group, groupMemberIds, GroupCreatedEvent);

        assertGroupMembershipLogMessage(testLogger.getLatestMessage(),
                GroupCreatedEvent, group.getDisplayName(), group.getId(), jacob.getId(), emily.getId());

        //update the group with one additional member
        List<ScimGroupMember> members = group.getMembers();
        members.add(mjonas);
        groupMemberIds = Stream.of(jacob, emily, jonas)
                .map(ScimCore::getId)
                .toArray(String[]::new);

        group.setMembers(members);
        MockHttpServletRequestBuilder groupPut = put("/Groups/" + group.getId())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", group.getVersion())
                .content(JsonUtils.writeValueAsBytes(group));

        resetAuditTestReceivers();

        result = mockMvc.perform(groupPut).andExpect(status().isOk());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertNumberOfAuditEventsReceived(1);

        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(GroupModifiedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds),
                JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));

        verifyGroupAuditData(group, groupMemberIds, GroupModifiedEvent);

        assertGroupMembershipLogMessage(testLogger.getLatestMessage(),
                GroupModifiedEvent, group.getDisplayName(), group.getId(), jacob.getId(), emily.getId(), jonas.getId());

        //delete the group
        MockHttpServletRequestBuilder groupDelete = delete("/Groups/" + group.getId())
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + adminToken)
                .header("If-Match", group.getVersion())
                .content(JsonUtils.writeValueAsBytes(group));

        resetAuditTestReceivers();

        result = mockMvc.perform(groupDelete).andExpect(status().isOk());
        group = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        assertNumberOfAuditEventsReceived(1);

        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertEquals(GroupDeletedEvent, event.getAuditEvent().getType());
        assertEquals(group.getId(), event.getAuditEvent().getPrincipalId());
        assertEquals(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds),
                JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class));

        verifyGroupAuditData(group, groupMemberIds, GroupDeletedEvent);

        assertGroupMembershipLogMessage(testLogger.getLatestMessage(),
                GroupDeletedEvent, group.getDisplayName(), group.getId(), jacob.getId(), emily.getId(), jonas.getId());
    }

    private static ScimUser buildRandomScimUser() {
        String username = "jacob" + new RandomValueStringGenerator().generate();
        String firstName = "Jacob";
        String lastName = "Gyllenhammar";
        String email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        return user;
    }

    private void verifyGroupAuditData(ScimGroup group, String[] groupMemberIds, AuditEventType eventType) {
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
        assertThat((Collection<String>) auditObjects.get("members"), containsInAnyOrder(groupMemberIds));
    }

    private ScimUser createUser(String adminToken, String username, String firstname, String lastname, String email, String password, boolean verified) throws Exception {
        ScimUser user = new ScimUser();
        username += new RandomValueStringGenerator().generate();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstname, lastname));
        user.addEmail(email);
        user.setPassword(password);
        user.setVerified(verified);

        MockHttpServletRequestBuilder userPost = post("/Users")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(new MockHttpSession())
                .header("Authorization", "Bearer " + adminToken)
                .content(JsonUtils.writeValueAsBytes(user));

        resetAuditTestReceivers();

        ResultActions result = mockMvc.perform(userPost).andExpect(status().isCreated());

        assertNumberOfAuditEventsReceived(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());
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

    private void resetAuditTestReceivers() {
        testListener.clearEvents();
        testLogger.reset();
    }

    private void assertNumberOfAuditEventsReceived(int expectedEventCount) {
        assertEquals(expectedEventCount, testListener.getEventCount());
        assertEquals(expectedEventCount, testLogger.getMessageCount());
    }

    private void assertSingleAuditEventFiredWith(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        assertSingleClientAdminAuditEventFiredWith(expectedEventType, expectedScopes, expectedAuthorities);
        assertSingleAuditEventLogMessage(expectedEventType, expectedScopes, expectedAuthorities);
    }

    private void assertSingleClientAdminAuditEventFiredWith(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        List<AbstractUaaEvent> events = testListener.getEvents().stream().filter(e -> e instanceof AbstractClientAdminEvent).collect(Collectors.toList());
        assertNotNull(events);
        assertEquals(1, events.size());

        AbstractUaaEvent event = events.get(0);
        assertEquals(expectedEventType, event.getAuditEvent().getType());

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture(), anyString());

        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType() == expectedEventType).collect(Collectors.toList());
        assertNotNull(auditEvents);
        assertEquals(1, auditEvents.size());

        AuditEvent auditEvent = auditEvents.get(0);
        String auditEventData = auditEvent.getData();
        assertNotNull(auditEventData);

        Map<String, Object> map = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {
        });
        List<String> auditScopes = (List<String>) map.get("scopes");
        List<String> auditAuthorities = (List<String>) map.get("authorities");

        assertNotNull(auditScopes);
        assertNotNull(auditAuthorities);
        assertThat(auditScopes, containsInAnyOrder(expectedScopes));
        assertThat(auditAuthorities, containsInAnyOrder(expectedAuthorities));
    }

    private void assertSingleAuditEventLogMessage(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        assertEquals(1, testLogger.getMessageCount());

        String message = testLogger.getLatestMessage();
        assertThat(message, startsWith(expectedEventType.toString()));
        String commaSeparatedQuotedScopes = Arrays.stream(expectedScopes).map(s -> "\"" + s + "\"").collect(joining(","));
        assertThat(message, containsString(format("\"scopes\":[%s]", commaSeparatedQuotedScopes)));

        String commaSeparatedQuotedAuthorities = Arrays.stream(expectedAuthorities).map(s -> "\"" + s + "\"").collect(joining(","));
        assertThat(message, containsString(format("\"authorities\":[%s]", commaSeparatedQuotedAuthorities)));
    }

    private void assertLogMessageWithSession(String actualLogMessage, AuditEventType expectedAuditEventType, String expectedPrincipal, String expectedUserName) {
        assertThat(actualLogMessage, startsWith(expectedAuditEventType.toString() + " "));
        assertThat(actualLogMessage, containsString(format("principal=%s,", expectedPrincipal)));
        assertThat(actualLogMessage, containsString(format(" ('%s'): ", expectedUserName)));
        assertThat(actualLogMessage, containsString(", identityZoneId=[uaa]"));
        assertThat(actualLogMessage, matchesRegex(".*origin=\\[.*sessionId=<SESSION>.*\\].*"));
    }

    private static void assertLogMessageWithoutSession(String actualLogMessage, AuditEventType expectedAuditEventType, String expectedPrincipal, String expectedUserName) {
        assertThat(actualLogMessage, startsWith(expectedAuditEventType.toString() + " "));
        assertThat(actualLogMessage, containsString(format("principal=%s,", expectedPrincipal)));
        assertThat(actualLogMessage, containsString(format(" ('%s'): ", expectedUserName)));
        assertThat(actualLogMessage, containsString(", identityZoneId=[uaa]"));
        assertThat(actualLogMessage, not(containsString("sessionId")));
    }

    private static void assertGroupMembershipLogMessage(String actualLogMessage, AuditEventType expectedEventType, String expectedGroupDisplayName, String expectedGroupId, String... expectedUserIds) {
        assertThat(actualLogMessage, startsWith(expectedEventType.toString() + " "));
        assertThat(actualLogMessage, containsString(format("principal=%s,", expectedGroupId)));
        assertThat(actualLogMessage, not(containsString("sessionId")));

        Pattern groupLogPattern = Pattern.compile(" \\('\\{\"group_name\":\"" + Pattern.quote(expectedGroupDisplayName) + "\",\"members\":\\[(.*?)]}'\\): ");
        Matcher patternMatcher = groupLogPattern.matcher(actualLogMessage);
        assertThat(patternMatcher.find(), is(true));
        Set<String> memberIdsFromLogMessage = StringUtils.commaDelimitedListToSet(patternMatcher.group(1).replaceAll("\"", ""));
        assertThat(memberIdsFromLogMessage, equalTo(Sets.newHashSet(expectedUserIds)));
    }

}
