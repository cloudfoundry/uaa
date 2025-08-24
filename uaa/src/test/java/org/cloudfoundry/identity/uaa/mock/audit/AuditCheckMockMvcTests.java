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
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.AuditListener;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.event.AbstractClientAdminEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.*;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeast;
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

@DefaultTestContext
@DirtiesContext
class AuditCheckMockMvcTests {

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    private MultitenantClientServices clientRegistrationService;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;
    private ApplicationListener<UserAuthenticationSuccessEvent> authSuccessListener;
    private ScimUser testUser;
    private final String testPassword = "secr3T";
    @Autowired
    @Qualifier("uaaUserDatabaseAuthenticationManager")
    private AuthzAuthenticationManager mgr;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private String adminToken;
    private UaaAuditService mockAuditService;
    private AuditListener auditListener;
    private ClientDetails originalLoginClient;

    @Autowired
    private GenericWebApplicationContext configurableApplicationContext;
    @Autowired
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
    void setUp() throws Exception {
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
    void resetLoginClient() {
        clientRegistrationService.updateClientDetails(originalLoginClient);
        MockMvcUtils.removeEventListener(configurableApplicationContext, testListener);
        MockMvcUtils.removeEventListener(configurableApplicationContext, authSuccessListener);
        MockMvcUtils.removeEventListener(configurableApplicationContext, auditListener);
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
        UaaClientDetails client = new UaaClientDetails(clientId, resource, scopes, grantTypes, authorities);
        client.setClientSecret(clientSecret);

        mockMvc.perform(post("/oauth/clients")
                .header(AUTHORIZATION, "Bearer " + adminToken)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(client))
        ).andExpect(status().isCreated());
        assertSingleAuditEventFiredWith(ClientCreateSuccess, new String[]{"scope1", "scope2", "scope3"}, new String[]{"uaa.resource", "uaa.admin"});

        resetAuditTestReceivers();

        client.setScope(Arrays.asList("scope4", "scope5"));
        client.setAuthorities(Arrays.asList(new SimpleGrantedAuthority("authority1"), new SimpleGrantedAuthority("authority2")));

        mockMvc.perform(put("/oauth/clients/" + clientId)
                .header(AUTHORIZATION, "Bearer " + adminToken)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(client))
        ).andExpect(status().isOk());
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        IdentityProviderAuthenticationSuccessEvent passwordEvent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        assertThat(passwordEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(passwordEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userEvent.getUser().getId()).isEqualTo(passwordEvent.getUser().getId());
        assertThat(userEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(userEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        assertThat(passwordEvent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        IdentityProviderAuthenticationSuccessEvent passwordEvent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        assertThat(passwordEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(passwordEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userEvent.getUser().getId()).isEqualTo(passwordEvent.getUser().getId());
        assertThat(userEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(userEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        assertThat(passwordEvent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

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

        // When the profile is ldap, an extra event is emitted
        assertThatNumberOfAuditEventsReceivedIsGreaterThanOrEqualTo(3);

        IdentityProviderAuthenticationFailureEvent idpAuthFailEvent = (IdentityProviderAuthenticationFailureEvent) testListener.getEvents().getFirst();
        assertThat(idpAuthFailEvent.getUsername()).isEqualTo(testUser.getUserName());
        assertThat(idpAuthFailEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        UserAuthenticationFailureEvent userAuthFailEvent = (UserAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertThat(userAuthFailEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(userAuthFailEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        PrincipalAuthenticationFailureEvent principalAuthFailEvent = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(2);
        assertThat(principalAuthFailEvent.getName()).isEqualTo(testUser.getUserName());
        assertThat(principalAuthFailEvent.getAuditEvent().getOrigin()).doesNotContain("sessionId"); // PrincipalAuthenticationFailureEvent should not contain sessionId at all

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(3);

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(authSuccessListener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertThat(event.getUser().getUsername()).isEqualTo(molly.getUserName());
        assertThat(event.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        UnverifiedUserAuthenticationEvent unverifiedUserAuthEvent = testListener.getLatestEventOfType(UnverifiedUserAuthenticationEvent.class);
        assertThat(unverifiedUserAuthEvent.getUser().getUsername()).isEqualTo(molly.getUserName());
        assertThat(unverifiedUserAuthEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        UnverifiedUserAuthenticationEvent event = (UnverifiedUserAuthenticationEvent) testListener.getLatestEvent();
        assertThat(event.getUser().getUsername()).isEqualTo(molly.getUserName());
        assertThat(event.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

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

        // When the profile is ldap, an extra event is emitted
        assertThatNumberOfAuditEventsReceivedIsGreaterThanOrEqualTo(3);

        IdentityProviderAuthenticationFailureEvent event1 = (IdentityProviderAuthenticationFailureEvent) testListener.getEvents().getFirst();
        UserAuthenticationFailureEvent event2 = (UserAuthenticationFailureEvent) testListener.getEvents().get(1);
        PrincipalAuthenticationFailureEvent event3 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(2);
        assertThat(event1.getUsername()).isEqualTo(testUser.getUserName());
        assertThat(event2.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(event3.getName()).isEqualTo(testUser.getUserName());
        assertThat(event1.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        assertThat(event2.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        // PrincipalAuthenticationFailureEvent does not contain sessionId at all
        assertThat(event3.getAuditEvent().getOrigin()).doesNotContain("sessionId=<SESSION>");

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
        assertThat(events).hasSize(5);
        for (AuditEvent event : events) {
            assertThat(event.getOrigin()).contains("sessionId=<SESSION>");
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

        // When the profile is ldap, an extra event is emitted
        assertThatNumberOfAuditEventsReceivedIsGreaterThanOrEqualTo(2);

        UserNotFoundEvent event1 = (UserNotFoundEvent) testListener.getEvents().getFirst();
        assertThat(event1.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertThat(((Authentication) event1.getSource()).getName()).isEqualTo(username);
        assertThat(event2.getName()).isEqualTo(username);
        // PrincipalAuthenticationFailureEvent does not contain sessionId at all
        assertThat(event2.getAuditEvent().getOrigin()).doesNotContain("sessionId=<SESSION>");

        String encodedUsername = Utf8.decode(Base64.encodeBase64(MessageDigest.getInstance("SHA-1").digest(Utf8.encode(username))));
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        IdentityProviderAuthenticationSuccessEvent passwordevent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertThat(passwordevent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userevent.getUser().getId()).isEqualTo(passwordevent.getUser().getId());
        assertThat(userevent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        assertThat(passwordevent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        resetAuditTestReceivers();
        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        assertThatNumberOfAuditEventsReceivedIsEqualTo(4);

        assertThat(testListener.getLatestEvent()).isInstanceOf(TokenIssuedEvent.class);
        assertThat(testLogger.getLatestMessage()).startsWith(TokenIssuedEvent.toString());

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
        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        PasswordChangeEvent pw = (PasswordChangeEvent) testListener.getLatestEvent();
        assertThat(pw.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(pw.getMessage()).isEqualTo("Password changed");
        assertThat(pw.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        IdentityProviderAuthenticationSuccessEvent passwordevent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        String userid = passwordevent.getUser().getId();
        assertThat(passwordevent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userevent.getUser().getId()).isEqualTo(passwordevent.getUser().getId());
        assertThat(userevent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");
        assertThat(passwordevent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessageWithSession(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessageWithSession(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        resetAuditTestReceivers();
        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testUser.getUserName(), testPassword, "password.write");
        assertThatNumberOfAuditEventsReceivedIsEqualTo(4);

        assertThat(testListener.getLatestEvent()).isInstanceOf(TokenIssuedEvent.class);
        assertThat(testLogger.getLatestMessage()).startsWith(TokenIssuedEvent.toString());

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/" + userid + "/password")
                .accept(APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .session(session)
                .header("Authorization", "Bearer " + marissaToken)
                .content("""
                        {
                          "password": "Koala2",
                          "oldPassword": "invalid"
                        }\
                        """);

        resetAuditTestReceivers();
        mockMvc.perform(changePasswordPut).andExpect(status().isUnauthorized());
        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        PasswordChangeFailureEvent pwfe = (PasswordChangeFailureEvent) testListener.getLatestEvent();
        assertThat(pwfe.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(pwfe.getMessage()).isEqualTo("Old password is incorrect");
        assertThat(pwfe.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        assertLogMessageWithSession(testLogger.getLatestMessage(), PasswordChangeFailure, testUser.getUserName(), "Old password is incorrect");
    }

    @Test
    void password_change_recorded_at_dao(@Autowired ScimUserProvisioning provisioning) {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator().generate() + "@test.org", "first", "last");
        user.setPrimaryEmail(user.getUserName());
        user = provisioning.createUser(user, "oldpassword", identityZoneManager.getCurrentIdentityZoneId());
        provisioning.changePassword(user.getId(), "oldpassword", "newpassword", identityZoneManager.getCurrentIdentityZoneId());

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        //the last event should be our password modified event
        PasswordChangeEvent pw = (PasswordChangeEvent) testListener.getLatestEvent();
        assertThat(pw.getUser().getUsername()).isEqualTo(user.getUserName());
        assertThat(pw.getMessage()).isEqualTo("Password changed");

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(5);

        PasswordChangeEvent pce = (PasswordChangeEvent) testListener.getLatestEvent();
        assertThat(pce.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(pce.getMessage()).isEqualTo("Password changed");
        //PasswordChangeEvent does not contain session in this case
        assertThat(pce.getAuditEvent().getOrigin()).doesNotContain("sessionId=<SESSION>");

        assertLogMessageWithoutSession(testLogger.getLatestMessage(), PasswordChangeSuccess, testUser.getId(), "Password changed");
    }

    @Test
    void clientAuthenticationSuccess() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isOk());

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent) testListener.getEvents().getFirst();
        assertThat(event.getClientId()).isEqualTo("login");
        AuditEvent auditEvent = event.getAuditEvent();
        assertThat(auditEvent.getPrincipalId()).isEqualTo("login");

        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(0), ClientAuthenticationSuccess, "login", "Client authentication success");
    }

    @Test
    void clientAuthenticationFailure() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64("login:loginsecretwrong".getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent) testListener.getLatestEvent();
        assertThat(event.getClientId()).isEqualTo("login");
        AuditEvent auditEvent = event.getAuditEvent();
        assertThat(auditEvent.getPrincipalId()).isEqualTo("login");

        assertLogMessageWithoutSession(testLogger.getLatestMessage(), ClientAuthenticationFailure, "login", "Bad credentials");
    }

    @Test
    void clientAuthenticationFailureClientNotFound() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64("login2:loginsecret".getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", "login")
                .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        PrincipalAuthenticationFailureEvent event0 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().getFirst();
        assertThat(event0.getAuditEvent().getPrincipalId()).isEqualTo("login2");
        ClientAuthenticationFailureEvent event1 = (ClientAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertThat(event1.getClientId()).isEqualTo("login");

        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(0), PrincipalAuthenticationFailure, "login2", "null");
        assertLogMessageWithoutSession(testLogger.getMessageAtIndex(1), ClientAuthenticationFailure, "login", "Bad credentials");
    }

    @Test
    void userApprovalAdded() throws Exception {
        clientRegistrationService.updateClientDetails(new UaaClientDetails("login", "oauth", "oauth.approvals", "password", "oauth.login"));

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        assertThat(approvalModifiedEvent.getAuthentication().getName()).isEqualTo(testUser.getUserName());
        assertThat(approvalModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        String latestMessage = testLogger.getLatestMessage();
        assertThat(latestMessage).contains(" user=" + testUser.getUserName());
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertThat(userModifiedEvent.getAuthentication().getName()).isEqualTo(testAccounts.getAdminClientId());
        assertThat(userModifiedEvent.getUsername()).isEqualTo(scimUser.getUserName());
        assertThat(userModifiedEvent.getAuditEvent().getType()).isEqualTo(UserCreatedEvent);
        assertThat(userModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(scimUser.getUserName())).findFirst().get();
        String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                createdUser.getId(),
                scimUser.getUserName());
        assertLogMessageWithSession(testLogger.getLatestMessage(),
                UserCreatedEvent, createdUser.getId(), logMessage);
    }

    @Nested
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

            String logMessage = " ('[\"user_id=%s\",\"username=%s\"]'): ".formatted(
                    createdUser.getId(),
                    scimUser.getUserName());
            String actualLogMessage = testLogger.getLatestMessage();
            assertThat(actualLogMessage).startsWith(UserCreatedEvent.toString())
                    .contains("principal=%s,".formatted(createdUser.getId()))
                    .contains(logMessage)
                    .contains(", identityZoneId=[%s]".formatted(zoneSeeder.getIdentityZoneId()))
                    .matches(".*origin=\\[.*sessionId=<SESSION>.*\\].*");
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

            assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

            String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                    scimUser.getId(),
                    scimUser.getUserName());
            String actualLogMessage = testLogger.getLatestMessage();
            assertThat(actualLogMessage).startsWith(UserDeletedEvent.toString())
                    .contains("principal=%s,".formatted(scimUser.getId()))
                    .contains(" ('%s'): ".formatted(logMessage))
                    .contains(", identityZoneId=[%s]".formatted(zoneSeeder.getIdentityZoneId()))
                    .matches(".*origin=\\[.*sessionId=<SESSION>.*\\].*");
        }

    }

    @Test
    void generateUserCreatedEvent_DuringLoginServerAuthorize() throws Exception {
        clientRegistrationService.updateClientDetails(new UaaClientDetails("login", "oauth", "oauth.approvals", "authorization_code,password,client_credentials", "oauth.login", "http://localhost:8080/uaa"));
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(3);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getEvents().getFirst();
        assertThat(userModifiedEvent.getAuthentication().getName()).isEqualTo("login");
        assertThat(userModifiedEvent.getUsername()).isEqualTo(username);
        assertThat(userModifiedEvent.getAuditEvent().getType()).isEqualTo(UserCreatedEvent);
        assertThat(userModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(username)).findFirst().get();

        String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                createdUser.getId(),
                username);

        assertLogMessageWithSession(testLogger.getMessageAtIndex(0),
                UserCreatedEvent, createdUser.getId(), logMessage);
    }

    @Nested
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

            assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

            UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
            assertThat(userModifiedEvent.getAuthentication().getName()).isEqualTo(testAccounts.getAdminClientId());
            assertThat(userModifiedEvent.getUsername()).isEqualTo(scimUser.getUserName());
            assertThat(userModifiedEvent.getAuditEvent().getType()).isEqualTo(UserModifiedEvent);
            assertThat(userModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

            String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(scimUser.getId(), scimUser.getUserName());
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

            assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

            UserModifiedEvent userDeletedEvent = (UserModifiedEvent) testListener.getLatestEvent();
            assertThat(userDeletedEvent.getAuthentication().getName()).isEqualTo(testAccounts.getAdminClientId());
            assertThat(userDeletedEvent.getUsername()).isEqualTo(scimUser.getUserName());
            assertThat(userDeletedEvent.getAuditEvent().getType()).isEqualTo(UserDeletedEvent);
            assertThat(userDeletedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

            String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                    scimUser.getId(),
                    scimUser.getUserName());
            assertLogMessageWithSession(testLogger.getLatestMessage(),
                    UserDeletedEvent, scimUser.getId(), logMessage);
        }
    }

    @Test
    void userVerifiedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,scim.write");

        String username = "jacob";
        String firstName = "Jacob";
        String lastName = "Gyllenhammar";
        String email = "jacob@gyllenhammar.non";
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertThat(userModifiedEvent.getAuthentication().getName()).isEqualTo(testAccounts.getAdminClientId());
        assertThat(userModifiedEvent.getUsername()).isEqualTo(username);
        assertThat(userModifiedEvent.getAuditEvent().getType()).isEqualTo(UserVerifiedEvent);
        assertThat(userModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        assertLogMessageWithSession(testLogger.getLatestMessage(),
                UserVerifiedEvent, user.getId(), "[\"user_id=%s\",\"username=%s\"]".formatted(user.getId(), username));
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        ResetPasswordRequestEvent event = (ResetPasswordRequestEvent) testListener.getLatestEvent();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(testUser.getUserName());
        assertThat(event.getAuditEvent().getData()).isEqualTo(testUser.getPrimaryEmail());
        assertThat(event.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        assertLogMessageWithSession(testLogger.getLatestMessage(),
                PasswordResetRequest, testUser.getUserName(), testUser.getPrimaryEmail());
    }

    @Test
    void groupEvents() throws Exception {
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        GroupModifiedEvent event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(GroupCreatedEvent);
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(group.getId());
        assertThat(JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class))
                .isEqualTo(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds));

        verifyGroupAuditData(groupMemberIds, GroupCreatedEvent);

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(GroupModifiedEvent);
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(group.getId());
        assertThat(JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class)).isEqualTo(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds));

        verifyGroupAuditData(groupMemberIds, GroupModifiedEvent);

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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        event = (GroupModifiedEvent) testListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(GroupDeletedEvent);
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(group.getId());
        assertThat(JsonUtils.readValue(event.getAuditEvent().getData(), GroupModifiedEvent.GroupInfo.class))
                .isEqualTo(new GroupModifiedEvent.GroupInfo(group.getDisplayName(), groupMemberIds));

        verifyGroupAuditData(groupMemberIds, GroupDeletedEvent);

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

    private void verifyGroupAuditData(String[] groupMemberIds, AuditEventType eventType) {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture(), anyString());
        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType() == eventType).toList();
        assertThat(auditEvents).hasSize(1);
        AuditEvent auditEvent = auditEvents.getFirst();
        String auditEventData = auditEvent.getData();
        assertThat(auditEventData).isNotNull();
        Map<String, Object> auditObjects = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {
        });
        assertThat(auditObjects).containsEntry("group_name", "testgroup");
        assertThat((Collection<String>) auditObjects.get("members")).containsExactlyInAnyOrder(groupMemberIds);
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(1);

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        assertThat(userModifiedEvent.getAuthentication().getName()).isEqualTo(testAccounts.getAdminClientId());
        assertThat(userModifiedEvent.getUsername()).isEqualTo(username);
        assertThat(userModifiedEvent.getAuditEvent().getType()).isEqualTo(UserCreatedEvent);
        assertThat(userModifiedEvent.getAuditEvent().getOrigin()).contains("sessionId=<SESSION>");

        return JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
    }

    private class DefaultApplicationListener<T extends ApplicationEvent> implements ApplicationListener<T> {
        @Override
        public void onApplicationEvent(T event) {
            // do nothing
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

    private void assertThatNumberOfAuditEventsReceivedIsEqualTo(int expectedEventCount) {
        assertThat(testListener.getEventCount()).isEqualTo(expectedEventCount);
        assertThat(testLogger.getMessageCount()).isEqualTo(expectedEventCount);
    }

    private void assertThatNumberOfAuditEventsReceivedIsGreaterThanOrEqualTo(int expectedEventCount) {
        assertThat(testListener.getEventCount()).isGreaterThanOrEqualTo(expectedEventCount);
        assertThat(testLogger.getMessageCount()).isGreaterThanOrEqualTo(expectedEventCount);
    }

    private void assertSingleAuditEventFiredWith(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        assertSingleClientAdminAuditEventFiredWith(expectedEventType, expectedScopes, expectedAuthorities);
        assertSingleAuditEventLogMessage(expectedEventType, expectedScopes, expectedAuthorities);
    }

    private void assertSingleClientAdminAuditEventFiredWith(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        List<AbstractUaaEvent> events = testListener.getEvents().stream().filter(AbstractClientAdminEvent.class::isInstance).toList();
        assertThat(events).hasSize(1);

        AbstractUaaEvent event = events.getFirst();
        assertThat(event.getAuditEvent().getType()).isEqualTo(expectedEventType);

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, atLeast(1)).log(captor.capture(), anyString());

        List<AuditEvent> auditEvents = captor.getAllValues().stream().filter(e -> e.getType() == expectedEventType).toList();
        assertThat(auditEvents).hasSize(1);

        AuditEvent auditEvent = auditEvents.getFirst();
        String auditEventData = auditEvent.getData();
        assertThat(auditEventData).isNotNull();

        Map<String, Object> map = JsonUtils.readValue(auditEventData, new TypeReference<Map<String, Object>>() {
        });
        List<String> auditScopes = (List<String>) map.get("scopes");
        List<String> auditAuthorities = (List<String>) map.get("authorities");

        assertThat(auditScopes).containsExactlyInAnyOrder(expectedScopes);
        assertThat(auditAuthorities).containsExactlyInAnyOrder(expectedAuthorities);
    }

    private void assertSingleAuditEventLogMessage(AuditEventType expectedEventType, String[] expectedScopes, String[] expectedAuthorities) {
        assertThat(testLogger.getMessageCount()).isOne();

        String message = testLogger.getLatestMessage();
        assertThat(message).startsWith(expectedEventType.toString());
        String commaSeparatedQuotedScopes = Arrays.stream(expectedScopes).map(s -> "\"" + s + "\"").collect(joining(","));
        assertThat(message).contains("\"scopes\":[%s]".formatted(commaSeparatedQuotedScopes));

        String commaSeparatedQuotedAuthorities = Arrays.stream(expectedAuthorities).map(s -> "\"" + s + "\"").collect(joining(","));
        assertThat(message).contains("\"authorities\":[%s]".formatted(commaSeparatedQuotedAuthorities));
    }

    private void assertLogMessageWithSession(String actualLogMessage, AuditEventType expectedAuditEventType, String expectedPrincipal, String expectedUserName) {
        assertThat(actualLogMessage).startsWith(expectedAuditEventType.toString() + " ")
                .contains("principal=%s,".formatted(expectedPrincipal))
                .contains(" ('%s'): ".formatted(expectedUserName))
                .contains(", identityZoneId=[uaa]")
                .matches(".*origin=\\[.*sessionId=<SESSION>.*\\].*");
    }

    private static void assertLogMessageWithoutSession(String actualLogMessage, AuditEventType expectedAuditEventType, String expectedPrincipal, String expectedUserName) {
        assertThat(actualLogMessage).startsWith(expectedAuditEventType.toString() + " ")
                .contains("principal=%s,".formatted(expectedPrincipal))
                .contains(" ('%s'): ".formatted(expectedUserName))
                .contains(", identityZoneId=[uaa]")
                .doesNotContain("sessionId");
    }

    private static void assertGroupMembershipLogMessage(String actualLogMessage, AuditEventType expectedEventType, String expectedGroupDisplayName, String expectedGroupId, String... expectedUserIds) {
        assertThat(actualLogMessage).startsWith(expectedEventType.toString() + " ")
                .contains("principal=%s,".formatted(expectedGroupId))
                .doesNotContain("sessionId");

        Pattern groupLogPattern = Pattern.compile(" \\('\\{\"group_name\":\"" + Pattern.quote(expectedGroupDisplayName) + "\",\"members\":\\[(.*?)]}'\\): ");
        Matcher patternMatcher = groupLogPattern.matcher(actualLogMessage);
        assertThat(patternMatcher.find()).isTrue();
        Set<String> memberIdsFromLogMessage = StringUtils.commaDelimitedListToSet(patternMatcher.group(1).replaceAll("\"", ""));
        assertThat(memberIdsFromLogMessage).isEqualTo(Sets.newHashSet(expectedUserIds));
    }
}
