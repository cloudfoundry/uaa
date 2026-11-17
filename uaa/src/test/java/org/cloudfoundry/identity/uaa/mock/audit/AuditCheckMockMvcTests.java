package org.cloudfoundry.identity.uaa.mock.audit;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
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
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.services.ScimGroupMembershipService;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import tools.jackson.core.type.TypeReference;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.*;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
    @Autowired
    private TransactionTemplate transactionTemplate;
    @MockitoSpyBean
    private ScimEventPublisher scimEventPublisher;
    @Autowired
    private ScimGroupMembershipService groupMembershipService;
    @MockitoSpyBean
    private ScimGroupEndpoints groupEndpoints;
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

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userEvent.getUser().getId()).isEqualTo(passwordEvent.getUser().getId());
        assertThat(userEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(passwordEvent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessage(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessage(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/authenticate", "/authenticate/"})
    void userLoginAuthenticateEndpointTest(String url) throws Exception {
        MockHttpServletRequestBuilder loginPost = post(url)
                .accept(APPLICATION_JSON_VALUE)
                .session(new MockHttpSession())
                .param("username", testUser.getUserName())
                .param("password", testPassword);

        MvcResult loginResult = mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andReturn();
        assertThat(loginResult.getResponse().getContentAsString())
                .contains(
                        "\"username\":\"" + testUser.getUserName(),
                        "\"email\":\"" + testUser.getPrimaryEmail());

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

        IdentityProviderAuthenticationSuccessEvent passwordEvent = testListener.getLatestEventOfType(IdentityProviderAuthenticationSuccessEvent.class);
        assertThat(passwordEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());

        UserAuthenticationSuccessEvent userEvent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userEvent.getUser().getId()).isEqualTo(passwordEvent.getUser().getId());
        assertThat(userEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());
        assertThat(passwordEvent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessage(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessage(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());
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

        UserAuthenticationFailureEvent userAuthFailEvent = (UserAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertThat(userAuthFailEvent.getUser().getUsername()).isEqualTo(testUser.getUserName());

        PrincipalAuthenticationFailureEvent principalAuthFailEvent = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(2);
        assertThat(principalAuthFailEvent.getName()).isEqualTo(testUser.getUserName());

        String idpAuthFailMsg = testLogger.getMessageAtIndex(0);
        assertLogMessage(idpAuthFailMsg, IdentityProviderAuthenticationFailure, "null", testUser.getUserName());

        String userAuthFailMsg = testLogger.getMessageAtIndex(1);
        assertLogMessage(userAuthFailMsg, UserAuthenticationFailure, testUser.getId(), testUser.getUserName());

        String principalAuthFailMsg = testLogger.getMessageAtIndex(2);
        assertLogMessage(principalAuthFailMsg, PrincipalAuthenticationFailure, testUser.getUserName(), "null");
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

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessage(userAuthLogMsg, UserAuthenticationSuccess, molly.getId(), molly.getUserName());
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

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UnverifiedUserAuthentication);
        assertLogMessage(userAuthLogMsg, UnverifiedUserAuthentication, molly.getId(), molly.getUserName());
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

        String userAuthLogMsg = testLogger.getFirstLogMessageOfType(UnverifiedUserAuthentication);
        assertLogMessage(userAuthLogMsg, UnverifiedUserAuthentication, molly.getId(), molly.getUserName());
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

        String idpAuthLogMsg = testLogger.getMessageAtIndex(0);
        assertLogMessage(idpAuthLogMsg, IdentityProviderAuthenticationFailure, "null", testUser.getUserName());

        String userAuthLogMsg = testLogger.getMessageAtIndex(1);
        assertLogMessage(userAuthLogMsg, UserAuthenticationFailure, testUser.getId(), testUser.getUserName());

        String principalAuthLogMsg = testLogger.getMessageAtIndex(2);
        assertLogMessage(principalAuthLogMsg, PrincipalAuthenticationFailure, testUser.getUserName(), "null");
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
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent) testListener.getEvents().get(1);
        assertThat(((Authentication) event1.getSource()).getName()).isEqualTo(username);
        assertThat(event2.getName()).isEqualTo(username);

        String encodedUsername = Utf8.decode(Base64.getEncoder().encode(MessageDigest.getInstance("SHA-1").digest(Utf8.encode(username))));
        assertLogMessage(testLogger.getMessageAtIndex(0), UserNotFound, encodedUsername, "");
        assertLogMessage(testLogger.getMessageAtIndex(1), PrincipalAuthenticationFailure, username, "null");
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
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userevent.getUser().getId()).isEqualTo(passwordevent.getUser().getId());
        assertThat(passwordevent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessage(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessage(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

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
        assertThat(pw.getAuditEvent().getPrincipalName()).isEqualTo(testUser.getUserName());

        String pwLogMsg = testLogger.getLatestMessage();
        assertLogMessage(pwLogMsg, PasswordChangeSuccess, testUser.getId(), "Password changed");
        assertThat(pwLogMsg).contains("principalName=[%s]".formatted(testUser.getUserName()));
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
        UserAuthenticationSuccessEvent userevent = testListener.getLatestEventOfType(UserAuthenticationSuccessEvent.class);
        assertThat(userevent.getUser().getId()).isEqualTo(passwordevent.getUser().getId());
        assertThat(passwordevent.getAuthenticationType()).isEqualTo(OriginKeys.UAA);

        String passwordLogMsg = testLogger.getFirstLogMessageOfType(IdentityProviderAuthenticationSuccess);
        assertLogMessage(passwordLogMsg, IdentityProviderAuthenticationSuccess, testUser.getId(), testUser.getUserName());

        String userEventLogMsg = testLogger.getFirstLogMessageOfType(UserAuthenticationSuccess);
        assertLogMessage(userEventLogMsg, UserAuthenticationSuccess, testUser.getId(), testUser.getUserName());

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
        assertThat(pwfe.getAuditEvent().getPrincipalName()).isEqualTo(testUser.getUserName());

        String pwfeLogMsg = testLogger.getLatestMessage();
        assertLogMessage(pwfeLogMsg, PasswordChangeFailure, testUser.getId(), "Old password is incorrect");
        assertThat(pwfeLogMsg).contains("principalName=[%s]".formatted(testUser.getUserName()));
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
        assertThat(pw.getAuditEvent().getPrincipalName()).isEqualTo(user.getUserName());

        String pwLogMsg = testLogger.getLatestMessage();
        assertLogMessage(pwLogMsg, PasswordChangeSuccess, user.getId(), "Password changed");
        assertThat(pwLogMsg).contains("principalName=[%s]".formatted(user.getUserName()));
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
        assertThat(pce.getAuditEvent().getPrincipalName()).isEqualTo(testUser.getUserName());

        String pceLogMsg = testLogger.getLatestMessage();
        assertLogMessage(pceLogMsg, PasswordChangeSuccess, testUser.getId(), "Password changed");
        assertThat(pceLogMsg).contains("principalName=[%s]".formatted(testUser.getUserName()));
    }

    @Test
    void clientAuthenticationSuccess() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.getEncoder().encode("login:loginsecret".getBytes()));
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

        assertLogMessage(testLogger.getMessageAtIndex(0), ClientAuthenticationSuccess, "login", "Client authentication success");
    }

    @Test
    void clientAuthenticationFailure() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.getEncoder().encode("login:loginsecretwrong".getBytes()));
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

        assertLogMessage(testLogger.getLatestMessage(), ClientAuthenticationFailure, "login", "Bad credentials");
    }

    @Test
    void clientAuthenticationFailureClientNotFound() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.getEncoder().encode("login2:loginsecret".getBytes()));
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

        assertLogMessage(testLogger.getMessageAtIndex(0), PrincipalAuthenticationFailure, "login2", "null");
        assertLogMessage(testLogger.getMessageAtIndex(1), ClientAuthenticationFailure, "login", "Bad credentials");
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

        String latestMessage = testLogger.getLatestMessage();
        assertThat(latestMessage).contains(" user=" + testUser.getUserName());
        assertLogMessage(latestMessage, ApprovalModifiedEvent, testUser.getId(), "{\"scope\":\"cloud_controller.read\",\"status\":\"APPROVED\"}");
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

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(scimUser.getUserName())).findFirst().get();
        String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                createdUser.getId(),
                scimUser.getUserName());
        assertLogMessage(testLogger.getLatestMessage(),
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
        void membershipEventsUseRequestZoneAndActor() throws Exception {
            ScimGroup group = JsonUtils.readValue(mockMvc.perform(post("/Groups")
                            .headers(zoneSeeder.getZoneSubdomainRequestHeader()).with(httpBearer(scimWriteUserToken))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsBytes(new ScimGroup("zone-membership-" + generator.generate()))))
                    .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString(), ScimGroup.class);
            resetAuditTestReceivers();
            mockMvc.perform(post("/Groups/" + group.getId() + "/members")
                            .headers(zoneSeeder.getZoneSubdomainRequestHeader()).with(httpBearer(scimWriteUserToken))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsBytes(new ScimGroupMember(scimWriteUser.getId()))))
                    .andExpect(status().isCreated());

            List<AuditEvent> events = capturedAuditEvents();
            assertThat(events).extracting(AuditEvent::getType).containsExactly(GroupMembershipAddedEvent, GroupModifiedEvent);
            assertLegacyGroupSnapshot(events.getLast(), group, scimWriteUser.getId());
            assertThat(events.getLast().getIdentityZoneId()).isEqualTo(zoneSeeder.getIdentityZoneId());
            assertThat(events.getLast().getOrigin()).contains("client=" + adminClient.getClientId());
            AuditEvent event = events.getFirst();
            assertThat(event.getPrincipalId()).isEqualTo(group.getId());
            assertThat(event.getIdentityZoneId()).isEqualTo(zoneSeeder.getIdentityZoneId()).isNotEqualTo("uaa");
            assertThat(event.getOrigin()).contains("client=" + adminClient.getClientId());
            assertThat(JsonUtils.readValueAsMap(event.getData())).containsEntry("member_name", scimWriteUser.getUserName())
                    .containsEntry("member_id", scimWriteUser.getId());

            resetAuditTestReceivers();
            mockMvc.perform(delete("/Groups/" + group.getId() + "/members/" + scimWriteUser.getId())
                            .headers(zoneSeeder.getZoneSubdomainRequestHeader()).with(httpBearer(scimWriteUserToken)))
                    .andExpect(status().isOk());
            events = capturedAuditEvents();
            assertThat(events).extracting(AuditEvent::getType).containsExactly(GroupMembershipRemovedEvent, GroupModifiedEvent);
            assertLegacyGroupSnapshot(events.getLast(), group);
            assertThat(events).allSatisfy(audit -> {
                assertThat(audit.getIdentityZoneId()).isEqualTo(zoneSeeder.getIdentityZoneId());
                assertThat(audit.getOrigin()).contains("client=" + adminClient.getClientId());
            });
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
                    .contains(", identityZoneId=[%s]".formatted(zoneSeeder.getIdentityZoneId()));
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
                    .contains(", identityZoneId=[%s]".formatted(zoneSeeder.getIdentityZoneId()));
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

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(identityZoneManager.getCurrentIdentityZoneId())
                .stream().filter(dbUser -> dbUser.getUserName().equals(username)).findFirst().get();

        String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                createdUser.getId(),
                username);

        assertLogMessage(testLogger.getMessageAtIndex(0),
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

            String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(scimUser.getId(), scimUser.getUserName());
            assertLogMessage(testLogger.getLatestMessage(),
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

            String logMessage = "[\"user_id=%s\",\"username=%s\"]".formatted(
                    scimUser.getId(),
                    scimUser.getUserName());
            assertLogMessage(testLogger.getLatestMessage(),
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

        assertLogMessage(testLogger.getLatestMessage(),
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

        assertLogMessage(testLogger.getLatestMessage(),
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

        assertThatNumberOfAuditEventsReceivedIsEqualTo(2);

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

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void membershipChangesPrecedeUnchangedGroupModifiedEvent(String method) throws Exception {
        ScimUser added = createUser(adminToken, "added", "Added", "User", "added@example.com", testPassword, true);
        ScimUser retained = createUser(adminToken, "retained", "Retained", "User", "retained@example.com", testPassword, true);
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(testUser.getId()),
                new ScimGroupMember(retained.getId())));
        ScimGroup update = new ScimGroup(group.getId(), group.getDisplayName(), identityZoneManager.getCurrentIdentityZoneId());
        if ("PATCH".equals(method)) {
            ScimGroupMember removed = new ScimGroupMember(testUser.getId());
            removed.setOperation("delete");
            update.setMembers(List.of(removed, new ScimGroupMember(added.getId())));
        } else {
            update.setMembers(List.of(new ScimGroupMember(retained.getId()), new ScimGroupMember(added.getId())));
        }
        resetAuditTestReceivers();

        MockHttpServletRequestBuilder request = "PATCH".equals(method)
                ? patch("/Groups/" + group.getId()) : put("/Groups/" + group.getId());
        mockMvc.perform(request.header(AUTHORIZATION, "Bearer " + adminToken)
                        .header("If-Match", "*").contentType(MediaType.APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(update)))
                .andExpect(status().isOk());

        List<AuditEvent> events = capturedAuditEvents();
        assertThat(events).extracting(AuditEvent::getType)
                .containsExactly(GroupMembershipRemovedEvent, GroupMembershipAddedEvent, GroupModifiedEvent);
        assertMembershipAudit(events.get(0), group, testUser.getId(), testUser.getUserName(), "USER");
        assertMembershipAudit(events.get(1), group, added.getId(), added.getUserName(), "USER");
        Map<String, Object> snapshot = JsonUtils.readValueAsMap(events.get(2).getData());
        assertThat(snapshot).containsOnlyKeys("group_name", "members").containsEntry("group_name", group.getDisplayName());
        assertThat((List<String>) snapshot.get("members")).containsExactlyInAnyOrder(retained.getId(), added.getId());
        assertThat(testLogger.getMessageAtIndex(0)).startsWith("GroupMembershipRemovedEvent ").contains(testUser.getUserName());
        assertThat(testLogger.getMessageAtIndex(1)).startsWith("GroupMembershipAddedEvent ").contains(added.getUserName());
        assertThat(testLogger.getLatestMessage()).startsWith("GroupModifiedEvent ");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PUT", "PATCH"})
    void metadataOnlyUpdateAndRemoveAllMembers(String method) throws Exception {
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(testUser.getId())));
        ScimGroup metadata = "PATCH".equals(method) ? new ScimGroup() : group;
        metadata.setDescription("Only the description changed");
        resetAuditTestReceivers();
        MockHttpServletRequestBuilder metadataRequest = "PATCH".equals(method)
                ? patch("/Groups/" + group.getId()) : put("/Groups/" + group.getId());
        mockMvc.perform(metadataRequest.header(AUTHORIZATION, "Bearer " + adminToken)
                        .header("If-Match", "*").contentType(MediaType.APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(metadata)))
                .andExpect(status().isOk());
        assertThat(capturedAuditEvents()).extracting(AuditEvent::getType).containsExactly(GroupModifiedEvent);

        if ("PATCH".equals(method)) {
            ScimGroupMember removed = new ScimGroupMember(testUser.getId());
            removed.setOperation("delete");
            group.setMembers(List.of(removed));
        } else {
            group.setMembers(List.of());
        }
        resetAuditTestReceivers();
        MockHttpServletRequestBuilder removalRequest = "PATCH".equals(method)
                ? patch("/Groups/" + group.getId()) : put("/Groups/" + group.getId());
        mockMvc.perform(removalRequest.header(AUTHORIZATION, "Bearer " + adminToken)
                        .header("If-Match", "*").contentType(MediaType.APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(group)))
                .andExpect(status().isOk());
        List<AuditEvent> events = capturedAuditEvents();
        assertThat(events).extracting(AuditEvent::getType).containsExactly(GroupMembershipRemovedEvent, GroupModifiedEvent);
        assertMembershipAudit(events.getFirst(), group, testUser.getId(), testUser.getUserName(), "USER");
        assertThat((List<?>) JsonUtils.readValueAsMap(events.getLast().getData()).get("members")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"USER", "GROUP"})
    void singleMemberEndpointsEmitDedicatedEventsAndFinalSnapshot(String memberType) throws Exception {
        ScimUser retained = createUser(adminToken, "retained", "Retained", "User", "retained@example.com", testPassword, true);
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(retained.getId())));
        ScimGroupMember member;
        String memberName;
        if ("GROUP".equals(memberType)) {
            ScimGroup nested = createMembershipAuditGroup(List.of());
            member = new ScimGroupMember(nested.getId(), ScimGroupMember.Type.GROUP);
            memberName = nested.getDisplayName();
        } else {
            member = new ScimGroupMember();
            member.setMemberId(testUser.getId());
            memberName = testUser.getUserName();
        }
        String path = "/Groups/" + group.getId() + "/members";
        resetAuditTestReceivers();
        mockMvc.perform(post(path).header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content(JsonUtils.writeValueAsBytes(member)))
                .andExpect(status().isCreated());
        List<AuditEvent> events = capturedAuditEvents();
        assertThat(events).extracting(AuditEvent::getType).containsExactly(GroupMembershipAddedEvent, GroupModifiedEvent);
        assertMembershipAudit(events.getFirst(), group, member.getMemberId(), memberName, memberType);
        assertLegacyGroupSnapshot(events.getLast(), group, retained.getId(), member.getMemberId());
        assertThat(testLogger.getMessageAtIndex(0)).startsWith("GroupMembershipAddedEvent ");
        assertThat(testLogger.getMessageAtIndex(1)).startsWith("GroupModifiedEvent ");

        resetAuditTestReceivers();
        mockMvc.perform(post(path).header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content(JsonUtils.writeValueAsBytes(member)))
                .andExpect(status().isConflict());
        assertThatNumberOfAuditEventsReceivedIsEqualTo(0);

        resetAuditTestReceivers();
        mockMvc.perform(delete(path + "/" + member.getMemberId()).header(AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk());
        events = capturedAuditEvents();
        assertThat(events).extracting(AuditEvent::getType).containsExactly(GroupMembershipRemovedEvent, GroupModifiedEvent);
        assertMembershipAudit(events.getFirst(), group, member.getMemberId(), memberName, memberType);
        assertLegacyGroupSnapshot(events.getLast(), group, retained.getId());
        assertThat(testLogger.getMessageAtIndex(0)).startsWith("GroupMembershipRemovedEvent ");
        assertThat(testLogger.getMessageAtIndex(1)).startsWith("GroupModifiedEvent ");

        resetAuditTestReceivers();
        mockMvc.perform(delete(path + "/" + member.getMemberId()).header(AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isNotFound());
        assertThatNumberOfAuditEventsReceivedIsEqualTo(0);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void failedGroupUpdateDoesNotEmitMembershipSuccessEvents(boolean staleVersion) throws Exception {
        ScimUser added = createUser(adminToken, "valid", "Valid", "User", "valid@example.com", testPassword, true);
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(testUser.getId())));
        String originalName = group.getDisplayName();
        String originalDescription = group.getDescription();
        int originalVersion = group.getVersion();
        var originalCreated = group.getMeta().getCreated();
        var originalModified = group.getMeta().getLastModified();
        group.setDisplayName("changed-" + generator.generate());
        group.setDescription("Must roll back");
        group.setMembers(List.of(new ScimGroupMember(added.getId()),
                new ScimGroupMember("missing-member-" + generator.generate())));
        resetAuditTestReceivers();
        ResultActions result = mockMvc.perform(put("/Groups/" + group.getId()).header(AUTHORIZATION, "Bearer " + adminToken)
                        .header("If-Match", staleVersion ? "-1" : "*").contentType(MediaType.APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(group)));
        if (staleVersion) {
            result.andExpect(status().isConflict());
        } else {
            result.andExpect(status().isBadRequest());
        }
        assertThatNumberOfAuditEventsReceivedIsEqualTo(0);
        ScimGroup persisted = JsonUtils.readValue(mockMvc.perform(get("/Groups/" + group.getId())
                        .header(AUTHORIZATION, "Bearer " + adminToken)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), ScimGroup.class);
        assertThat(persisted.getMembers()).extracting(ScimGroupMember::getMemberId).containsExactly(testUser.getId());
        assertThat(persisted.getDisplayName()).isEqualTo(originalName);
        assertThat(persisted.getDescription()).isEqualTo(originalDescription);
        assertThat(persisted.getVersion()).isEqualTo(originalVersion);
        assertThat(persisted.getMeta().getCreated()).isEqualTo(originalCreated);
        assertThat(persisted.getMeta().getLastModified()).isEqualTo(originalModified);
    }

    @Test
    void groupLockRequiresCurrentZoneAndReleasesAfterFailure() throws Exception {
        ScimGroup group = createMembershipAuditGroup(List.of());
        assertThatThrownBy(() -> groupMembershipService.withLock(group.getId(), "wrong-zone", () -> {
            throw new AssertionError("Wrong zone must not enter membership operation");
        })).isInstanceOf(ScimResourceNotFoundException.class);
        assertThatThrownBy(() -> groupMembershipService.withLock(group.getId(),
                identityZoneManager.getCurrentIdentityZoneId(), () -> {
                    throw new IllegalStateException("Operation failed");
                })).isInstanceOf(IllegalStateException.class);
        assertThat(groupMembershipService.withLock(group.getId(), identityZoneManager.getCurrentIdentityZoneId(),
                () -> "lock released")).isEqualTo("lock released");
    }

    @Test
    void membershipUpdateRejectsRepeatableReadBeforeCallbackOrWrites() throws Exception {
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(testUser.getId())));
        var outer = new TransactionTemplate(transactionTemplate.getTransactionManager());
        outer.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        resetAuditTestReceivers();
        assertThatThrownBy(() -> outer.executeWithoutResult(_ ->
                groupMembershipService.withLock(group.getId(), identityZoneManager.getCurrentIdentityZoneId(), () -> {
                    throw new AssertionError("Unsupported isolation must reject before the write callback");
                })))
                .isInstanceOf(IllegalTransactionStateException.class)
                .hasMessageContaining("READ_COMMITTED");
        assertThat(capturedAuditEvents()).isEmpty();
        ScimGroup persisted = JsonUtils.readValue(mockMvc.perform(get("/Groups/" + group.getId())
                        .header(AUTHORIZATION, "Bearer " + adminToken)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), ScimGroup.class);
        assertThat(persisted.getDisplayName()).isEqualTo(group.getDisplayName());
        assertThat(persisted.getVersion()).isEqualTo(group.getVersion());
        assertThat(persisted.getMembers()).extracting(ScimGroupMember::getMemberId).containsExactly(testUser.getId());
    }

    @ParameterizedTest
    @CsvSource({"PUT,true", "PUT,false", "PATCH,true", "PATCH,false", "POST,true", "POST,false", "DELETE,true", "DELETE,false"})
    void membershipEventsWaitForOuterTransactionAndRespectRollback(String method, boolean rollback) throws Exception {
        boolean removing = "DELETE".equals(method);
        boolean bulk = "PUT".equals(method) || "PATCH".equals(method);
        ScimGroup group = createMembershipAuditGroup(removing ? List.of(new ScimGroupMember(testUser.getId())) : List.of());
        ScimGroup update = new ScimGroup(group.getId(), group.getDisplayName(), identityZoneManager.getCurrentIdentityZoneId());
        update.setDescription("Committed bulk metadata");
        update.setMembers(List.of(new ScimGroupMember(testUser.getId())));
        var outer = new TransactionTemplate(transactionTemplate.getTransactionManager());
        outer.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        resetAuditTestReceivers();
        outer.executeWithoutResult(transaction -> {
            try {
                String path = "/Groups/" + group.getId();
                MockHttpServletRequestBuilder request = switch (method) {
                    case "PUT" -> put(path).header("If-Match", "*").content(JsonUtils.writeValueAsBytes(update));
                    case "PATCH" -> patch(path).header("If-Match", "*").content(JsonUtils.writeValueAsBytes(update));
                    case "POST" -> post(path + "/members").content(JsonUtils.writeValueAsBytes(new ScimGroupMember(testUser.getId())));
                    case "DELETE" -> delete(path + "/members/" + testUser.getId());
                    default -> throw new IllegalArgumentException(method);
                };
                mockMvc.perform(request.header(AUTHORIZATION, "Bearer " + adminToken).contentType(MediaType.APPLICATION_JSON))
                        .andExpect("POST".equals(method) ? status().isCreated() : status().isOk());
            } catch (Exception e) {
                throw new AssertionError(e);
            }
            assertThat(capturedAuditEvents()).isEmpty();
            if (rollback) {
                transaction.setRollbackOnly();
            }
        });
        String[] expectedMembers = rollback == removing ? new String[]{testUser.getId()} : new String[0];
        if (rollback) {
            assertThat(capturedAuditEvents()).isEmpty();
        } else {
            List<AuditEvent> events = capturedAuditEvents();
            assertThat(events).extracting(AuditEvent::getType)
                    .containsExactly(removing ? GroupMembershipRemovedEvent : GroupMembershipAddedEvent, GroupModifiedEvent);
            assertMembershipAudit(events.getFirst(), group, testUser.getId(), testUser.getUserName(), "USER");
            assertLegacyGroupSnapshot(events.getLast(), group, expectedMembers);
        }
        ScimGroup persisted = JsonUtils.readValue(mockMvc.perform(get("/Groups/" + group.getId())
                        .header(AUTHORIZATION, "Bearer " + adminToken)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), ScimGroup.class);
        assertThat(persisted.getMembers()).extracting(ScimGroupMember::getMemberId).containsExactly(expectedMembers);
        assertThat(persisted.getDescription()).isEqualTo(bulk && !rollback ? update.getDescription() : group.getDescription());
        assertThat(persisted.getDisplayName()).isEqualTo(group.getDisplayName());
        assertThat(persisted.getVersion()).isEqualTo(group.getVersion() + (bulk && !rollback ? 1 : 0));
        assertThat(persisted.getMeta().getCreated()).isEqualTo(group.getMeta().getCreated());
        if (!bulk || rollback) {
            assertThat(persisted.getMeta().getLastModified()).isEqualTo(group.getMeta().getLastModified());
        }
    }

    @ParameterizedTest
    @CsvSource({"PUT,POST", "PATCH,POST", "PUT,DELETE", "PATCH,DELETE"})
    void concurrentBulkAndSingleMembershipChangesSerialize(String bulkMethod, String singleMethod) throws Exception {
        ScimUser other = createUser(adminToken, "other", "Other", "User", "other@example.com", testPassword, true);
        boolean adding = "POST".equals(singleMethod);
        ScimGroup group = createMembershipAuditGroup(adding
                ? List.of(new ScimGroupMember(testUser.getId()))
                : List.of(new ScimGroupMember(testUser.getId()), new ScimGroupMember(other.getId())));
        ScimGroup update = new ScimGroup(group.getId(), group.getDisplayName(), identityZoneManager.getCurrentIdentityZoneId());
        if ("PATCH".equals(bulkMethod)) {
            ScimGroupMember removed = new ScimGroupMember(testUser.getId());
            removed.setOperation("delete");
            update.setMembers(List.of(removed));
        } else {
            update.setMembers(adding ? List.of() : List.of(new ScimGroupMember(other.getId())));
        }
        CountDownLatch bulkSnapshot = new CountDownLatch(1);
        CountDownLatch releaseBulk = new CountDownLatch(1);
        CountDownLatch singleRequestEntered = new CountDownLatch(1);
        CountDownLatch singleSnapshot = new CountDownLatch(1);
        Map<String, List<AuditEvent>> byOperation = new ConcurrentHashMap<>();
        ApplicationListener<AbstractUaaEvent> listener = event -> {
            String operation = Thread.currentThread().getName();
            if (operation.equals("membership-bulk") || operation.equals("membership-single")) {
                byOperation.computeIfAbsent(operation, _ -> new ArrayList<>()).add(event.getAuditEvent());
            }
        };
        MockMvcUtils.removeEventListener(configurableApplicationContext, testListener);
        configurableApplicationContext.addApplicationListener(listener);
        doAnswer(invocation -> {
            Object prepared = invocation.callRealMethod();
            bulkSnapshot.countDown();
            await().atMost(10, TimeUnit.SECONDS).until(() -> releaseBulk.getCount() == 0);
            return prepared;
        }).when(scimEventPublisher).prepareMembershipChanges(any(), any());
        if (adding) {
            doAnswer(invocation -> {
                singleRequestEntered.countDown();
                return invocation.callRealMethod();
            }).when(AopTestUtils.<ScimGroupEndpoints>getUltimateTargetObject(groupEndpoints)).addMemberToGroup(eq(group.getId()), any());
        } else {
            doAnswer(invocation -> {
                singleRequestEntered.countDown();
                return invocation.callRealMethod();
            }).when(AopTestUtils.<ScimGroupEndpoints>getUltimateTargetObject(groupEndpoints)).deleteGroupMembership(eq(group.getId()), anyString());
        }
        doAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("membership-single")) {
                singleSnapshot.countDown();
            }
            return invocation.callRealMethod();
        }).when(scimEventPublisher).prepareMembershipEvent(any(), any(), any());
        var workers = Executors.newFixedThreadPool(2);
        try {
            var bulk = workers.submit(() -> {
                Thread.currentThread().setName("membership-bulk");
                MockHttpServletRequestBuilder request = "PATCH".equals(bulkMethod)
                        ? patch("/Groups/" + group.getId()) : put("/Groups/" + group.getId());
                return mockMvc.perform(request.header(AUTHORIZATION, "Bearer " + adminToken)
                                .header("If-Match", "*").contentType(MediaType.APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsBytes(update)))
                        .andExpect(status().isOk()).andReturn();
            });
            await().atMost(10, TimeUnit.SECONDS).until(() -> bulkSnapshot.getCount() == 0);
            var single = workers.submit(() -> {
                Thread.currentThread().setName("membership-single");
                String path = "/Groups/" + group.getId() + "/members";
                MockHttpServletRequestBuilder request = adding
                        ? post(path).contentType(MediaType.APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsBytes(new ScimGroupMember(other.getId())))
                        : delete(path + "/" + other.getId());
                return mockMvc.perform(request.header(AUTHORIZATION, "Bearer " + adminToken))
                        .andExpect(adding ? status().isCreated() : status().isOk()).andReturn();
            });
            await().atMost(10, TimeUnit.SECONDS).until(() -> singleRequestEntered.getCount() == 0);
            // The contender has entered its endpoint, but must not read its audit snapshot or finish.
            await().during(300, TimeUnit.MILLISECONDS).atMost(2, TimeUnit.SECONDS).untilAsserted(() -> {
                assertThat(singleSnapshot.getCount()).isOne();
                assertThat(single.isDone()).isFalse();
            });
            releaseBulk.countDown();
            await().atMost(10, TimeUnit.SECONDS).until(bulk::isDone);
            bulk.get();
            await().atMost(10, TimeUnit.SECONDS).until(single::isDone);
            single.get();
            assertThat(singleSnapshot.getCount()).isZero();
            List<AuditEvent> bulkEvents = byOperation.get("membership-bulk");
            List<AuditEvent> singleEvents = byOperation.get("membership-single");
            assertThat(bulkEvents).extracting(AuditEvent::getType)
                    .containsExactly(GroupMembershipRemovedEvent, GroupModifiedEvent);
            assertThat(singleEvents).extracting(AuditEvent::getType)
                    .containsExactly(adding ? GroupMembershipAddedEvent : GroupMembershipRemovedEvent, GroupModifiedEvent);
            assertMembershipAudit(bulkEvents.getFirst(), group, testUser.getId(), testUser.getUserName(), "USER");
            assertMembershipAudit(singleEvents.getFirst(), group, other.getId(), other.getUserName(), "USER");
            assertLegacyGroupSnapshot(bulkEvents.getLast(), group, adding ? new String[0] : new String[]{other.getId()});
            assertLegacyGroupSnapshot(singleEvents.getLast(), group, adding ? new String[]{other.getId()} : new String[0]);
            ScimGroup persisted = JsonUtils.readValue(mockMvc.perform(get("/Groups/" + group.getId())
                            .header(AUTHORIZATION, "Bearer " + adminToken)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(), ScimGroup.class);
            assertThat(persisted.getMembers()).extracting(ScimGroupMember::getMemberId)
                    .containsExactly(adding ? new String[]{other.getId()} : new String[0]);
        } finally {
            releaseBulk.countDown();
            workers.shutdownNow();
            await().atMost(15, TimeUnit.SECONDS).until(workers::isTerminated);
            MockMvcUtils.removeEventListener(configurableApplicationContext, listener);
        }
    }

    @Test
    void patchWaitsForSingleMemberInsertBeforeReadingAndMerging() throws Exception {
        ScimUser added = createUser(adminToken, "added", "Added", "User", "added@example.com", testPassword, true);
        ScimGroup group = createMembershipAuditGroup(List.of(new ScimGroupMember(testUser.getId())));
        ScimGroup update = new ScimGroup();
        ScimGroupMember removed = new ScimGroupMember(testUser.getId());
        removed.setOperation("delete");
        update.setMembers(List.of(removed));
        CountDownLatch insertReady = new CountDownLatch(1);
        CountDownLatch releaseInsert = new CountDownLatch(1);
        CountDownLatch patchRequestEntered = new CountDownLatch(1);
        CountDownLatch patchSnapshot = new CountDownLatch(1);
        Map<String, List<AuditEvent>> byOperation = new ConcurrentHashMap<>();
        ApplicationListener<AbstractUaaEvent> listener = event -> {
            String operation = Thread.currentThread().getName();
            if (operation.equals("membership-post-first") || operation.equals("membership-patch-second")) {
                byOperation.computeIfAbsent(operation, _ -> new ArrayList<>()).add(event.getAuditEvent());
            }
        };
        MockMvcUtils.removeEventListener(configurableApplicationContext, testListener);
        configurableApplicationContext.addApplicationListener(listener);
        doAnswer(invocation -> {
            Object prepared = invocation.callRealMethod();
            if (Thread.currentThread().getName().equals("membership-post-first")) {
                insertReady.countDown();
                await().atMost(10, TimeUnit.SECONDS).until(() -> releaseInsert.getCount() == 0);
            }
            return prepared;
        }).when(scimEventPublisher).prepareMembershipEvent(any(), any(), any());
        doAnswer(invocation -> {
            patchRequestEntered.countDown();
            return invocation.callRealMethod();
        }).when(AopTestUtils.<ScimGroupEndpoints>getUltimateTargetObject(groupEndpoints)).patchGroup(any(), eq(group.getId()), anyString(), any());
        doAnswer(invocation -> {
            patchSnapshot.countDown();
            return invocation.callRealMethod();
        }).when(scimEventPublisher).prepareMembershipChanges(any(), any());
        var workers = Executors.newFixedThreadPool(2);
        try {
            var postResult = workers.submit(() -> {
                Thread.currentThread().setName("membership-post-first");
                return mockMvc.perform(post("/Groups/" + group.getId() + "/members")
                                .header(AUTHORIZATION, "Bearer " + adminToken).contentType(MediaType.APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsBytes(new ScimGroupMember(added.getId()))))
                        .andExpect(status().isCreated()).andReturn();
            });
            await().atMost(10, TimeUnit.SECONDS).until(() -> insertReady.getCount() == 0);
            var patchResult = workers.submit(() -> {
                Thread.currentThread().setName("membership-patch-second");
                return mockMvc.perform(patch("/Groups/" + group.getId())
                                .header(AUTHORIZATION, "Bearer " + adminToken).header("If-Match", "*")
                                .contentType(MediaType.APPLICATION_JSON).content(JsonUtils.writeValueAsBytes(update)))
                        .andExpect(status().isOk()).andReturn();
            });
            await().atMost(10, TimeUnit.SECONDS).until(() -> patchRequestEntered.getCount() == 0);
            await().during(300, TimeUnit.MILLISECONDS).atMost(2, TimeUnit.SECONDS).untilAsserted(() -> {
                assertThat(patchSnapshot.getCount()).isOne();
                assertThat(patchResult.isDone()).isFalse();
            });
            releaseInsert.countDown();
            await().atMost(10, TimeUnit.SECONDS).until(postResult::isDone);
            postResult.get();
            await().atMost(10, TimeUnit.SECONDS).until(patchResult::isDone);
            patchResult.get();
            List<AuditEvent> postEvents = byOperation.get("membership-post-first");
            List<AuditEvent> patchEvents = byOperation.get("membership-patch-second");
            assertThat(postEvents).extracting(AuditEvent::getType).containsExactly(GroupMembershipAddedEvent, GroupModifiedEvent);
            assertThat(patchEvents).extracting(AuditEvent::getType).containsExactly(GroupMembershipRemovedEvent, GroupModifiedEvent);
            assertMembershipAudit(postEvents.getFirst(), group, added.getId(), added.getUserName(), "USER");
            assertMembershipAudit(patchEvents.getFirst(), group, testUser.getId(), testUser.getUserName(), "USER");
            assertLegacyGroupSnapshot(postEvents.getLast(), group, testUser.getId(), added.getId());
            assertLegacyGroupSnapshot(patchEvents.getLast(), group, added.getId());
            ScimGroup persisted = JsonUtils.readValue(mockMvc.perform(get("/Groups/" + group.getId())
                            .header(AUTHORIZATION, "Bearer " + adminToken)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(), ScimGroup.class);
            assertThat(persisted.getMembers()).extracting(ScimGroupMember::getMemberId).containsExactly(added.getId());
        } finally {
            releaseInsert.countDown();
            workers.shutdownNow();
            await().atMost(15, TimeUnit.SECONDS).until(workers::isTerminated);
            MockMvcUtils.removeEventListener(configurableApplicationContext, listener);
        }
    }

    private ScimGroup createMembershipAuditGroup(List<ScimGroupMember> members) throws Exception {
        ScimGroup group = new ScimGroup(null, "membership-audit-" + generator.generate(),
                identityZoneManager.getCurrentIdentityZoneId());
        group.setMembers(members);
        return JsonUtils.readValue(mockMvc.perform(post("/Groups").header(AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content(JsonUtils.writeValueAsBytes(group)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString(), ScimGroup.class);
    }

    private List<AuditEvent> capturedAuditEvents() {
        return testListener.getEvents().stream().map(AbstractUaaEvent::getAuditEvent).toList();
    }

    private void assertLegacyGroupSnapshot(AuditEvent event, ScimGroup group, String... memberIds) {
        assertThat(event.getPrincipalId()).isEqualTo(group.getId());
        Map<String, Object> data = JsonUtils.readValueAsMap(event.getData());
        assertThat(data).containsOnlyKeys("group_name", "members").containsEntry("group_name", group.getDisplayName());
        assertThat((List<String>) data.get("members")).containsExactlyInAnyOrder(memberIds);
    }

    private void assertMembershipAudit(AuditEvent event, ScimGroup group, String memberId, String name, String type) {
        assertThat(event.getOrigin()).contains("client=" + testAccounts.getAdminClientId());
        assertThat(event.getPrincipalId()).isEqualTo(group.getId());
        assertThat(event.getIdentityZoneId()).isEqualTo(identityZoneManager.getCurrentIdentityZoneId());
        assertThat(JsonUtils.readValueAsMap(event.getData())).containsExactlyInAnyOrderEntriesOf(Map.of(
                "group_name", group.getDisplayName(), "member_id", memberId, "member_name", name, "member_type", type));
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

    private void assertLogMessage(String actualLogMessage, AuditEventType expectedAuditEventType, String expectedPrincipal, String expectedUserName) {
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
        assertThat(memberIdsFromLogMessage).hasSameElementsAs(Sets.newHashSet(expectedUserIds));
    }
}
