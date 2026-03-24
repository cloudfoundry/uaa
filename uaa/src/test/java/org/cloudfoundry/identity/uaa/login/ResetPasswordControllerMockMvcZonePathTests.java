package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.PredictableGenerator;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import jakarta.servlet.http.Cookie;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.account.UaaResetPasswordService.FORGOT_PASSWORD_INTENT_PREFIX;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
@EnabledIfZonePathsEnabled
public class ResetPasswordControllerMockMvcZonePathTests {
    private final AlphanumericRandomValueStringGenerator subdomainGenerator = new AlphanumericRandomValueStringGenerator();

    @Autowired
    public WebApplicationContext webApplicationContext;
    private ExpiringCodeStore codeStore;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void initResetPasswordTest() {
        codeStore = webApplicationContext.getBean(ExpiringCodeStore.class);
    }

    @AfterEach
    void resetGenerator() {
        webApplicationContext.getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(24));
    }

    final @Value("${login.url}") String externalLoginUrl = "";

    @Test
    void resettingAPasswordUsingUsernameToEnsureNoModification() throws Exception {

        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        PasswordChange change = new PasswordChange(users.getFirst().getId(), users.getFirst().getUserName(), users.getFirst().getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.getFirst(), code, true))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=password_reset"))
                .andReturn();
    }

    @Test
    void resettingPasswordDoesNotUpdateLastLogonTime() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        Long lastLogonBeforeReset = users.getFirst().getLastLogonTime();
        PasswordChange change = new PasswordChange(users.getFirst().getId(), users.getFirst().getUserName(), users.getFirst().getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.getFirst(), code, true))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=password_reset"))
                .andReturn();

        ScimUser userMarissa = webApplicationContext.getBean(ScimUserProvisioning.class).retrieve(users.getFirst().getId(), IdentityZoneHolder.get().getId());
        if (lastLogonBeforeReset != null) {
            assertThat(userMarissa.getLastLogonTime()).isEqualTo(lastLogonBeforeReset);
        } else {
            assertThat(userMarissa.getLastLogonTime()).isNull();
        }
    }

    @Test
    void resettingAPasswordFailsWhenUsernameChanged() throws Exception {

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        ScimUser user = users.getFirst();
        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), null, IdentityZoneHolder.get().getId());

        String formerUsername = user.getUserName();
        user.setUserName("newusername");
        user = userProvisioning.update(user.getId(), user, IdentityZoneHolder.get().getId());
        try {
            mockMvc.perform(createChangePasswordRequest(users.getFirst(), code, true))
                    .andExpect(status().isUnprocessableEntity());
        } finally {
            user.setUserName(formerUsername);
            userProvisioning.update(user.getId(), user, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    void resettingAPasswordWhenCodeIsValidRendersTheChangePasswordForm() throws Exception {

        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);

        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), FORGOT_PASSWORD_INTENT_PREFIX + user.getId(), IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder get = get("/reset_password?code={code}", code.getCode())
                .accept(MediaType.TEXT_HTML);

        String content = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String renderedCode = findInRenderedPage(content, "\\<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"(.*?)\\\"\\/\\>");

        String renderedEmail = findInRenderedPage(content, "\\<input type=\\\"hidden\\\" name=\\\"email\\\" value=\\\"(.*?)\\\"\\/\\>");
        assertThat(user.getPrimaryEmail()).isEqualTo(renderedEmail);

        mockMvc.perform(createChangePasswordRequest(user, renderedCode, true, "secret1", "secret1"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=password_reset"));
    }

    private String findInRenderedPage(String renderedContent, String regexPattern) {
        Pattern expiringCodePattern = Pattern.compile(regexPattern);
        Matcher matcher = expiringCodePattern.matcher(renderedContent);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    @Test
    void correct_url_gets_generated_by_default() throws Exception {
        ScimUser user = getScimUser();
        FakeJavaMailSender sender = webApplicationContext.getBean(FakeJavaMailSender.class);
        sender.clearMessage();
        String expectedRedirect = externalLoginUrl + "/reset_password?code=";
        mockMvc.perform(
                        post("/forgot_password.do")
                                .header("Host", "localhost")
                                .header("X-Forwarded-Host", "other.host.com")
                                .param("username", user.getUserName())
                )
                .andExpect(redirectedUrl("email_sent?code=reset_password"));
        assertThat(sender.getSentMessages().getFirst().getContentString()).contains(expectedRedirect);
        assertThat(sender.getSentMessages().getFirst().getContentString()).doesNotContain("other.host.com");
    }

    private ScimUser getScimUser() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);
        return user;
    }

    @Test
    void new_code_overwrite_old_code_for_repeated_request() throws Exception {
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);

        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);
        JdbcTemplate template = webApplicationContext.getBean(JdbcTemplate.class);
        String intent = FORGOT_PASSWORD_INTENT_PREFIX + user.getId();

        mockMvc.perform(post("/forgot_password.do")
                        .param("username", user.getUserName()))
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        mockMvc.perform(post("/forgot_password.do")
                        .param("username", user.getUserName()))
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        assertThat((int) template.queryForObject("select count(*) from expiring_code_store where intent=?", Integer.class, new Object[]{intent})).isOne();

    }

    @Test
    void redirectToSavedRequest_ifPresent() throws Exception {
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(), new PortResolverImpl()) {
            @Override
            public String getRedirectUrl() {
                return "http://test/redirect/oauth/authorize";
            }

            @Override
            public String[] getParameterValues(String name) {
                if ("client_id".equals(name)) {
                    return new String[]{"admin"};
                }
                return new String[0];
            }

            @Override
            public List<Cookie> getCookies() {
                return null;
            }

            @Override
            public String getMethod() {
                return null;
            }

            @Override
            public List<String> getHeaderValues(String name) {
                return null;
            }

            @Override
            public Collection<String> getHeaderNames() {
                return null;
            }

            @Override
            public List<Locale> getLocales() {
                return null;
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return null;
            }
        };
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session), savedRequest);

        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        mockMvc.perform(post("/forgot_password.do")
                        .session(session)
                        .param("username", user.getUserName()))
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        mockMvc.perform(createChangePasswordRequest(user, "test" + generator.counter.get(), true, "secret1", "secret1")
                        .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=password_reset"));

        mockMvc.perform(post("/login.do")
                        .session(session)
                        .with(cookieCsrf())
                        .param("username", user.getUserName())
                        .param("password", "secret1"))
                .andExpect(redirectedUrl("http://test/redirect/oauth/authorize"));
    }

    @Test
    void resettingAPasswordFailsWhenPasswordChanged() throws Exception {
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        Thread.sleep(1000 - (System.currentTimeMillis() % 1000) + 10); //because password last modified is second only
        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), null, IdentityZoneHolder.get().getId());

        userProvisioning.changePassword(user.getId(), "secret", "secr3t", IdentityZoneHolder.get().getId());
        mockMvc.perform(createChangePasswordRequest(user, code, true))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void resettingAPasswordNoCsrfParameter() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        ExpiringCode code = codeStore.generateCode(users.getFirst().getId(), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.getFirst(), code, false))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login?error=invalid_login_request"));
    }

    @Test
    void resettingAPasswordUsingTimestampForUserModification() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        PasswordChange passwordChange = new PasswordChange(users.getFirst().getId(), users.getFirst().getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder post = createChangePasswordRequest(users.getFirst(), code,
                true, "newpassw0rD", "newpassw0rD");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=password_reset"));
    }

    @Test
    void resetPassword_ReturnsUnprocessableEntity_NewPasswordSameAsOld() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        ScimUser user = users.getFirst();
        PasswordChange passwordChange = new PasswordChange(user.getId(), user.getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"));

        code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(request().attribute("message", equalTo("Your new password cannot be the same as the old password.")))
                .andExpect(forwardedUrl("/reset_password"));
    }

    @Test
    void resetPassword_ReturnsUnprocessableEntity_NewPasswordNotAccordingToPolicy() throws Exception {

        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaaZoneId());
        UaaIdentityProviderDefinition currentDefinition = uaaProvider.getConfig();
        PasswordPolicy passwordPolicy = new PasswordPolicy();
        passwordPolicy.setMinLength(3);
        passwordPolicy.setMaxLength(20);
        uaaProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).update(uaaProvider, uaaProvider.getIdentityZoneId());

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertThat(users)
                .isNotNull()
                .hasSize(1);
        ScimUser user = users.getFirst();
        PasswordChange passwordChange = new PasswordChange(user.getId(), user.getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"));

        code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(createChangePasswordRequest(user, code, true, "a", "a"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(request().attribute("message", equalTo("Password must be at least 3 characters in length.")))
                .andExpect(forwardedUrl("/reset_password"));

        uaaProvider = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaaZoneId());
        uaaProvider.setConfig(currentDefinition);
        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).update(uaaProvider, uaaProvider.getIdentityZoneId());
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, ExpiringCode code, boolean useCSRF) throws Exception {
        return createChangePasswordRequest(user, code, useCSRF, "newpassw0rDl", "newpassw0rDl");
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, ExpiringCode code, boolean useCSRF, String password, String passwordConfirmation) {
        return createChangePasswordRequest(user, code.getCode(), useCSRF, password, passwordConfirmation);
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, String code, boolean useCSRF, String password, String passwordConfirmation) {
        return createChangePasswordRequest(user, code, useCSRF, password, passwordConfirmation, null, null);
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, String code, boolean useCSRF, String password, String passwordConfirmation, ZoneResolutionMode mode, String subdomain) {
        MockHttpServletRequestBuilder post;
        if (mode != null && subdomain != null) {
            post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/reset_password.do");
        } else {
            post = post("/reset_password.do");
        }
        if (useCSRF) {
            post.with(cookieCsrf());
        }
        post.param("code", code)
                .param("email", user.getPrimaryEmail())
                .param("password", password)
                .param("password_confirmation", passwordConfirmation);
        return post;
    }

    /**
     * Creates another identity zone (with admin client) and a user in that zone for zone-path tests.
     * Returns the created user; the zone is in the DB and request-based resolution will use it.
     */
    private ScimUser createUserInOtherZone(String subdomain) throws Exception {
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "admin-secret", null, subdomain);
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        return MockMvcUtils.createUserInZone(mockMvc, adminToken, user, zoneResult.getIdentityZone().getSubdomain());
    }

    /**
     * Creates another identity zone (with admin client) and a user in that zone; returns both for tests that need to generate codes in the zone.
     */
    private IdentityZoneCreationResult createZoneAndUserInOtherZone(String subdomain, ScimUser[] userOut) throws Exception {
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "admin-secret", null, subdomain);
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        ScimUser created = MockMvcUtils.createUserInZone(mockMvc, adminToken, user, zoneResult.getIdentityZone().getSubdomain());
        userOut[0] = created;
        return zoneResult;
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void get_forgot_password_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/forgot_password")
                        .param("client_id", "example")
                        .param("redirect_uri", "http://example.com"))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot_password"))
                .andExpect(model().attribute("client_id", "example"))
                .andExpect(model().attribute("redirect_uri", "http://example.com"));
    }

    /**
     * Forgot password page must be zone-path aware: form action and "Back to Sign In" link
     * must use the zone path prefix when present.
     * Passes for SUBDOMAIN (no /z/ path); will pass for ZONE_PATH once forgot_password.html is made zone-aware.
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void forgot_password_page_has_zone_aware_form_action_and_login_link(ZoneResolutionMode mode) throws Exception {
        String subdomain = mode == ZoneResolutionMode.ZONE_PATH
                ? subdomainGenerator.generate().toLowerCase()
                : "";
        if (mode == ZoneResolutionMode.ZONE_PATH) {
            MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
        }

        String expectedFormAction = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/forgot_password.do" : "/forgot_password.do";
        String expectedLoginPath = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/forgot_password")
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot_password"))
                .andExpect(content().string(containsString("action=\"" + expectedFormAction + "\"")))
                .andExpect(content().string(containsString(expectedLoginPath)));
    }

    /**
     * Backwards compatibility: when UAA is deployed with context path /uaa (e.g. integration tests),
     * forgot_password page must render form action and login link with /uaa prefix.
     */
    @Test
    void forgotPasswordPageWithContextPath_returnsFormActionAndLoginLinkWithContextPath() throws Exception {
        mockMvc.perform(get("/uaa/forgot_password").contextPath("/uaa").accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot_password"))
                .andExpect(content().string(containsString("action=\"/uaa/forgot_password.do\"")))
                .andExpect(content().string(containsString("/uaa/login")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void forgot_password_redirects_to_email_sent_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        ScimUser user = createUserInOtherZone(subdomain);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/forgot_password.do")
                        .param("username", user.getUserName()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=reset_password"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void get_email_sent_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/email_sent")
                        .param("code", "reset_password"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("code", "reset_password"));
    }

    /**
     * email_sent page must render "Back to Sign In" link zone-aware: href="/login" or href="/z/{subdomain}/login".
     * Passes for SUBDOMAIN; will pass for ZONE_PATH once email_sent template/controller are zone path aware.
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void email_sent_page_contains_zone_aware_back_to_sign_in_link(ZoneResolutionMode mode) throws Exception {
        String subdomain = mode == ZoneResolutionMode.ZONE_PATH
                ? subdomainGenerator.generate().toLowerCase()
                : "";
        if (mode == ZoneResolutionMode.ZONE_PATH) {
            MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
        }
        String expectedLoginHref = mode == ZoneResolutionMode.ZONE_PATH
                ? "href=\"/z/" + subdomain + "/login\"" : "href=\"/login\"";

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/email_sent")
                        .param("code", "reset_password")
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedLoginHref)));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void reset_password_full_flow_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        ScimUser user = createUserInOtherZone(subdomain);

        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/forgot_password.do")
                        .param("username", user.getUserName()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        String code = "test" + generator.counter.get();
        String expectedLoginRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "/z/" + subdomain + "/login?success=password_reset"
                : "/login?success=password_reset";
        mockMvc.perform(createChangePasswordRequest(user, code, true, "secret1", "secret1", mode, subdomain))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedLoginRedirect));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void get_reset_password_with_code_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = subdomainGenerator.generate().toLowerCase();
        ScimUser[] userHolder = new ScimUser[1];
        IdentityZoneCreationResult zoneResult = createZoneAndUserInOtherZone(subdomain, userHolder);
        ScimUser user = userHolder[0];

        IdentityZone zone = zoneResult.getIdentityZone();
        IdentityZone previousZone = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(zone);
            PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");
            ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), FORGOT_PASSWORD_INTENT_PREFIX + user.getId(), zone.getId());

            String expectedFormAction = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/reset_password.do" : "/reset_password.do";

            MockHttpServletRequestBuilder getRequest = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/reset_password")
                    .param("code", code.getCode())
                    .accept(MediaType.TEXT_HTML);

            mockMvc.perform(getRequest)
                    .andExpect(status().isOk())
                    .andExpect(view().name("reset_password"))
                    .andExpect(content().string(containsString("Reset Password")))
                    .andExpect(content().string(containsString("Username: " + user.getUserName())))
                    .andExpect(content().string(containsString("Create new password")))
                    .andExpect(content().string(containsString("action=\"" + expectedFormAction + "\"")));
        } finally {
            IdentityZoneHolder.set(previousZone);
        }
    }
}
