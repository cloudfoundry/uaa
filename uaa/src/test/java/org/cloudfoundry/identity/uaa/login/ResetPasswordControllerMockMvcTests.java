package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.PredictableGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.Cookie;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.account.UaaResetPasswordService.FORGOT_PASSWORD_INTENT_PREFIX;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
public class ResetPasswordControllerMockMvcTests {
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

    @Test
    void testResettingAPasswordUsingUsernameToEnsureNoModification() throws Exception {

        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordChange change = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), users.get(0).getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.get(0), code, true))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?success=password_reset"))
            .andReturn();
    }

    @Test
    void testResettingPasswordDoesNotUpdateLastLogonTime() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        Long lastLogonBeforeReset = users.get(0).getLastLogonTime();
        PasswordChange change = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), users.get(0).getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.get(0), code, true))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?success=password_reset"))
            .andReturn();

        ScimUser userMarissa = webApplicationContext.getBean(ScimUserProvisioning.class).retrieve(users.get(0).getId(), IdentityZoneHolder.get().getId());
        if(lastLogonBeforeReset != null) {
            assertEquals(lastLogonBeforeReset,userMarissa.getLastLogonTime());
        } else {
            assertNull(userMarissa.getLastLogonTime());
        }
    }

    @Test
    void testResettingAPasswordFailsWhenUsernameChanged() throws Exception {

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), null, IdentityZoneHolder.get().getId());

        String formerUsername = user.getUserName();
        user.setUserName("newusername");
        user = userProvisioning.update(user.getId(), user, IdentityZoneHolder.get().getId());
        try {
            mockMvc.perform(createChangePasswordRequest(users.get(0), code, true))
                .andExpect(status().isUnprocessableEntity());
        } finally {
            user.setUserName(formerUsername);
            userProvisioning.update(user.getId(), user, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    void testResettingAPassword_whenCodeIsValid_rendersTheChangePasswordForm() throws Exception {

        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
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
        assertEquals(renderedEmail, user.getPrimaryEmail());


        mockMvc.perform(createChangePasswordRequest(user, renderedCode, true, "secret1", "secret1"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?success=password_reset"));
    }

    private String findInRenderedPage(String renderedContent, String regexPattern) {
        Pattern expiringCodePattern = Pattern.compile(regexPattern);
        Matcher matcher = expiringCodePattern.matcher(renderedContent);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    @Test
    void correct_url_gets_generated_by_default() throws Exception {
        ScimUser user = getScimUser();
        FakeJavaMailSender sender = webApplicationContext.getBean(FakeJavaMailSender.class);
        sender.clearMessage();
        mockMvc.perform(
            post("/forgot_password.do")
                .header("Host", "localhost")
                .header("X-Forwarded-Host", "other.host.com")
                .param("username", user.getUserName())
        )
            .andExpect(redirectedUrl("email_sent?code=reset_password"));
        assertThat(sender.getSentMessages().get(0).getContentString(), containsString("http://localhost/reset_password?code="));
        assertThat(sender.getSentMessages().get(0).getContentString(), not(containsString("other.host.com")));
    }

    private ScimUser getScimUser() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);
        return user;
    }

    @Test
    void new_code_overwrite_old_code_for_repeated_request() throws Exception {
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword("secret");
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);


        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);
        JdbcTemplate template = webApplicationContext.getBean(JdbcTemplate.class);
        String intent = FORGOT_PASSWORD_INTENT_PREFIX+user.getId();

        mockMvc.perform(post("/forgot_password.do")
                                 .param("username", user.getUserName()))
            .andExpect(redirectedUrl("email_sent?code=reset_password"));

        mockMvc.perform(post("/forgot_password.do")
                                 .param("username", user.getUserName()))
            .andExpect(redirectedUrl("email_sent?code=reset_password"));

        assertEquals(1, (int)template.queryForObject("select count(*) from expiring_code_store where intent=?", new Object[] {intent}, Integer.class));

    }

    @Test
    void redirectToSavedRequest_ifPresent() throws Exception {
        String username = new RandomValueStringGenerator().generate() ;
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
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
                    return new String[] {"admin"};
                }
                return new String[0];
            }
            @Override public List<Cookie> getCookies() { return null; }
            @Override public String getMethod() { return null; }
            @Override public List<String> getHeaderValues(String name) { return null; }
            @Override
            public Collection<String> getHeaderNames() { return null; }
            @Override public List<Locale> getLocales() { return null; }
            @Override public Map<String, String[]> getParameterMap() { return null; }
        };
        SessionUtils.setSavedRequestSession(session, savedRequest);

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
    void testResettingAPasswordFailsWhenPasswordChanged() throws Exception {
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
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
    void testResettingAPasswordNoCsrfParameter() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        ExpiringCode code = codeStore.generateCode(users.get(0).getId(), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        mockMvc.perform(createChangePasswordRequest(users.get(0), code, false))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login?error=invalid_login_request"));
    }

    @Test
    void testResettingAPasswordUsingTimestampForUserModification() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordChange passwordChange = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder post = createChangePasswordRequest(users.get(0), code,
            true, "newpassw0rD", "newpassw0rD");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?success=password_reset"));
    }

    @Test
    void resetPassword_ReturnsUnprocessableEntity_NewPasswordSameAsOld() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId());
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
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
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
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
        return createChangePasswordRequest(user,code.getCode(),useCSRF, password,passwordConfirmation);
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, String code, boolean useCSRF, String password, String passwordConfirmation) {
        MockHttpServletRequestBuilder post = post("/reset_password.do");
        if (useCSRF) {
            post.with(cookieCsrf());
        }
        post.param("code", code)
            .param("email", user.getPrimaryEmail())
            .param("password", password)
            .param("password_confirmation", passwordConfirmation);
        return post;
    }
}
