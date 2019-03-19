package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.SpringServletAndHoneycombTestConfig;
import org.cloudfoundry.identity.uaa.account.EmailChange;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.test.JsonObjectMatcherUtils;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class DisableUserManagementSecurityFilterMockMvcTest {
    private static final String PASSWD = "passwd";
    private static final String ACCEPT_TEXT_HTML = "text/html";
    private static final String ERROR_TEXT = "internal_user_management_disabled";
    private static final String MESSAGE_TEXT = "Internal User Creation is currently disabled. External User Store is in use.";

    private String token;

    @Autowired
    private ExpiringCodeStore codeStore;

    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @Value("${disableInternalUserManagement:false}")
    private boolean disableInternalUserManagement;

    @BeforeEach
    void setUp(@Autowired FilterChainProxy springSecurityFilterChain) throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);

        token = testClient.getClientCredentialsOAuthAccessToken(
                "login",
                "loginsecret",
                "scim.write,password.write");
    }

    @AfterEach
    void tearDown() {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, disableInternalUserManagement);
    }

    @Test
    void userEndpointCreateNotAllowed_For_Origin_UAA() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        ResultActions result = createUser();
        result.andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void userEndpointCreateAllowed_For_Origin_LDAP() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        ResultActions result = createUser(OriginKeys.LDAP);
        result.andExpect(status().isCreated());
    }

    @Test
    void userEndpointUpdateNotAllowed_For_Origin_UAA() throws Exception {
        userEndpointUpdateNotAllowed_For_Origin_UAA(OriginKeys.UAA);
        userEndpointUpdateNotAllowed_For_Origin_UAA("");
        userEndpointUpdateNotAllowed_For_Origin_UAA(null);
    }

    @Test
    void userEndpointUpdateAllowed_For_Origin_SAML() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser(OriginKeys.SAML);
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(put("/Users/" + createdUser.getId())
                .header("Authorization", "Bearer " + token)
                .header("If-Match", "\"" + createdUser.getVersion() + "\"")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(createdUser)))
                .andExpect(status().isOk());
    }

    @Test
    void userEndpointUpdatePasswordNotAllowed_For_Origin_UAA() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(PASSWD);
        request.setPassword("n3wAw3som3Passwd");
        mockMvc.perform(put("/Users/" + createdUser.getId() + "/password")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("message", MESSAGE_TEXT)
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void userEndpointDeleteNotAllowed_For_Origin_UAA() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(delete("/Users/" + createdUser.getId())
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void userEndpointDeleteNotAllowed_For_Origin_LDAP() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser(OriginKeys.LDAP);
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(delete("/Users/" + createdUser.getId())
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void userEndpointGetUsersAllowed() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "scim.read");

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/Users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    @Test
    void userEndpointVerifyUsersNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/Users/" + createdUser.getId() + "/verify")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void accountsControllerCreateAccountNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/create_account"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void accountsControllerSendActivationEmailNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(post("/create_account.do")
                .with(cookieCsrf())
                .param("client_id", "login")
                .param("email", "another@example.com")
                .param("password", "foobar")
                .param("password_confirmation", "foobar"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void accountsControllerEmailSentNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/accounts/email_sent"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void accountsControllerVerifyUserNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", createdUser.getId());
        codeData.put("client_id", "login");

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/verify_user")
                .param("code", getExpiringCode(codeData).getCode()))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void changeEmailControllerChangeEmailPageNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockHttpSession userSession = getUserSession(createdUser.getUserName(), PASSWD);
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/change_email")
                .session(userSession)
                .with(cookieCsrf())
                .accept(ACCEPT_TEXT_HTML))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));
    }

    @Test
    void changeEmailControllerChangeEmailNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(post("/change_email.do")
                .session(getUserSession(createdUser.getUserName(), PASSWD))
                .with(CookieCsrfPostProcessor.cookieCsrf())
                .accept(ACCEPT_TEXT_HTML)
                .param("newEmail", "newUser@example.com")
                .param("client_id", "login"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void changeEmailControllerVerifyEmailNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        EmailChange change = new EmailChange();
        change.setClientId("login");
        change.setEmail(createdUser.getUserName());
        change.setUserId(createdUser.getId());
        ExpiringCode code = getExpiringCode(change);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/verify_email")
                .param("code", code.getCode()))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void changePasswordControllerChangePasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);

        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);

        mockMvc.perform(get("/change_password")
                .session(getUserSession(createdUser.getUserName(), PASSWD)))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void changePasswordControllerChangePasswordNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);
        MockHttpSession userSession = getUserSession(createdUser.getUserName(), PASSWD);
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(post("/change_password.do")
                .session(userSession)
                .with(CookieCsrfPostProcessor.cookieCsrf())
                .accept(ACCEPT_TEXT_HTML)
                .param("current_password", PASSWD)
                .param("new_password", "whatever")
                .param("confirm_password", "whatever"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void resetPasswordControllerForgotPasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/forgot_password"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void resetPasswordControllerForgotPasswordNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(post("/forgot_password.do")
                .param("email", "another@example.com"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void resetPasswordControllerEmailSentPageNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/email_sent"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void resetPasswordControllerResetPasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/reset_password")
                .param("code", "12345")
                .param("email", "another@example.com"))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    @Test
    void resetPasswordControllerResetPasswordNotAllowed() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        PasswordChange change = new PasswordChange(createdUser.getId(), createdUser.getUserName(), createdUser.getPasswordLastModified(), "", "");

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(post("/reset_password.do")
                .param("code", getExpiringCode(change).getCode())
                .param("email", createdUser.getUserName())
                .param("password", "new-password")

                .param("password_confirmation", "new-password")
                .with(CookieCsrfPostProcessor.cookieCsrf()))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", MESSAGE_TEXT)
                                        .put("message", MESSAGE_TEXT)
                                        .put("error", ERROR_TEXT))));

    }

    private ExpiringCode getExpiringCode(Object data) {
        Timestamp fiveMinutes = new Timestamp(System.currentTimeMillis() + (1000 * 60 * 5));
        return codeStore.generateCode(JsonUtils.writeValueAsString(data), fiveMinutes, null, IdentityZoneHolder.get().getId());
    }

    private CookieCsrfPostProcessor cookieCsrf() {
        return new CookieCsrfPostProcessor();
    }

    private MockHttpSession getUserSession(String username, String password) throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.invalidate();

        MockHttpSession afterLoginSession = (MockHttpSession) mockMvc.perform(post("/login.do")
                .with(cookieCsrf())
                .session(session)
                .accept(ACCEPT_TEXT_HTML)
                .param("username", username)
                .param("password", password))
                .andDo(print())
                .andReturn().getRequest().getSession(false);

        assertNotNull(afterLoginSession);
        assertNotNull(afterLoginSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        return afterLoginSession;
    }

    private ResultActions createUser() throws Exception {
        return createUser(OriginKeys.UAA);
    }

    private ResultActions createUser(String origin) throws Exception {
        String id = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(id, id + "@example.com", "first-name", "family-name");
        user.setOrigin(origin);
        user.setPassword(PASSWD);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(id + "@example.com");
        user.setEmails(Collections.singletonList(email));

        return mockMvc.perform(post("/Users")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)));
    }

    private void userEndpointUpdateNotAllowed_For_Origin_UAA(String origin) throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
        ResultActions result = createUser(origin);
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(put("/Users/" + createdUser.getId())
                .header("Authorization", "Bearer " + token)
                .header("If-Match", "\"" + createdUser.getVersion() + "\"")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(createdUser)))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(new JSONObject()
                                .put("error_description", MESSAGE_TEXT)
                                .put("message", MESSAGE_TEXT)
                                .put("error", ERROR_TEXT))));
    }
}
