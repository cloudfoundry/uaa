package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ChangeEmailEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.ResultActions;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor;

@Component
public class AllowUserManagementSecurityFilterMockMvcTest extends InjectedMockContextTest {

    public static final String PASSWD = "passwd";
    public static final String ACCEPT_TEXT_HTML = "text/html";

    private TestClient testClient;
    private String token;

    ExpiringCodeStore codeStore = null;

    @Before
    public void setUp() throws Exception {
        codeStore = (ExpiringCodeStore)this.getWebApplicationContext().getBean("codeStore");

        testClient = new TestClient(getMockMvc());
        token = testClient.getClientCredentialsOAuthAccessToken(
            "login",
            "loginsecret",
            "scim.write,password.write");
    }

    @After
    public void tearDown() {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
    }

    @Test
    public void userEndpointCreateNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        ResultActions result = createUser();
        result.andExpect(status().isForbidden());
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.",
            result.andReturn().getResponse().getErrorMessage());
    }

    @Test
    public void userEndpointUpdateNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(put("/Users/" + createdUser.getId())
            .header("Authorization", "Bearer " + token)
            .header("If-Match", "\"" + createdUser.getVersion() + "\"")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(createdUser)))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void userEndpointUpdatePasswordNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(PASSWD);
        request.setPassword("n3wAw3som3Passwd");
        String errorMessage = getMockMvc().perform(put("/Users/" + createdUser.getId() + "/password")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request)))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void userEndpointDeleteNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(delete("/Users/" + createdUser.getId())
            .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void userEndpointGetUsersNotAllowed() throws Exception {
        TestClient adminClient = new TestClient(getMockMvc());
        String adminToken = adminClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "scim.read");

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/Users")
            .header("Authorization", "Bearer " + adminToken))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void userEndpointVerifyUsersNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/Users/" + createdUser.getId() + "/verify")
            .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void accountsControllerCreateAccountNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/create_account"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void accountsControllerSendActivationEmailNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(post("/create_account.do")
            .param("client_id", "login")
            .param("email", "another@example.com")
            .param("password", "foobar")
            .param("password_confirmation", "foobar"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void accountsControllerEmailSentNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/accounts/email_sent"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void accountsControllerVerifyUserNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", createdUser.getId());
        codeData.put("client_id", "login");

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/verify_user")
            .param("code", getExpiringCode(codeData).getCode()))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void changeEmailControllerChangeEmailPageNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/change_email")
            .session(getUserSession(createdUser.getUserName(), PASSWD))
            .with(csrf())
            .accept(ACCEPT_TEXT_HTML))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void changeEmailControllerChangeEmailNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(post("/change_email.do")
            .session(getUserSession(createdUser.getUserName(), PASSWD))
            .with(csrf())
            .accept(ACCEPT_TEXT_HTML)
            .param("newEmail", "newUser@example.com")
            .param("client_id", "login"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void changeEmailControllerVerifyEmailNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        ChangeEmailEndpoints.EmailChange change = new ChangeEmailEndpoints.EmailChange();
        change.setClientId("login");
        change.setEmail(createdUser.getUserName());
        change.setUserId(createdUser.getId());
        ExpiringCode code = getExpiringCode(change);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/verify_email")
            .param("code", code.getCode()))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void changePasswordControllerChangePasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/change_password"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void changePasswordControllerChangePasswordNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(post("/change_password.do")
            .session(getUserSession(createdUser.getUserName(), PASSWD))
            .with(csrf())
            .accept(ACCEPT_TEXT_HTML)
            .param("current_password", PASSWD)
            .param("new_password", "whatever")
            .param("confirm_password", "whatever"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void resetPasswordControllerForgotPasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/forgot_password"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void resetPasswordControllerForgotPasswordNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(post("/forgot_password.do")
            .param("email", "another@example.com"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void resetPasswordControllerEmailSentPageNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/email_sent"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void resetPasswordControllerResetPasswordPageNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(get("/reset_password")
            .param("code", "12345")
            .param("email", "another@example.com"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    @Test
    public void resetPasswordControllerResetPasswordNotAllowed() throws Exception {
        MockMvcUtils.setInternalUserManagement(true, getWebApplicationContext());
        ResultActions result = createUser();
        ScimUser createdUser = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), ScimUser.class);

        PasswordChange change = new PasswordChange(createdUser.getId(), createdUser.getUserName(), createdUser.getPasswordLastModified());

        MockMvcUtils.setInternalUserManagement(false, getWebApplicationContext());
        String errorMessage = getMockMvc().perform(post("/reset_password.do")
            .param("code", getExpiringCode(change).getCode())
            .param("email", createdUser.getUserName())
            .param("password", "new-password")
            .param("password_confirmation", "new-password")
            .with(csrf()))
            .andExpect(status().isForbidden()).andReturn().getResponse().getErrorMessage();
        assertEquals("Internal User Creation is currently disabled. External User Store is in use.", errorMessage);
    }

    private ExpiringCode getExpiringCode(Object data) {
        Timestamp fiveMinutes = new Timestamp(System.currentTimeMillis()+(1000*60*5));
        return codeStore.generateCode(JsonUtils.writeValueAsString(data), fiveMinutes);
    }

    private CookieCsrfPostProcessor cookieCsrf() {
        return new CookieCsrfPostProcessor();
    }

    private MockHttpSession getUserSession(String username, String password) throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpSession afterLoginSession = (MockHttpSession) getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(ACCEPT_TEXT_HTML)
            .param("username", username)
            .param("password", password))
            .andReturn().getRequest().getSession(false);

        assertTrue(session.isInvalid());
        assertNotNull(afterLoginSession);
        assertNotNull(afterLoginSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        return afterLoginSession;
    }

    private ResultActions createUser() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(id, id + "@example.com", "first-name", "family-name");
        user.setPassword(PASSWD);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(id + "@example.com");
        user.setEmails(Collections.singletonList(email));

        return getMockMvc().perform(post("/Users")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user)));
    }

}
