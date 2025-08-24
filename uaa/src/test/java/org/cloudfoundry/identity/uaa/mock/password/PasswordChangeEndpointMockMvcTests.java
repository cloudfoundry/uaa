package org.cloudfoundry.identity.uaa.mock.password;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class PasswordChangeEndpointMockMvcTests {
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String passwordWriteToken;
    private String adminToken;
    private String password;

    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setUp(@Autowired TestClient testClient, @Autowired MockMvc mockMvc) throws Exception {
        this.mockMvc = mockMvc;
        this.testClient = testClient;

        password = "secret";

        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret scim.write clients.admin");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();

        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, null, "client_credentials", "password.write");
        clientDetails.setClientSecret(clientSecret);

        MockMvcUtils.createClient(mockMvc, adminToken, clientDetails);

        passwordWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "password.write");
    }

    @Test
    void changePassword_withInvalidPassword_returnsErrorJson() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        String tooLongPassword = new RandomValueStringGenerator(260).generate();
        request.setPassword(tooLongPassword);
        MockHttpServletRequestBuilder putRequest = put("/Users/" + user.getId() + "/password")
                .header("Authorization", "Bearer " + passwordWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request));

        mockMvc.perform(putRequest)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    void changePassword_NewPasswordSameAsOld_ReturnsUnprocessableEntityWithJsonError() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        request.setPassword(password);
        mockMvc.perform(put("/Users/" + user.getId() + "/password").header("Authorization", "Bearer " + passwordWriteToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Your new password cannot be the same as the old password."));
    }

    @Test
    void changePassword_WithBadOldPassword_ReturnsUnauthorizedError() throws Exception {
        ScimUser user = createUser();
        String userToken = testClient.getUserOAuthAccessToken("cf", "", user.getUserName(), password, "password.write");

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("wrongPassword");
        request.setPassword(password);
        mockMvc.perform(put("/Users/" + user.getId() + "/password")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error_description").value("Old password is incorrect"))
                .andExpect(jsonPath("$.error").value("unauthorized"));
    }

    @Test
    void changePassword_SuccessfullyChangePassword() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        request.setPassword("n3wAw3som3Passwd");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId() + "/password")
                .header("Authorization", "Bearer " + passwordWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .accept(APPLICATION_JSON);

        mockMvc.perform(put)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.message").value("password updated"));
    }

    @Test
    void changePassword_Resets_Session() throws Exception {
        ScimUser user = createUser();

        MockHttpSession session = new MockHttpSession();
        session.invalidate();
        MockHttpSession afterLoginSession = (MockHttpSession) mockMvc.perform(post("/login.do")
                        .with(cookieCsrf())
                        .session(session)
                        .accept(TEXT_HTML_VALUE)
                        .param("username", user.getUserName())
                        .param("password", password))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getRequest().getSession(false);

        assertThat(afterLoginSession).isNotNull();
        assertThat(afterLoginSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();

        MockHttpSession afterPasswordChange = (MockHttpSession) mockMvc.perform(post("/change_password.do")
                        .session(afterLoginSession)
                        .with(cookieCsrf())
                        .accept(TEXT_HTML_VALUE)
                        .param("current_password", password)
                        .param("new_password", "secr3T1")
                        .param("confirm_password", "secr3T1"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"))
                .andReturn().getRequest().getSession(false);

        assertThat(afterLoginSession.isInvalid()).isTrue();
        assertThat(afterPasswordChange).isNotNull();
        assertThat(afterPasswordChange.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
        assertThat(afterLoginSession).isNotSameAs(afterPasswordChange);
    }

    @Test
    void changePassword_Resets_All_Sessions() throws Exception {
        ScimUser user = createUser();

        MockHttpSession session = new MockHttpSession();
        MockHttpSession afterLoginSessionA = (MockHttpSession) mockMvc.perform(post("/login.do")
                        .with(cookieCsrf())
                        .session(session)
                        .accept(TEXT_HTML_VALUE)
                        .param("username", user.getUserName())
                        .param("password", password))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getRequest().getSession(false);

        session = new MockHttpSession();
        MockHttpSession afterLoginSessionB = (MockHttpSession) mockMvc.perform(post("/login.do")
                        .with(cookieCsrf())
                        .session(session)
                        .accept(TEXT_HTML_VALUE)
                        .param("username", user.getUserName())
                        .param("password", password))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getRequest().getSession(false);

        assertThat(afterLoginSessionA.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
        assertThat(afterLoginSessionB.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();

        mockMvc.perform(get("/profile").session(afterLoginSessionB))
                .andExpect(status().isOk());

        Thread.sleep(1000 - (System.currentTimeMillis() % 1000) + 1);

        MockHttpSession afterPasswordChange = (MockHttpSession) mockMvc.perform(post("/change_password.do")
                        .session(afterLoginSessionA)
                        .with(cookieCsrf())
                        .accept(TEXT_HTML_VALUE)
                        .param("current_password", password)
                        .param("new_password", "secr3T1")
                        .param("confirm_password", "secr3T1"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"))
                .andReturn().getRequest().getSession(false);

        assertThat(afterLoginSessionA.isInvalid()).isTrue();
        assertThat(afterPasswordChange).isNotNull();
        assertThat(afterPasswordChange.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
        assertThat(afterLoginSessionA).isNotSameAs(afterPasswordChange);
        mockMvc.perform(
                        get("/profile")
                                .session(afterLoginSessionB)
                                .accept(TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    private ScimUser createUser() throws Exception {
        String id = generator.generate();
        ScimUser user = new ScimUser(id, id + "user@example.com", "name", "familyname");
        user.addEmail(id + "user@example.com");
        user.setPassword(password);
        return MockMvcUtils.createUser(mockMvc, adminToken, user);
    }
}
