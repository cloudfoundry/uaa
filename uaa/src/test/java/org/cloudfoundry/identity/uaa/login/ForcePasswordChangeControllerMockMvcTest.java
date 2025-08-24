package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.util.Date;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
class ForcePasswordChangeControllerMockMvcTest {
    private ScimUser user;
    private String token;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setup() throws Exception {
        String username = new AlphanumericRandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, "uaa");
    }

    @AfterEach
    void cleanup() {
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
    }

    @Nested
    @DefaultTestContext
    class HappyPath {
        @BeforeEach
        void setup() throws Exception {
            UserAccountStatus userAccountStatus = new UserAccountStatus();
            userAccountStatus.setPasswordChangeRequired(true);
            String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
            mockMvc.perform(
                            patch("/Users/" + user.getId() + "/status")
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON)
                                    .contentType(APPLICATION_JSON)
                                    .content(jsonStatus))
                    .andExpect(status().isOk());
        }

        @Test
        void requires_user_to_change_password() throws Exception {
            MockHttpSession session = new MockHttpSession();

            MockHttpServletRequestBuilder userForcePasswordChangePostLogin = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .with(cookieCsrf())
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            mockMvc.perform(userForcePasswordChangePostLogin)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/"));

            assertThat(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(session)).isTrue();

            mockMvc.perform(get("/")
                            .session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/force_password_change"));

            assertThat(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(session)).isTrue();

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .session(session)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/force_password_change_completed"));
            assertThat(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(session)).isFalse();

            mockMvc.perform(get("/force_password_change_completed")
                            .session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://localhost/"));
            assertThat(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(session)).isFalse();
        }

    }

    @Nested
    @DefaultTestContext
    class WithPasswordPolicy {
        IdentityProvider identityProvider;
        UaaIdentityProviderDefinition cleanIdpDefinition;

        @BeforeEach
        void setup() {
            identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
            cleanIdpDefinition = (UaaIdentityProviderDefinition) identityProvider.getConfig();
        }

        @AfterEach
        void cleanup() {
            identityProvider.setConfig(cleanIdpDefinition);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }

        @ParameterizedTest
        @MethodSource("org.cloudfoundry.identity.uaa.login.ForcePasswordChangeControllerMockMvcTest#authenticationTestParams")
        void force_password_change_with_invalid_password(PasswordPolicyWithInvalidPassword passwordPolicyWithInvalidPassword) throws Exception {
            UserAccountStatus userAccountStatus = new UserAccountStatus();
            userAccountStatus.setPasswordChangeRequired(true);
            String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
            mockMvc.perform(
                            patch("/Users/" + user.getId() + "/status")
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON)
                                    .contentType(APPLICATION_JSON)
                                    .content(jsonStatus))
                    .andExpect(status().isOk());
            MockHttpSession session = new MockHttpSession();
            Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

            identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicyWithInvalidPassword.passwordPolicy, null));
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            MockHttpServletRequestBuilder invalidPost = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .cookie(cookie)
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            mockMvc.perform(invalidPost)
                    .andExpect(status().isFound());

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", passwordPolicyWithInvalidPassword.password)
                    .param("password_confirmation", passwordPolicyWithInvalidPassword.password)
                    .session(session)
                    .cookie(cookie)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(view().name("force_password_change"))
                    .andExpect(model().attribute("message", passwordPolicyWithInvalidPassword.errorMessage))
                    .andExpect(model().attribute("email", user.getPrimaryEmail()));
        }

        @Test
        void force_password_when_system_was_configured() throws Exception {
            PasswordPolicy passwordPolicy = new PasswordPolicy(4, 20, 0, 0, 0, 0, 0);
            passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
            identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));

            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
            MockHttpSession session = new MockHttpSession();

            MockHttpServletRequestBuilder invalidPost = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .session(session)
                    .with(cookieCsrf())
                    .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

            mockMvc.perform(invalidPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/"));

            mockMvc.perform(
                            get("/")
                                    .session(session)
                    )
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/force_password_change"));

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .session(session)
                    .with(cookieCsrf());

            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/force_password_change_completed"));

            mockMvc.perform(get("/force_password_change_completed")
                            .session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://localhost/"));
            assertThat(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated()).isTrue();
            assertThat(SessionUtils.isPasswordChangeRequired(session)).isFalse();
        }
    }

    @Test
    void submit_password_change_when_not_authenticated() throws Exception {
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
        mockMvc.perform(
                        patch("/Users/" + user.getId() + "/status")
                                .header("Authorization", "Bearer " + token)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_JSON)
                                .content(jsonStatus))
                .andExpect(status().isOk());

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test");
        validPost.with(cookieCsrf());
        mockMvc.perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    static class PasswordPolicyWithInvalidPassword {
        PasswordPolicy passwordPolicy;
        String password;
        String errorMessage;

        public PasswordPolicyWithInvalidPassword(PasswordPolicy passwordPolicy, String password, String errorMessage) {
            this.passwordPolicy = passwordPolicy;
            this.password = password;
            this.errorMessage = errorMessage;
        }
    }

    static Stream<PasswordPolicyWithInvalidPassword> authenticationTestParams() {
        return Stream.of(
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(2, 0, 0, 0, 0, 0, 0), "1", "Password must be at least 2 characters in length."),
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(0, 1, 0, 0, 0, 0, 0), "12", "Password must be no more than 1 characters in length."),
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(0, 1, 1, 0, 0, 0, 0), "1", "Password must contain at least 1 uppercase characters."),
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(0, 1, 0, 1, 0, 0, 0), "1", "Password must contain at least 1 lowercase characters."),
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(0, 1, 0, 0, 1, 0, 0), "a", "Password must contain at least 1 digit characters."),
                new PasswordPolicyWithInvalidPassword(new PasswordPolicy(0, 1, 0, 0, 0, 1, 0), "a", "Password must contain at least 1 special characters.")
        );

    }

}
