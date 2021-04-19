package org.cloudfoundry.identity.uaa.login;

import lombok.SneakyThrows;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.*;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.csrf;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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
    private MfaProvider mfaProvider;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setup() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        user = MockMvcUtils.createUser(mockMvc, token, user);
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, "uaa");
        mfaProvider = MockMvcUtils.createMfaProvider(webApplicationContext, IdentityZone.getUaa());
    }

    @AfterEach
    void cleanup() {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
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

            getLoginForm(mockMvc, session);

            MockHttpServletRequestBuilder userForcePasswordChangePostLogin = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .with(csrf(session));
            mockMvc.perform(userForcePasswordChangePostLogin)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/"));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertTrue(SessionUtils.isPasswordChangeRequired(session));

            getRootPath(session)
                    .andExpect(redirectedUrl("/force_password_change"));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertTrue(SessionUtils.isPasswordChangeRequired(session));

            getForcePasswordChangeForm(mockMvc, session);

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .with(csrf(session));
            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(("/force_password_change_completed")));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertFalse(SessionUtils.isPasswordChangeRequired(session));

            getForcePasswordChangeCompleted(session)
                    .andExpect(redirectedUrl("http://localhost/"));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertFalse(SessionUtils.isPasswordChangeRequired(session));
        }

        @Nested
        @DefaultTestContext
        class WithMFA {
            @BeforeEach
            void setup() {
                uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
                MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
            }


            @Test
            @DisplayName("")
            void requires_user_to_change_password() throws Exception {
                MockHttpSession session = (MockHttpSession) performMfaRegistrationInZone(
                        user.getUserName(),
                        "secret",
                        mockMvc,
                        "localhost",
                        new String[]{"pwd"},
                        new String[]{"pwd", "mfa", "otp"}
                ).andExpect(status().isFound())
                        .andExpect(redirectedUrl("/force_password_change"))
                        .andReturn()
                        .getRequest()
                        .getSession(false);

                getForcePasswordChangeForm(mockMvc, session);

                MockHttpServletRequestBuilder validPost = post("/force_password_change")
                        .param("password", "test")
                        .param("password_confirmation", "test")
                        .with(csrf(session));
                mockMvc.perform(validPost)
                        .andExpect(status().isFound())
                        .andExpect(redirectedUrl(("/force_password_change_completed")));
                assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
                assertFalse(SessionUtils.isPasswordChangeRequired(session));

                getForcePasswordChangeCompleted(session)
                        .andExpect(redirectedUrl("http://localhost/"));
                assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
                assertFalse(SessionUtils.isPasswordChangeRequired(session));
            }
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
            cleanIdpDefinition = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
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

            identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicyWithInvalidPassword.passwordPolicy, null));
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            getLoginForm(mockMvc, session);

            MockHttpServletRequestBuilder login = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .with(csrf(session));
            mockMvc.perform(login)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/"));

            getForcePasswordChangeForm(mockMvc, session);

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", passwordPolicyWithInvalidPassword.password)
                    .param("password_confirmation", passwordPolicyWithInvalidPassword.password)
                    .with(csrf(session));
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

            getLoginForm(mockMvc, session);

            MockHttpServletRequestBuilder login = post("/login.do")
                    .param("username", user.getUserName())
                    .param("password", "secret")
                    .with(csrf(session));
            mockMvc.perform(login)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/"));

            getRootPath(session)
                    .andExpect(redirectedUrl("/force_password_change"));

            getForcePasswordChangeForm(mockMvc, session);

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .with(csrf(session));
            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(("/force_password_change_completed")));

            getForcePasswordChangeCompleted(session)
                    .andExpect(redirectedUrl("http://localhost/"));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertFalse(SessionUtils.isPasswordChangeRequired(session));
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
        mockMvc.perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("http://localhost/login?error=invalid_login_request")));
    }

    @SneakyThrows
    private ResultActions getForcePasswordChangeCompleted(MockHttpSession session) {
        return performGet(mockMvc, session, "/force_password_change_completed")
                .andExpect(status().isFound());
    }

    @SneakyThrows
    private ResultActions getRootPath(MockHttpSession session) {
        return performGet(mockMvc, session, "/")
                .andExpect(status().isFound());
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
