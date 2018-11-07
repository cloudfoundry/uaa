package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.performMfaRegistrationInZone;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
class ForcePasswordChangeControllerMockMvcTest {
    private ScimUser user;
    private String token;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private MfaProvider mfaProvider;

    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;

    @BeforeEach
    void setup() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();


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

    @Test
    void force_password_change_when_mfa_is_enabled() throws Exception {
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
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
        ResultActions actions = performMfaRegistrationInZone(
                user.getUserName(),
                "secret",
                mockMvc,
                "localhost",
                new String[]{"pwd"},
                new String[]{"pwd", "mfa", "otp"}
        );
        actions
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/force_password_change"));
        MockHttpSession session = (MockHttpSession) actions.andReturn().getRequest().getSession(false);
        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .with(cookieCsrf());
        validPost.with(cookieCsrf());
        mockMvc.perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/force_password_change_completed")));
        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertFalse(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());

        mockMvc.perform(get("/force_password_change_completed")
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/"));
        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertFalse(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());
    }

    @Test
    void force_password_change_happy_path() throws Exception {
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

        MockHttpServletRequestBuilder userForcePasswordChangePostLogin = post("/login.do")
                .param("username", user.getUserName())
                .param("password", "secret")
                .session(session)
                .with(cookieCsrf())
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
        mockMvc.perform(userForcePasswordChangePostLogin)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));

        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertTrue(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());

        mockMvc.perform(get("/")
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/force_password_change"));

        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertTrue(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .with(cookieCsrf());
        validPost.with(cookieCsrf());
        mockMvc.perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/force_password_change_completed")));
        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertFalse(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());

        mockMvc.perform(get("/force_password_change_completed")
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/"));
        assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
        assertFalse(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());
    }

    @Test
    void force_password_change_with_invalid_password() throws Exception {
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

        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(15, 20, 0, 0, 0, 0, 0);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        try {
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
                    .param("password", "test")
                    .param("password_confirmation", "test")
                    .session(session)
                    .cookie(cookie)
                    .with(cookieCsrf());
            mockMvc.perform(validPost)
                    .andExpect(view().name("force_password_change"))
                    .andExpect(model().attribute("message", "Password must be at least 15 characters in length."))
                    .andExpect(model().attribute("email", user.getPrimaryEmail()));
        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }
    }

    @Test
    void force_password_when_system_was_configured() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(4, 20, 0, 0, 0, 0, 0);
        passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));

        try {
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
            validPost.with(cookieCsrf());

            mockMvc.perform(validPost)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(("/force_password_change_completed")));

            mockMvc.perform(get("/force_password_change_completed")
                    .session(session))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://localhost/"));
            assertTrue(((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication().isAuthenticated());
            assertFalse(((UaaAuthentication) ((SecurityContext) ((HttpSession) session).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).getAuthentication()).isRequiresPasswordChange());


        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
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
                .andExpect(redirectedUrl(("http://localhost/login")));
    }

}
