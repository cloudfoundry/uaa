package org.cloudfoundry.identity.uaa.login;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.util.Date;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.performMfaRegistrationInZone;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class ForcePasswordChangeControllerMockMvcTest extends InjectedMockContextTest {
    private ScimUser user;
    private String token;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private String adminToken;
    private MfaProvider mfaProvider;

    @Before
    public void setup() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), "uaa");
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "uaa.admin"
        );
        mfaProvider = MockMvcUtils.createMfaProvider(getWebApplicationContext(), IdentityZone.getUaa());
    }

    @After
    public void cleanup () throws Exception {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);
    }

    @Test
    public void force_password_change_when_mfa_is_enabled() throws Exception {
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);
        forcePasswordChangeForUser();
        //force_password_change_happy_path();
        ResultActions actions = performMfaRegistrationInZone(
            user.getUserName(),
            "secret",
            getMockMvc(),
            "localhost",
            new String[]{"pwd"},
            new String[]{"pwd", "mfa", "otp"}
        );
        actions
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/force_password_change"));
        completePasswordChange((MockHttpSession) actions.andReturn().getRequest().getSession(false));
    }

    @Test
    public void force_password_change_happy_path() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();

        MockHttpServletRequestBuilder invalidPost = post("/login.do")
            .param("username", user.getUserName())
            .param("password", "secret")
            .session(session)
            .with(cookieCsrf())
            .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
        getMockMvc().perform(invalidPost)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertTrue(getUaaAuthentication(session).isRequiresPasswordChange());

        getMockMvc().perform(get("/")
            .session(session))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/force_password_change"));

        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertTrue(getUaaAuthentication(session).isRequiresPasswordChange());

        completePasswordChange(session);

    }

    public void completePasswordChange(MockHttpSession session) throws Exception {
        MockHttpServletRequestBuilder validPost = post("/force_password_change")
            .param("password", "test")
            .param("password_confirmation", "test")
            .session(session)
            .with(cookieCsrf());
        validPost.with(cookieCsrf());
        getMockMvc().perform(validPost)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(("/force_password_change_completed")));
        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());

        getMockMvc().perform(get("/force_password_change_completed")
            .session(session))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/"));
        assertTrue(getUaaAuthentication(session).isAuthenticated());
        assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());
    }

    private UaaAuthentication getUaaAuthentication(HttpSession session) {
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        return (UaaAuthentication) context.getAuthentication();
    }

    @Test
    public void force_password_change_with_invalid_password() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(15,20,0,0,0,0,0);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        try {
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

            MockHttpServletRequestBuilder invalidPost = post("/login.do")
                .param("username", user.getUserName())
                .param("password", "secret")
                .session(session)
                .cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
            getMockMvc().perform(invalidPost)
                .andExpect(status().isFound());

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .cookie(cookie)
                .with(cookieCsrf());
            getMockMvc().perform(validPost)
                .andExpect(view().name("force_password_change"))
                .andExpect(model().attribute("message", "Password must be at least 15 characters in length."))
                .andExpect(model().attribute("email", user.getPrimaryEmail()));
        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }
    }

    @Test
    public void force_password_when_system_was_configured() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(4,20,0,0,0,0,0);
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

            getMockMvc().perform(invalidPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));

            getMockMvc().perform(
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

            getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/force_password_change_completed")));

            getMockMvc().perform(get("/force_password_change_completed")
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/"));
            assertTrue(getUaaAuthentication(session).isAuthenticated());
            assertFalse(getUaaAuthentication(session).isRequiresPasswordChange());



        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        }
    }

    @Test
    public void submit_password_change_when_not_authenticated() throws Exception {
        forcePasswordChangeForUser();

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test");
        validPost.with(cookieCsrf());
        getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("http://localhost/login")));
    }

    private void forcePasswordChangeForUser() throws Exception {
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        String jsonStatus = JsonUtils.writeValueAsString(userAccountStatus);
        getMockMvc().perform(
            patch("/Users/"+user.getId()+"/status")
                .header("Authorization", "Bearer "+token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(jsonStatus))
            .andExpect(status().isOk());
    }
}
