package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.servlet.http.Cookie;
import java.net.URLEncoder;
import java.util.Date;

import static org.mockito.Matchers.contains;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
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

    @Before
    public void setup() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);
    }

    @Test
    public void testHandleChangePasswordForUser() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

        MockHttpServletRequestBuilder invalidPost = post("/login.do")
                .param("username", user.getUserName())
                .param("password", "secret")
                .session(session)
                .cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");
        getMockMvc().perform(invalidPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/force_password_change"));

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session)
                .cookie(cookie);
        validPost.with(csrf());
        getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/")))
                .andExpect(currentUserCookie(user.getId()));
    }

    @Test
    public void testHandleChangePasswordForUserWithInvalidPassword() throws Exception {
        forcePasswordChangeForUser();
        MockHttpSession session = new MockHttpSession();
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(15,20,0,0,0,0,0);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        try {
            identityProviderProvisioning.update(identityProvider);

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
                .with(csrf());
            getMockMvc().perform(validPost)
                .andExpect(view().name("force_password_change"))
                .andExpect(model().attribute("message", "Password must be at least 15 characters in length."))
                .andExpect(model().attribute("email", user.getPrimaryEmail()));
        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider);
        }
    }

    @Test
    public void testHandleChangePasswordForSystemWideChange() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentConfig = ((UaaIdentityProviderDefinition) identityProvider.getConfig());
        PasswordPolicy passwordPolicy = new PasswordPolicy(4,20,0,0,0,0,0);
        passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
        identityProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));

        try {
            identityProviderProvisioning.update(identityProvider);
            MockHttpSession session = new MockHttpSession();
            Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

            MockHttpServletRequestBuilder invalidPost = post("/login.do")
                .param("username", user.getUserName())
                .param("password", "secret")
                .session(session).cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf1");

            getMockMvc().perform(invalidPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/force_password_change"));

            MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test")
                .session(session).cookie(cookie);
            validPost.with(csrf());

            getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/")))
                .andExpect(currentUserCookie(user.getId()));

        } finally {
            identityProvider.setConfig(currentConfig);
            identityProviderProvisioning.update(identityProvider);
        }
    }

    @Test
    public void testHandleChangePasswordForUserInvalid() throws Exception {
        forcePasswordChangeForUser();

        MockHttpServletRequestBuilder validPost = post("/force_password_change")
                .param("password", "test")
                .param("password_confirmation", "test");
        validPost.with(csrf());
        getMockMvc().perform(validPost)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(("/login")));
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

    private static ResultMatcher currentUserCookie(String userId) {
        return result -> {
            cookie().value("Current-User", URLEncoder.encode("{\"userId\":\"" + userId + "\"}", "UTF-8")).match(result);
            cookie().maxAge("Current-User", 365*24*60*60);
            cookie().path("Current-User", "").match(result);
        };
    }
}
