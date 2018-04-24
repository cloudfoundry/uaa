package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.OpenIdSessionStateCalculator;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuthorizationPromptNoneEntryPointMockMvcTests extends InjectedMockContextTest {

    private String adminToken;

    @Before
    public void setup() throws Exception {
        BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        client.setAutoApproveScopes(Arrays.asList("openid"));
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.write uaa.admin");
        MockMvcUtils.createClient(getMockMvc(), adminToken, client);
    }

    @After
    public void cleanup() throws Exception {
        MockMvcUtils.deleteClient(getMockMvc(), adminToken, "ant", "");
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenNotAuthenticated() throws Exception {
        MvcResult result = getMockMvc().perform(
          get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        assertThat(result.getResponse().getRedirectedUrl(), startsWith("http://example.com/with/path.html#error=login_required"));
    }

    @Test
    public void silentAuthentication_clearsCurrentUserCookie_whenNotAuthenticated() throws Exception {
        MvcResult result = getMockMvc().perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        // This is necessary to make sure Current-User gets cleaned up when, for example, a UAA is restarted and the
        // user's JSESSIONID is no longer valid.
        assertThat(result.getResponse().getCookie("Current-User").getValue(), nullValue());
        assertThat(result.getResponse().getCookie("Current-User").getMaxAge(), equalTo(0));
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenSessionHasBeenInvalidated() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);
        session.invalidate();

        getMockMvc().perform(
          get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
            .session(session)
        ).andExpect(redirectedUrlPattern("http://example.com/**/*"));
    }

    @Test
    public void testSilentAuthentication_whenScopesNotAutoapproved() throws Exception {
        MockMvcUtils.deleteClient(getMockMvc(), adminToken, "ant", "");
        BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        MockMvcUtils.createClient(getMockMvc(), adminToken, client);

        MockHttpSession session = new MockHttpSession();
        login(session);

        getMockMvc().perform(
          get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
            .session(session)
        )
          .andExpect(redirectedUrl("http://example.com/with/path.html#error=interaction_required"));
    }

    @Test
    public void testSilentAuthentication_includesSessionState() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) getWebApplicationContext().getBean("uaaAuthorizationEndpoint");
        OpenIdSessionStateCalculator backupCalculator = uaaAuthorizationEndpoint.getOpenIdSessionStateCalculator();
        try {
            OpenIdSessionStateCalculator calculator = mock(OpenIdSessionStateCalculator.class);

            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(calculator);
            when(calculator.calculate(anyString(), anyString(), anyString())).thenReturn("sessionhash.saltvalue");
            String currentUserId = MockMvcUtils.getUserByUsername(getMockMvc(), "marissa", adminToken).getId();

            //we need to know session id when we are calculating session_state
            MockHttpSession session = new MockHttpSession(null, "12345") {
                public String changeSessionId() {
                    return "12345";
                }
            };
            login(session);

            MvcResult result = getMockMvc().perform(
              get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                .session(session)
            )
              .andExpect(status().isFound())
              .andReturn();

            String redirectUrl = result.getResponse().getRedirectedUrl();
            Assert.assertThat(redirectUrl, containsString("session_state=sessionhash.saltvalue"));
            verify(calculator).calculate(currentUserId, "ant", "http://example.com");

            // uaa-singular relies on the Current-User cookie. Because of GDPR, the Current-User cookie was
            // changed to expire after a relatively short time. We have to renew that cookie during each
            // call to /oauth/authorize or uaa-singular can get into an infinite loop where every open browser
            // tab relying on uaa-singular aggressively polls /oauth/authorize?prompt=none
            Assert.assertThat(result.getResponse().getCookie("Current-User").getValue(), Matchers.containsString(currentUserId));
        } finally {
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(backupCalculator);
        }
    }

    @Test
    public void testSilentAuthentication_RuntimeException_displaysErrorFragment() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) getWebApplicationContext().getBean("uaaAuthorizationEndpoint");
        OpenIdSessionStateCalculator backupCalculator = uaaAuthorizationEndpoint.getOpenIdSessionStateCalculator();
        try {
            OpenIdSessionStateCalculator openIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(openIdSessionStateCalculator);

            when(openIdSessionStateCalculator.calculate(anyString(), anyString(), anyString())).thenThrow(RuntimeException.class);

            MockHttpSession session = new MockHttpSession();
            login(session);

            getMockMvc().perform(
              get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                .session(session)
            )
              .andExpect(status().is3xxRedirection())
              .andExpect(redirectedUrl("http://example.com/with/path.html#error=internal_server_error"));
        } finally {
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(backupCalculator);
        }
    }

    @Test
    public void testSilentAuthentication_Returns400_whenInvalidRedirectUrlIsProvided() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);

        getMockMvc().perform(
          get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=no good uri")
            .session(session)
        )
          .andExpect(status().is4xxClientError());
    }

    @Test
    public void nonSilentAuthentication_doesNotComputeSessionState() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);

        MvcResult result = getMockMvc().perform(
          get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&redirect_uri=http://example.com/with/path.html")
            .session(session)
        )
          .andReturn();
        Assert.assertThat(result.getResponse().getRedirectedUrl(), not(containsString("session_state")));
    }

    @Test
    public void silentAuthentication_implicit_returnsSessionStateWhenLoginIsRequired() throws Exception {
        MvcResult result = getMockMvc().perform(
          get("/oauth/authorize?response_type=id_token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/**")
        )
          .andReturn();
        Assert.assertThat(result.getResponse().getRedirectedUrl(), containsString("error=login_required"));
        Assert.assertThat(result.getResponse().getRedirectedUrl(), containsString("session_state"));
    }

    @Test
    public void silentAuthentication_withBadClientId() throws Exception {
        getMockMvc().perform(
          get("/oauth/authorize?response_type=id_token&scope=openid&client_id=bogus&prompt=none&redirect_uri=http://example.com/**")
        ).andExpect(status().isBadRequest());
    }

    @Test
    public void silentAuthentication_withoutClientId() throws Exception {
        getMockMvc().perform(
          get("/oauth/authorize?response_type=id_token&scope=openid&prompt=none&redirect_uri=http://example.com/**")
        ).andExpect(status().isBadRequest());
    }

    @Test
    public void silentAuthentication_notImplicit_returnsSessionStateWhenLoginIsRequired() throws Exception {
        MvcResult result = getMockMvc().perform(
          get("/oauth/authorize?response_type=code&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/**")
        )
          .andReturn();
        Assert.assertThat(result.getResponse().getRedirectedUrl(), containsString("login_required"));
        Assert.assertThat(result.getResponse().getRedirectedUrl(), containsString("session_state"));
    }


    private void login(MockHttpSession session) throws Exception {
        getMockMvc().perform(
          post("/login.do")
            .with(cookieCsrf())
            .param("username", "marissa")
            .param("password", "koala")
            .session(session)
        ).andExpect(redirectedUrl("/"));
    }
}