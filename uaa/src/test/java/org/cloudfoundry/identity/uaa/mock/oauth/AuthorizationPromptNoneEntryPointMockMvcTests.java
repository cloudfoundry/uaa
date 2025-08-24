package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.OpenIdSessionStateCalculator;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class AuthorizationPromptNoneEntryPointMockMvcTests {

    private String adminToken;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setup() throws Exception {
        TestClient testClient = new TestClient(mockMvc);

        UaaClientDetails client = new UaaClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        client.setAutoApproveScopes(Collections.singletonList("openid"));
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.write uaa.admin");
        MockMvcUtils.createClient(mockMvc, adminToken, client);
    }

    @AfterEach
    void cleanup() throws Exception {
        MockMvcUtils.deleteClient(mockMvc, adminToken, "ant", "");
    }

    @Test
    void silentAuthHonorsAntRedirectWhenNotAuthenticated() throws Exception {
        MvcResult result = mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).startsWith("http://example.com/with/path.html#error=login_required");
    }

    @Test
    void silentAuthentication_clearsCurrentUserCookie_whenNotAuthenticated() throws Exception {
        MvcResult result = mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        // This is necessary to make sure Current-User gets cleaned up when, for example, a UAA is restarted and the
        // user's JSESSIONID is no longer valid.
        assertThat(result.getResponse().getCookie("Current-User").getValue()).isNull();
        assertThat(result.getResponse().getCookie("Current-User").getMaxAge()).isZero();
    }

    @Test
    void silentAuthHonorsAntRedirectWhenSessionHasBeenInvalidated() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);
        session.invalidate();

        mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                        .session(session)
        ).andExpect(redirectedUrlPattern("http://example.com/**/*"));
    }

    @Test
    void silentAuthenticationWhenScopesNotAutoApproved() throws Exception {
        MockMvcUtils.deleteClient(mockMvc, adminToken, "ant", "");
        UaaClientDetails client = new UaaClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        MockMvcUtils.createClient(mockMvc, adminToken, client);

        MockHttpSession session = new MockHttpSession();
        login(session);

        mockMvc.perform(
                        get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                                .session(session)
                )
                .andExpect(redirectedUrl("http://example.com/with/path.html#error=interaction_required"));
    }

    @Test
    void silentAuthenticationIncludesSessionState() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) webApplicationContext.getBean("uaaAuthorizationEndpoint");
        try {
            OpenIdSessionStateCalculator mockOpenIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(mockOpenIdSessionStateCalculator);
            when(mockOpenIdSessionStateCalculator.calculate(anyString(), anyString(), anyString())).thenReturn("sessionhash.saltvalue");
            String currentUserId = MockMvcUtils.getUserByUsername(mockMvc, "marissa", adminToken).getId();

            //we need to know session id when we are calculating session_state
            MockHttpSession session = new MockHttpSession(null, "12345") {
                public String changeSessionId() {
                    return "12345";
                }
            };
            login(session);

            MvcResult result = mockMvc.perform(
                            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                                    .session(session)
                    )
                    .andExpect(status().isFound())
                    .andReturn();

            String redirectUrl = result.getResponse().getRedirectedUrl();
            assertThat(redirectUrl).contains("session_state=sessionhash.saltvalue");
            verify(mockOpenIdSessionStateCalculator).calculate(currentUserId, "ant", "http://example.com");

            // uaa-singular relies on the Current-User cookie. Because of GDPR, the Current-User cookie was
            // changed to expire after a relatively short time. We have to renew that cookie during each
            // call to /oauth/authorize or uaa-singular can get into an infinite loop where every open browser
            // tab relying on uaa-singular aggressively polls /oauth/authorize?prompt=none
            assertThat(result.getResponse().getCookie("Current-User").getValue()).contains(currentUserId);
        } finally {
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(new OpenIdSessionStateCalculator());
        }
    }

    @Test
    void silentAuthenticationRuntimeExceptionDisplaysErrorFragment() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) webApplicationContext.getBean("uaaAuthorizationEndpoint");
        try {
            OpenIdSessionStateCalculator mockOpenIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(mockOpenIdSessionStateCalculator);

            when(mockOpenIdSessionStateCalculator.calculate(anyString(), anyString(), anyString())).thenThrow(RuntimeException.class);

            MockHttpSession session = new MockHttpSession();
            login(session);

            mockMvc.perform(
                            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                                    .session(session)
                    )
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("http://example.com/with/path.html#error=internal_server_error"));
        } finally {
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(new OpenIdSessionStateCalculator());
        }
    }

    @Test
    void silentAuthenticationReturns400WhenInvalidRedirectUrlIsProvided() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);

        mockMvc.perform(
                        get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=no good uri")
                                .session(session)
                )
                .andExpect(status().is4xxClientError());
    }

    @Test
    void nonSilentAuthentication_doesNotComputeSessionState() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);

        MvcResult result = mockMvc.perform(
                        get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&redirect_uri=http://example.com/with/path.html")
                                .session(session)
                )
                .andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("session_state");
    }

    @Test
    void silentAuthentication_implicit_returnsSessionStateWhenLoginIsRequired() throws Exception {
        MvcResult result = mockMvc.perform(
                        get("/oauth/authorize?response_type=id_token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/**")
                )
                .andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).contains("error=login_required");
        assertThat(result.getResponse().getRedirectedUrl()).contains("session_state");
    }

    @Test
    void silentAuthentication_withBadClientId() throws Exception {
        mockMvc.perform(
                get("/oauth/authorize?response_type=id_token&scope=openid&client_id=bogus&prompt=none&redirect_uri=http://example.com/**")
        ).andExpect(status().isBadRequest());
    }

    @Test
    void silentAuthentication_withoutClientId() throws Exception {
        mockMvc.perform(
                get("/oauth/authorize?response_type=id_token&scope=openid&prompt=none&redirect_uri=http://example.com/**")
        ).andExpect(status().isBadRequest());
    }

    @Test
    void silentAuthentication_notImplicit_returnsSessionStateWhenLoginIsRequired() throws Exception {
        MvcResult result = mockMvc.perform(
                        get("/oauth/authorize?response_type=code&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/**")
                )
                .andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).contains("login_required");
        assertThat(result.getResponse().getRedirectedUrl()).contains("session_state");
    }

    private void login(MockHttpSession session) throws Exception {
        mockMvc.perform(
                post("/login.do")
                        .with(cookieCsrf())
                        .param("username", "marissa")
                        .param("password", "koala")
                        .session(session)
        ).andExpect(redirectedUrl("/"));
    }
}