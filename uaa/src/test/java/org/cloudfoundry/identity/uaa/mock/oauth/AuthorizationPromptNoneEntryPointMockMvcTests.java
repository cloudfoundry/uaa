package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.SpringServletAndHoneycombTestConfig;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.OpenIdSessionStateCalculator;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class AuthorizationPromptNoneEntryPointMockMvcTests {

    private String adminToken;

    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setup() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);

        BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        client.setAutoApproveScopes(Collections.singletonList("openid"));
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.write uaa.admin");
        MockMvcUtils.createClient(mockMvc, adminToken, client);
    }

    @AfterEach
    void cleanup() throws Exception {
        MockMvcUtils.deleteClient(mockMvc, adminToken, "ant", "");
    }

    @Test
    void testSilentAuthHonorsAntRedirect_whenNotAuthenticated() throws Exception {
        MvcResult result = mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        assertThat(result.getResponse().getRedirectedUrl(), startsWith("http://example.com/with/path.html#error=login_required"));
    }

    @Test
    void silentAuthentication_clearsCurrentUserCookie_whenNotAuthenticated() throws Exception {
        MvcResult result = mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        ).andReturn();

        // This is necessary to make sure Current-User gets cleaned up when, for example, a UAA is restarted and the
        // user's JSESSIONID is no longer valid.
        assertThat(result.getResponse().getCookie("Current-User").getValue(), nullValue());
        assertThat(result.getResponse().getCookie("Current-User").getMaxAge(), equalTo(0));
    }

    @Test
    void testSilentAuthHonorsAntRedirect_whenSessionHasBeenInvalidated() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);
        session.invalidate();

        mockMvc.perform(
                get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                        .session(session)
        ).andExpect(redirectedUrlPattern("http://example.com/**/*"));
    }

    @Test
    void testSilentAuthentication_whenScopesNotAutoApproved() throws Exception {
        MockMvcUtils.deleteClient(mockMvc, adminToken, "ant", "");
        BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
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
    void testSilentAuthentication_includesSessionState() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) webApplicationContext.getBean("uaaAuthorizationEndpoint");
        OpenIdSessionStateCalculator backupCalculator = uaaAuthorizationEndpoint.getOpenIdSessionStateCalculator();
        try {
            OpenIdSessionStateCalculator calculator = mock(OpenIdSessionStateCalculator.class);

            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(calculator);
            when(calculator.calculate(anyString(), anyString(), anyString())).thenReturn("sessionhash.saltvalue");
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
            assertThat(redirectUrl, containsString("session_state=sessionhash.saltvalue"));
            verify(calculator).calculate(currentUserId, "ant", "http://example.com");

            // uaa-singular relies on the Current-User cookie. Because of GDPR, the Current-User cookie was
            // changed to expire after a relatively short time. We have to renew that cookie during each
            // call to /oauth/authorize or uaa-singular can get into an infinite loop where every open browser
            // tab relying on uaa-singular aggressively polls /oauth/authorize?prompt=none
            assertThat(result.getResponse().getCookie("Current-User").getValue(), Matchers.containsString(currentUserId));
        } finally {
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(backupCalculator);
        }
    }

    @Test
    void testSilentAuthentication_RuntimeException_displaysErrorFragment() throws Exception {
        UaaAuthorizationEndpoint uaaAuthorizationEndpoint = (UaaAuthorizationEndpoint) webApplicationContext.getBean("uaaAuthorizationEndpoint");
        OpenIdSessionStateCalculator backupCalculator = uaaAuthorizationEndpoint.getOpenIdSessionStateCalculator();
        try {
            OpenIdSessionStateCalculator openIdSessionStateCalculator = mock(OpenIdSessionStateCalculator.class);
            uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(openIdSessionStateCalculator);

            when(openIdSessionStateCalculator.calculate(anyString(), anyString(), anyString())).thenThrow(RuntimeException.class);

            MockHttpSession session = new MockHttpSession();
            login(session);

            mockMvc.perform(
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
    void testSilentAuthentication_Returns400_whenInvalidRedirectUrlIsProvided() throws Exception {
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
        assertThat(result.getResponse().getRedirectedUrl(), not(containsString("session_state")));
    }

    @Test
    void silentAuthentication_implicit_returnsSessionStateWhenLoginIsRequired() throws Exception {
        MvcResult result = mockMvc.perform(
                get("/oauth/authorize?response_type=id_token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/**")
        )
                .andReturn();
        assertThat(result.getResponse().getRedirectedUrl(), containsString("error=login_required"));
        assertThat(result.getResponse().getRedirectedUrl(), containsString("session_state"));
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
        assertThat(result.getResponse().getRedirectedUrl(), containsString("login_required"));
        assertThat(result.getResponse().getRedirectedUrl(), containsString("session_state"));
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