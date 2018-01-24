package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.OpenIdSessionStateCalculator;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuthorizationPromptNoneEntryPointMockMvcTests extends InjectedMockContextTest {

    private static boolean isInitDone = false;

    @Before
    public void setup() throws Exception {
        if(!isInitDone) {
            BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
            client.setAutoApproveScopes(Arrays.asList("openid"));
            String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                    "clients.read clients.write clients.secret clients.admin uaa.admin");
            MockMvcUtils.createClient(getMockMvc(), adminToken, client);
            isInitDone = true;
        }
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenNotAuthenticated() throws Exception {
        getMockMvc().perform(
            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
        )
        .andExpect(redirectedUrl("http://example.com/with/path.html#error=login_required"));
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenAuthenticated() throws Exception {
        MockHttpSession session = new MockHttpSession();
        login(session);
        session.invalidate();

        getMockMvc().perform(
            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                .session(session)
        )
        .andExpect(redirectedUrlPattern("http://example.com/**/*"));
    }

    @Test
    public void testSessionStateIsCorrect() throws Exception {
        SecureRandom secureRandom = mock(SecureRandom.class);
        doNothing().when(secureRandom).nextBytes(any());

        OpenIdSessionStateCalculator sessionStateCalculator
                = (OpenIdSessionStateCalculator)getWebApplicationContext().getBean("openIdSessionStateCalculator");
        sessionStateCalculator.setSecureRandom(secureRandom);

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
        Assert.assertThat(redirectUrl, Matchers.containsString("session_state=707c310bc5aa38acc03d48a099fc999cd77f44df163178df1ca35863913f5711.0000000000000000000000000000000000000000000000000000000000000000"));
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