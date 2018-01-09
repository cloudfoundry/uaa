package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

public class AuthorizePromptNoneEntryPointMockMvcTests  extends InjectedMockContextTest {

    private static String adminToken;
    private static boolean isInitDone = false;

    @Before
    public void setup() throws Exception {
        if(!isInitDone) {
            BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
            adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                    "clients.read clients.write clients.secret clients.admin uaa.admin");
            MockMvcUtils.createClient(getMockMvc(), adminToken, client);
            isInitDone = true;
        }
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenNotAuthenticated() throws Exception {
        getMockMvc().perform(
            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
               .header("Authorization", "Bearer " + adminToken)
        )
        .andExpect(redirectedUrl("http://example.com/with/path.html#error=login_required"));
    }

    @Test
    public void testSilentAuthHonorsAntRedirect_whenAuthenticated() throws Exception {
        MockHttpSession session = new MockHttpSession();
        getMockMvc().perform(
            post("/login.do")
                .with(cookieCsrf())
                .param("username", "marissa")
                .param("password", "koala")
                .session(session)
        ).andExpect(redirectedUrl("/"));
        getMockMvc().perform(
            get("/oauth/authorize?response_type=token&scope=openid&client_id=ant&prompt=none&redirect_uri=http://example.com/with/path.html")
                .session(session)
                .header("Authorization", "Bearer " + adminToken)
        )
        .andExpect(redirectedUrl("http://example.com/with/path.html#error=interaction_required"));
    }
}