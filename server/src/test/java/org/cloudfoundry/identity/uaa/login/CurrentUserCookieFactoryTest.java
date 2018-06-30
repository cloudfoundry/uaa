package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import java.net.URLDecoder;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;

public class CurrentUserCookieFactoryTest {

    private CurrentUserCookieFactory factory;
    private int sessionTimeout;
    private HttpServletRequest request;
    private UaaPrincipal uaaPrincipal;
    private String username;
    private String email;

    @Before
    public void setup() {
        sessionTimeout = 1234;
        request = new MockHttpServletRequest("GET", "https://uaa.somesystemdomain.com/oauth/authorize");
        ((MockHttpServletRequest) request).setContextPath("/oauth/authorize");
        username = "marissa";
        email = "marissa@test.org";
        uaaPrincipal = new UaaPrincipal("user-guid", username, email, "uaa", "", "uaa");
        factory = new CurrentUserCookieFactory(sessionTimeout);
    }

    @Test
    public void getCookie_returnsCookieWithNameCurrentUser() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertEquals("Current-User", cookie.getName());
    }

    @Test
    public void getCookie_returnsCookieMaxAgeEqualToSessionTimeout() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertEquals(sessionTimeout, cookie.getMaxAge());
    }

    @Test
    public void getCookie_setsContextPath() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertEquals("/", cookie.getPath());
    }

    @Test
    public void getCookie_containsUrlEncodedJsonBody() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertEquals("%7B%22userId%22%3A%22user-guid%22%7D", cookie.getValue());
        String decoded = URLDecoder.decode(cookie.getValue(), "UTF-8");
        JsonNode parsedCookie = JsonUtils.readTree(decoded);
        assertEquals("\"user-guid\"", parsedCookie.get("userId").toString());
    }

    @Test
    public void getNullCookie() {
        Cookie cookie = factory.getNullCookie();

        assertEquals("Current-User", cookie.getName());
        assertFalse(cookie.isHttpOnly());
        assertEquals(0, cookie.getMaxAge());
        assertEquals("/", cookie.getPath());
    }

    @Test
    public void getCookie_doesNotIncludePersonallyIdentifiableInformation() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getValue(), not(containsString(username)));
        assertThat(cookie.getValue(), not(containsString(email)));
    }

    @Test
    public void getCookie_isNotHttpOnlyBecauseSingularReadsFromBrowserJS() throws Exception {
        // JavaScript running on the UAA's session_management page will not be able to interact with this
        // cookie if httpOnly is enabled.

        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertFalse(cookie.isHttpOnly());
    }

}