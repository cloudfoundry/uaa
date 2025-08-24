package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.http.Cookie;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class CurrentUserCookieFactoryTest {

    private CurrentUserCookieFactory factory;
    private int sessionTimeout;
    private UaaPrincipal uaaPrincipal;
    private String username;
    private String email;

    @BeforeEach
    void setup() {
        sessionTimeout = 1234;
        MockHttpServletRequest request = new MockHttpServletRequest("GET",
                "https://uaa.somesystemdomain.com/oauth/authorize");
        request.setContextPath("/oauth/authorize");
        username = "marissa";
        email = "marissa@test.org";
        uaaPrincipal = new UaaPrincipal("user-guid", username, email, "uaa", "", "uaa");
        factory = new CurrentUserCookieFactory(sessionTimeout, false);
    }

    @Test
    void getCookie_returnsCookieWithNameCurrentUser() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getName()).isEqualTo("Current-User");
    }

    @Test
    void getCookie_returnsCookieMaxAgeEqualToSessionTimeout() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getMaxAge()).isEqualTo(sessionTimeout);
    }

    @Test
    void getCookie_setsContextPath() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getPath()).isEqualTo("/");
    }

    @Test
    void getCookie_containsUrlEncodedJsonBody() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getValue()).isEqualTo("%7B%22userId%22%3A%22user-guid%22%7D");
        String decoded = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
        JsonNode parsedCookie = JsonUtils.readTree(decoded);
        assertThat(parsedCookie.get("userId")).hasToString("\"user-guid\"");
    }

    @Test
    void getNullCookie() {
        Cookie cookie = factory.getNullCookie();

        assertThat(cookie.getName()).isEqualTo("Current-User");
        assertThat(cookie.isHttpOnly()).isFalse();
        assertThat(cookie.getMaxAge()).isZero();
        assertThat(cookie.getPath()).isEqualTo("/");
    }

    @Test
    void getCookie_doesNotIncludePersonallyIdentifiableInformation() throws Exception {
        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.getValue()).doesNotContain(username)
                .doesNotContain(email);
    }

    @Test
    void getCookie_isNotHttpOnlyBecauseSingularReadsFromBrowserJS() throws Exception {
        // JavaScript running on the UAA's session_management page will not be able to interact with this
        // cookie if httpOnly is enabled.

        Cookie cookie = factory.getCookie(uaaPrincipal);
        assertThat(cookie.isHttpOnly()).isFalse();
    }
}
