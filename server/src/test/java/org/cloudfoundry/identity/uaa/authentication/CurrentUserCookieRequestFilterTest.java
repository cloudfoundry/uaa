package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.login.CurrentUserCookieFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CurrentUserCookieRequestFilterTest {

    private CurrentUserCookieRequestFilter filter;
    private CurrentUserCookieFactory currentUserCookieFactory;
    private FilterChain filterChain;
    private MockHttpServletRequest req;
    private MockHttpServletResponse res;

    @BeforeEach
    void setup() {
        SecurityContextHolder.clearContext();
        currentUserCookieFactory = mock(CurrentUserCookieFactory.class);
        filterChain = mock(FilterChain.class);
        req = new MockHttpServletRequest();
        res = new MockHttpServletResponse();
        filter = new CurrentUserCookieRequestFilter(currentUserCookieFactory);
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void whenUserIsAuthenticated_addsCurrentUserCookie() throws ServletException, IOException, CurrentUserCookieFactory.CurrentUserCookieEncodingException {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Cookie mockCookie = new Cookie("Current-User", "current-user-cookie-value");
        mockCookie.setPath("/some-path");
        mockCookie.setHttpOnly(false);
        mockCookie.setSecure(true);
        mockCookie.setMaxAge(47);
        when(currentUserCookieFactory.getCookie(Mockito.any(UaaPrincipal.class))).thenReturn(mockCookie);

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getCookie("Current-User").getValue()).isEqualTo("current-user-cookie-value");
        String setCookieHeaderValue = res.getHeader("Set-Cookie");
        assertThat(setCookieHeaderValue).contains("Path=/some-path")
                .contains("Max-Age=47")
                .contains("SameSite=Strict");
        verify(filterChain).doFilter(req, res);
    }

    @Test
    void whenUserIsAuthenticated_addsCurrentUserCookieWithStrictSameSiteAttribute() throws ServletException, IOException, CurrentUserCookieFactory.CurrentUserCookieEncodingException {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(currentUserCookieFactory.getCookie(Mockito.any(UaaPrincipal.class))).thenReturn(new Cookie("Current-User", "current-user-cookie-value"));

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getHeader("Set-Cookie")).isEqualTo("Current-User=current-user-cookie-value; SameSite=Strict");
        verify(filterChain).doFilter(req, res);
    }

    @Test
    void whenUserIsNotAuthenticated_clearsCurrentUserCookie() throws IOException, ServletException {
        when(currentUserCookieFactory.getNullCookie()).thenReturn(new Cookie("Current-User", null));

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getCookie("Current-User").getValue()).isNull();
        verify(filterChain).doFilter(req, res);
    }

    @Test
    void whenCurrentUserExceptionOccurs_respondWithInternalServerError() throws CurrentUserCookieFactory.CurrentUserCookieEncodingException, ServletException, IOException {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(currentUserCookieFactory.getCookie(Mockito.any(UaaPrincipal.class))).thenThrow(currentUserCookieFactory.new CurrentUserCookieEncodingException(null));

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getStatus()).isEqualTo(500);
        assertThat(res.getContentType()).isEqualTo("application/json");
        assertThat(JsonUtils.readTree(res.getContentAsString()).get("error").textValue()).isEqualTo("current_user_cookie_error");
        assertThat(JsonUtils.readTree(res.getContentAsString()).get("error_description").textValue()).isEqualTo("There was a problem while creating the Current-User cookie for user id user-guid");
        verifyNoInteractions(filterChain);
    }
}