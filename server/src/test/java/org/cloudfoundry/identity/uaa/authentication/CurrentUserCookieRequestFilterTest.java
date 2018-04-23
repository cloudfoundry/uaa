package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.login.CurrentUserCookieFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class CurrentUserCookieRequestFilterTest {

    private CurrentUserCookieRequestFilter filter;
    private CurrentUserCookieFactory currentUserCookieFactory;

    @Before
    public void setup() {
        currentUserCookieFactory = mock(CurrentUserCookieFactory.class);
        filter = new CurrentUserCookieRequestFilter(currentUserCookieFactory);
    }

    @After
    public void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void whenUserIsAuthenticated_addsCurrentUserCookie() throws ServletException, IOException, CurrentUserCookieFactory.CurrentUserCookieEncodingException {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        FilterChain filterChain = mock(FilterChain.class);
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        when(currentUserCookieFactory.getCookie(eq(req), any(UaaPrincipal.class))).thenReturn(new Cookie("Current-User", "current-user-cookie-value"));

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getCookie("Current-User").getValue(), equalTo("current-user-cookie-value"));
        verify(filterChain).doFilter(req, res);
    }

    @Test
    public void whenUserIsNotAuthenticated_clearsCurrentUserCookie() throws IOException, ServletException {
        FilterChain filterChain = mock(FilterChain.class);
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        when(currentUserCookieFactory.getNullCookie(eq(req))).thenReturn(new Cookie("Current-User", null));

        filter.doFilterInternal(req, res, filterChain);

        assertThat(res.getCookie("Current-User").getValue(), nullValue());
        verify(filterChain).doFilter(req, res);
    }

    @Test
    public void whenCurrentUserExceptionOccurs_respondWithInternalServerError() throws CurrentUserCookieFactory.CurrentUserCookieEncodingException, ServletException, IOException {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        FilterChain filterChain = mock(FilterChain.class);
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        when(currentUserCookieFactory.getCookie(eq(req), any(UaaPrincipal.class))).thenThrow(currentUserCookieFactory.new CurrentUserCookieEncodingException(null));

        filter.doFilterInternal(req, res, filterChain);

        assertEquals(500, res.getStatus());
        assertEquals("application/json", res.getContentType());
        assertThat(JsonUtils.readTree(res.getContentAsString()).get("error").textValue(), equalTo("current_user_cookie_error"));
        assertThat(JsonUtils.readTree(res.getContentAsString()).get("error_description").textValue(), equalTo("There was a problem while creating the Current-User cookie for user id user-guid"));
        verifyZeroInteractions(filterChain);
    }
}