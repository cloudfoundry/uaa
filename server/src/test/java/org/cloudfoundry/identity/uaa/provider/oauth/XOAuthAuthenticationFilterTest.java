package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class XOAuthAuthenticationFilterTest {

    @Mock
    private AccountSavingAuthenticationSuccessHandler mockAccountSavingAuthenticationSuccessHandler;
    @Mock
    private XOAuthAuthenticationManager mockXOAuthAuthenticationManager;
    @InjectMocks
    private XOAuthAuthenticationFilter filter;

    @BeforeEach
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticate() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        shouldAuthenticate(filter, request, "code");
        shouldAuthenticate(filter, request, "id_token");
        shouldAuthenticate(filter, request, "access_token");
    }

    private static void shouldAuthenticate(
            final XOAuthAuthenticationFilter filter,
            final MockHttpServletRequest request,
            final String pname) {
        assertFalse(filter.containsCredentials(request));
        request.setParameter(pname, "value");
        assertTrue(filter.containsCredentials(request));
        request.removeParameter(pname);
        assertFalse(filter.containsCredentials(request));
    }

    @Test
    void getIdTokenInResponse() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getParameter(anyString())).thenReturn(null);
        when(request.getParameter("id_token")).thenReturn("the_id_token");
        when(request.getParameter("access_token")).thenReturn("the_access_token");
        when(request.getParameter("code")).thenReturn("the_code");

        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("id", "username", "email@email.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId()), emptyList(), new UaaAuthenticationDetails(request));
        Mockito.when(mockXOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(mockXOAuthAuthenticationManager).authenticate(captor.capture());
        verify(chain).doFilter(request, response);

        XOAuthCodeToken xoAuthCodeToken = captor.getValue();
        assertEquals("the_access_token", xoAuthCodeToken.getAccessToken());
        assertEquals("the_id_token", xoAuthCodeToken.getIdToken());
        assertEquals("the_code", xoAuthCodeToken.getCode());
        assertEquals("the_origin", xoAuthCodeToken.getOrigin());
        assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void getXOAuthCodeTokenFromRequest() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getParameter(anyString())).thenReturn(null);
        when(request.getParameter("code")).thenReturn("the_code");

        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("id", "username", "email@email.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId()), emptyList(), new UaaAuthenticationDetails(request));
        Mockito.when(mockXOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(mockXOAuthAuthenticationManager).authenticate(captor.capture());
        verify(chain).doFilter(request, response);

        XOAuthCodeToken xoAuthCodeToken = captor.getValue();
        assertEquals("the_code", xoAuthCodeToken.getCode());
        assertEquals("the_origin", xoAuthCodeToken.getOrigin());
        assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        assertNull(xoAuthCodeToken.getIdToken());
        assertNull(xoAuthCodeToken.getAccessToken());
    }

    @Test
    void redirectsToErrorPageInCaseOfException() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getParameter(anyString())).thenReturn(null);
        when(request.getParameter("code")).thenReturn("the_code");

        Mockito.doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "error from oauth server")).when(mockXOAuthAuthenticationManager).authenticate(any());
        filter.doFilter(request, response, chain);
        assertThat(response.getHeader("Location"), Matchers.containsString(request.getContextPath() + "/oauth_error?error=There+was+an+error+when+authenticating+against+the+external+identity+provider%3A"));
    }
}
