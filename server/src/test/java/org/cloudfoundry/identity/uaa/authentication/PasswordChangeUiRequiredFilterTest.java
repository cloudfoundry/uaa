package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class PasswordChangeUiRequiredFilterTest {

    private MockHttpServletRequest mockHttpServletRequest;

    @Mock
    private UaaSavedRequestCache mockRequestCache;

    @Mock
    private UaaAuthentication mockUaaAuthentication;

    @Mock
    private HttpServletResponse mockHttpServletResponse;

    @Mock
    private FilterChain mockFilterChain;

    @InjectMocks
    private PasswordChangeUiRequiredFilter passwordChangeUiRequiredFilter;

    @BeforeEach
    void setUp() {
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setContextPath("");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void notAuthenticated() throws Exception {
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }

    @Test
    void authenticated() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, false);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }

    @Test
    void authenticatedPasswordExpired() throws Exception {
        mockHttpServletRequest.setPathInfo("/oauth/authorize");
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, true);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockHttpServletResponse, times(1)).sendRedirect("/force_password_change");
        verify(mockRequestCache, times(1)).saveRequest(any(), any());
    }

    @Test
    void loadingChangePasswordPage() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change");
        mockHttpServletRequest.setMethod(HttpMethod.GET.name());
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, true);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verify(mockHttpServletResponse, never()).sendRedirect(anyString());
    }

    @Test
    void submitChangePassword() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change");
        mockHttpServletRequest.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, true);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
        verify(mockHttpServletResponse, never()).sendRedirect(anyString());
    }

    @Test
    void followCompletedRedirect() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change_completed");
        mockHttpServletRequest.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, false);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockHttpServletResponse, times(1)).sendRedirect("/");
    }

    @Test
    void followCompletedRedirectWithSavedRequest() throws Exception {
        String location = "/oauth/authorize";
        SavedRequest savedRequest = getSavedRequest(location);
        when(mockRequestCache.getRequest(any(), any())).thenReturn(savedRequest);
        mockHttpServletRequest.setPathInfo("/force_password_change_completed");
        mockHttpServletRequest.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, false);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockHttpServletResponse, times(1)).sendRedirect(location);
    }

    @Test
    void tryingAccessForcePasswordPage() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change");
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, false);
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockHttpServletResponse, times(1)).sendRedirect("/");
    }

    @Test
    void tryingAccessForcePasswordPageNotAuthenticated() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change");
        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }

    @Test
    void completedButStillRequiresChange() throws Exception {
        mockHttpServletRequest.setPathInfo("/force_password_change_completed");
        mockHttpServletRequest.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        setRequiresPasswordChange(mockHttpServletRequest, true);

        passwordChangeUiRequiredFilter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);

        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockHttpServletResponse, times(1)).sendRedirect("/force_password_change");
    }

    private SavedRequest getSavedRequest(final String redirectUrl) {
        return new SavedRequest() {
            @Override
            public String getRedirectUrl() {
                return redirectUrl;
            }

            @Override
            public List<Cookie> getCookies() {
                return null;
            }

            @Override
            public String getMethod() {
                return null;
            }

            @Override
            public List<String> getHeaderValues(String name) {
                return null;
            }

            @Override
            public Collection<String> getHeaderNames() {
                return null;
            }

            @Override
            public List<Locale> getLocales() {
                return null;
            }

            @Override
            public String[] getParameterValues(String name) {
                return new String[0];
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return null;
            }
        };
    }

    private void setRequiresPasswordChange(MockHttpServletRequest request, boolean requiresPasswordChange) {
        MockHttpSession httpSession = new MockHttpSession();
        SessionUtils.setPasswordChangeRequired(httpSession, requiresPasswordChange);
        request.setSession(httpSession);
    }
}