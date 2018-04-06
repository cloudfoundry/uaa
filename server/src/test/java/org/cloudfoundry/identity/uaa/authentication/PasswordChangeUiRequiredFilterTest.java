package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class PasswordChangeUiRequiredFilterTest {


    private PasswordChangeUiRequiredFilter filter;
    private RequestCache cache;
    private UaaAuthentication authentication;
    private MockHttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @Before
    public void setup() {
        cache = mock(RequestCache.class);
        filter = new PasswordChangeUiRequiredFilter(
            "/force_password_change",
            cache,
            "/login/mfa/**"
        );

        authentication = mock(UaaAuthentication.class);
        request = new MockHttpServletRequest();
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        request.setContextPath("");
    }

    @After
    public void clear () {
        SecurityContextHolder.clearContext();
    }


    @Test
    public void isIgnored() throws Exception {
        for (String s : Arrays.asList("/login/mfa", "/login/mfa/register", "/login/mfa/verify.do")) {
            request.setPathInfo(s);
            assertTrue("Is ignored:"+s, filter.isIgnored(request, response));
        }
    }

    @Test
    public void request_to_mfa() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(true);
        request.setPathInfo("/login/mfa/register");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyZeroInteractions(response);
        verifyZeroInteractions(cache);
    }

    @Test
    public void not_authenticated() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void authenticated() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(false);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void authenticated_password_expired() throws Exception {
        request.setPathInfo("/oauth/authorize");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(true);
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendRedirect("/force_password_change");
        verify(cache, times(1)).saveRequest(any(), any());
    }

    @Test
    public void loading_change_password_page() throws Exception {
        request.setPathInfo("/force_password_change");
        request.setMethod(HttpMethod.GET.name());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(true);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void submit_change_password() throws Exception {
        request.setPathInfo("/force_password_change");
        request.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(true);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void follow_completed_redirect() throws Exception {
        request.setPathInfo("/force_password_change_completed");
        request.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(false);
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendRedirect("/");
    }

    @Test
    public void follow_completed_redirect_with_saved_request() throws Exception {
        String location = "/oauth/authorize";
        SavedRequest savedRequest = getSavedRequest(location);
        when(cache.getRequest(any(), any())).thenReturn(savedRequest);
        request.setPathInfo("/force_password_change_completed");
        request.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(false);
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendRedirect(location);
    }

    @Test
    public void trying_access_force_password_page() throws Exception {
        request.setPathInfo("/force_password_change");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(false);
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendRedirect("/");
    }


    @Test
    public void trying_access_force_password_page_not_authenticated() throws Exception {
        request.setPathInfo("/force_password_change");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void completed_but_still_requires_change() throws Exception {
        request.setPathInfo("/force_password_change_completed");
        request.setMethod(HttpMethod.POST.name());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.isRequiresPasswordChange()).thenReturn(true);

        filter.doFilterInternal(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendRedirect("/force_password_change");


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


}