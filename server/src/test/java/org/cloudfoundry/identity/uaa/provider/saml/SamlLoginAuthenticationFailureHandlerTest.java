package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.http.HttpStatus;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.Serial;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SamlLoginAuthenticationFailureHandlerTest {

    @Test
    public void testErrorRedirect() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertThat(actual).isEqualTo("https://example.com?error=access_denied&error_description=Denied%21");
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
    }

    @Test
    public void testErrorRedirectWithExistingQueryParameters() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com?go=bears" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertThat(actual).isEqualTo("https://example.com?go=bears&error=access_denied&error_description=Denied%21");
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
    }

    @Test
    public void testSomeOtherErrorCondition() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com?go=bears" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationException exception = new AuthenticationException("Authentication Exception") {
            /**
             *
             */
            @Serial
            private static final long serialVersionUID = 1L;
        };
        handler.onAuthenticationFailure(request, response, exception);
        String actual = response.getRedirectedUrl();
        assertThat(actual).isNull();
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testNoSession() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertThat(actual).isNull();
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testNoSavedRequest() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertThat(actual).isNull();
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @Test
    public void testNoRedirectURI() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);
        String actual = response.getRedirectedUrl();
        assertThat(actual).isNull();
        int status = response.getStatus();
        assertThat(status).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }
}
