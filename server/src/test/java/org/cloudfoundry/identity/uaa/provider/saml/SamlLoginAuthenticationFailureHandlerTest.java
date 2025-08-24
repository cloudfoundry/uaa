package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.hc.core5.http.HttpStatus;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.io.Serial;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlLoginAuthenticationFailureHandlerTest {

    @Test
    void errorRedirect() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com"});
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
    void errorRedirectWithExistingQueryParameters() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com?go=bears"});
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
    void someOtherErrorCondition() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com?go=bears"});
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
    void noSession() throws IOException, ServletException {
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
    void noSavedRequest() throws IOException, ServletException {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com"});
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
    void noRedirectURI() throws IOException, ServletException {
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
