package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LoginSAMLAuthenticationFailureHandlerTest {

    @Test
    public void testErrorRedirect() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<String, String[]>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        LoginSAMLException exception = new LoginSAMLException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertEquals("https://example.com?error=access_denied&error_description=Denied%21", actual);
        int status = response.getStatus();
        assertEquals(302, status);
    }

    @Test
    public void testErrorRedirectWithExistingQueryParameters() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<String, String[]>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com?go=bears" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        LoginSAMLException exception = new LoginSAMLException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertEquals("https://example.com?go=bears&error=access_denied&error_description=Denied%21", actual);
        int status = response.getStatus();
        assertEquals(302, status);
    }

    @Test
    public void testSomeOtherErrorCondition() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<String, String[]>();
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
            private static final long serialVersionUID = 1L;
        };
        handler.onAuthenticationFailure(request, response, exception);
        String actual = response.getRedirectedUrl();
        assertNull(actual);
        int status = response.getStatus();
        assertEquals(401, status);
    }

    @Test
    public void testNoSession() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        LoginSAMLException exception = new LoginSAMLException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertNull(actual);
        int status = response.getStatus();
        assertEquals(401, status);
    }

    @Test
    public void testNoSavedRequest() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<String, String[]>();
        parameterMap.put("redirect_uri", new String[] { "https://example.com" });
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        LoginSAMLException exception = new LoginSAMLException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertNull(actual);
        int status = response.getStatus();
        assertEquals(401, status);
    }

    @Test
    public void testNoRedirectURI() throws IOException, ServletException {
        LoginSAMLAuthenticationFailureHandler handler = new LoginSAMLAuthenticationFailureHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<String, String[]>();
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        LoginSAMLException exception = new LoginSAMLException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);
        String actual = response.getRedirectedUrl();
        assertNull(actual);
        int status = response.getStatus();
        assertEquals(401, status);
    }
}
