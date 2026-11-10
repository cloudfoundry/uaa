package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.hc.core5.http.HttpStatus;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@EnabledIfZonePathsEnabled
class SamlLoginAuthenticationFailureHandlerZonePathTest {

    private final RedirectResolver redirectResolver = mock(RedirectResolver.class);
    private final MultitenantClientServices clientServices = mock(MultitenantClientServices.class);
    private final IdentityZoneManager identityZoneManager = mock(IdentityZoneManager.class);

    private SamlLoginAuthenticationFailureHandler newHandler() throws Exception {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn("uaa");
        when(clientServices.loadClientByClientId("client", "uaa")).thenReturn(mock(ClientDetails.class));
        // a registered redirect_uri is resolved to itself
        when(redirectResolver.resolveRedirect(anyString(), any())).thenAnswer(invocation -> invocation.getArgument(0));
        return new SamlLoginAuthenticationFailureHandler(redirectResolver, clientServices, identityZoneManager);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorRedirect(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com"});
        parameterMap.put("client_id", new String[]{"client"});
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, "https://example.com?error=access_denied&error_description=Denied%21", mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void errorRedirectWithExistingQueryParameters(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com?go=bears"});
        parameterMap.put("client_id", new String[]{"client"});
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, "https://example.com?go=bears&error=access_denied&error_description=Denied%21", mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void someOtherErrorCondition(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com?go=bears"});
        parameterMap.put("client_id", new String[]{"client"});
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
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
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void noSession(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void noSavedRequest(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://example.com"});
        parameterMap.put("client_id", new String[]{"client"});
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void noRedirectURI(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        Map<String, String[]> parameterMap = new HashMap<>();
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        mode.applyRequestPath(request, "/saml/callback");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        SamlLoginException exception = new SamlLoginException("Denied!");
        handler.onAuthenticationFailure(request, response, exception);
        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    /**
     * Asserts redirect URL: server-relative paths (starting with "/") must start with "/z/{subdomain}" when
     * mode is ZONE_PATH and must not start with "/z/" when mode is DEFAULT. External URLs and null are compared as-is.
     */
    private static void assertRedirectUrl(String actual, String expected, ZoneRequestPathMode mode) {
        if (expected == null) {
            assertThat(actual).isNull();
        } else if (expected.startsWith("/")) {
            String expectedWithPrefix = mode.redirectPrefix() + expected;
            assertThat(actual).isEqualTo(expectedWithPrefix);
        } else {
            assertThat(actual).isEqualTo(expected);
        }
        if (actual != null && actual.startsWith("/")) {
            if (mode == ZoneRequestPathMode.ZONE_PATH) {
                assertThat(actual).startsWith("/z/" + mode.getSubdomain());
            } else {
                assertThat(actual).doesNotStartWith("/z/");
            }
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void unregisteredRedirectUriIsNotFollowed(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();
        when(redirectResolver.resolveRedirect(anyString(), any())).thenThrow(new RedirectMismatchException("no match"));
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://unregistered.example.com"});
        parameterMap.put("client_id", new String[]{"client"});

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        mode.applyRequestPath(request, "/saml/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new SamlLoginException("Denied!"));

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void unknownClientIsNotFollowed(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();
        when(clientServices.loadClientByClientId("client", "uaa")).thenThrow(new ClientRegistrationException("no client"));
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://unregistered.example.com"});
        parameterMap.put("client_id", new String[]{"client"});

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        mode.applyRequestPath(request, "/saml/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new SamlLoginException("Denied!"));

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void requestWithoutClientIdIsNotFollowed(ZoneRequestPathMode mode) throws Exception {
        SamlLoginAuthenticationFailureHandler handler = newHandler();
        Map<String, String[]> parameterMap = new HashMap<>();
        parameterMap.put("redirect_uri", new String[]{"https://unregistered.example.com"});

        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterMap()).thenReturn(parameterMap);

        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        mode.applyRequestPath(request, "/saml/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new SamlLoginException("Denied!"));

        String actual = response.getRedirectedUrl();
        assertRedirectUrl(actual, null, mode);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    }
}
