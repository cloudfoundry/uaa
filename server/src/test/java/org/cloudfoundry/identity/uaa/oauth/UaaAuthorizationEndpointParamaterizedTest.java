package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

public class UaaAuthorizationEndpointParamaterizedTest {

    private static final String REDIRECT_URI = "http://sub.domain.com/callback?oauth=true";
    private static final String HTTP_SOME_OTHER_SITE_CALLBACK = "http://some.other.site/callback";
    private final SessionAuthenticationException authException = new SessionAuthenticationException("");
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;
    private UaaClientDetails client;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MultitenantClientServices clientDetailsService;
    private RedirectResolver redirectResolver;

    private String redirectUrl;

    public void initUaaAuthorizationEndpointParamaterizedTest(String responseType) {
        redirectUrl = REDIRECT_URI;

        client = new UaaClientDetails("id", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", redirectUrl);
        clientDetailsService = mock(MultitenantClientServices.class);
        redirectResolver = mock(RedirectResolver.class);
        OpenIdSessionStateCalculator calculator = mock(OpenIdSessionStateCalculator.class);

        String zoneID = IdentityZoneHolder.get().getId();
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), eq(zoneID))).thenReturn(client);
        when(redirectResolver.resolveRedirect(eq(redirectUrl), (ClientDetails) same(client))).thenReturn(redirectUrl);
        when(redirectResolver.resolveRedirect(eq(HTTP_SOME_OTHER_SITE_CALLBACK), (ClientDetails) same(client))).thenThrow(new RedirectMismatchException(null));
        when(calculator.calculate(anyString(), anyString(), anyString())).thenReturn("sessionstate.salt");

        uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint(
                redirectResolver,
                null,
                null,
                null,
                null,
                null,
                clientDetailsService,
                null,
                null);
        uaaAuthorizationEndpoint.setOpenIdSessionStateCalculator(calculator);

        request = new MockHttpServletRequest("GET", "/oauth/authorize");
        request.setParameter(OAuth2Utils.CLIENT_ID, client.getClientId());
        request.setParameter(OAuth2Utils.RESPONSE_TYPE, responseType);
        response = new MockHttpServletResponse();
    }

    public static Stream<Arguments> parameters() {
        return Stream.of(
                arguments("code"),
                arguments("token"),
                arguments("id_token"),
                arguments("token id_token")
        );
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void missing_redirect_uri(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        client.setRegisteredRedirectUri(Collections.emptySet());
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void client_not_found(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        reset(clientDetailsService);
        when(clientDetailsService.loadClientByClientId(anyString(), anyString())).thenThrow(new NoSuchClientException("not found"));
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void redirect_mismatch(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        request.setParameter(OAuth2Utils.REDIRECT_URI, HTTP_SOME_OTHER_SITE_CALLBACK);
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void redirect_contains_error(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        request.setParameter(OAuth2Utils.REDIRECT_URI, redirectUrl);
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
        assertThat(response.getHeader("Location")).contains("error=login_required");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void redirect_honors_ant_matcher(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        client = new UaaClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        request.setParameter(OAuth2Utils.REDIRECT_URI, "http://example.com/some/path");
        request.setParameter(OAuth2Utils.CLIENT_ID, client.getClientId());
        String zoneID = IdentityZoneHolder.get().getId();
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), eq(zoneID))).thenReturn(client);
        when(redirectResolver.resolveRedirect(eq(redirectUrl), (ClientDetails) same(client))).thenReturn(redirectUrl);

        when(redirectResolver.resolveRedirect(eq("http://example.com/some/path"), (ClientDetails) same(client))).thenReturn("http://example.com/some/path");
        uaaAuthorizationEndpoint.commence(request, response, authException);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{index}: {0}")
    void authorization_exception(String responseType) throws Exception {
        initUaaAuthorizationEndpointParamaterizedTest(responseType);
        RedirectMismatchException redirectMismatchException = new RedirectMismatchException("error");
        ServletWebRequest servletWebRequest = mock(ServletWebRequest.class);
        MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
        when(servletWebRequest.getResponse()).thenReturn(mockHttpServletResponse);
        ModelAndView modelAndView = uaaAuthorizationEndpoint.handleOAuth2Exception(redirectMismatchException, servletWebRequest);
        assertThat(modelAndView).isNotNull();
        assertThat(modelAndView.getModelMap()).isNotEmpty();
        assertThat(modelAndView.getViewName()).isEqualTo("forward:/oauth/error");
    }
}
