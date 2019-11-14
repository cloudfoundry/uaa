package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class UaaAuthorizationEndpointParamaterizedTest {

    private static final String REDIRECT_URI = "http://sub.domain.com/callback?oauth=true";
    private static final String HTTP_SOME_OTHER_SITE_CALLBACK = "http://some.other.site/callback";
    private final SessionAuthenticationException authException = new SessionAuthenticationException("");
    private UaaAuthorizationEndpoint uaaAuthorizationEndpoint;
    private BaseClientDetails client;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MultitenantClientServices clientDetailsService;
    private RedirectResolver redirectResolver;
    private OpenIdSessionStateCalculator calculator;

    private final String responseType;
    private final String redirectUrl;

    public UaaAuthorizationEndpointParamaterizedTest(String responseType) {
        this.responseType = responseType;
        redirectUrl = REDIRECT_URI;
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"code"},
                {"token"},
                {"id_token"},
                {"token id_token"}
        });
    }

    @Before
    public void setup() {
        client = new BaseClientDetails("id", "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", redirectUrl);
        clientDetailsService = mock(MultitenantClientServices.class);
        redirectResolver = mock(RedirectResolver.class);
        calculator = mock(OpenIdSessionStateCalculator.class);

        String zoneID = IdentityZoneHolder.get().getId();
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), eq(zoneID))).thenReturn(client);
        when(redirectResolver.resolveRedirect(eq(redirectUrl), same(client))).thenReturn(redirectUrl);
        when(redirectResolver.resolveRedirect(eq(HTTP_SOME_OTHER_SITE_CALLBACK), same(client))).thenThrow(new RedirectMismatchException(null));
        when(calculator.calculate(anyString(), anyString(), anyString())).thenReturn("sessionstate.salt");

        uaaAuthorizationEndpoint = new UaaAuthorizationEndpoint(
                redirectResolver,
                null,
                null,
                null,
                null,
                calculator,
                null,
                clientDetailsService,
                null,
                null);

        request = new MockHttpServletRequest("GET", "/oauth/authorize");
        request.setParameter(OAuth2Utils.CLIENT_ID, client.getClientId());
        request.setParameter(OAuth2Utils.RESPONSE_TYPE, responseType);
        response = new MockHttpServletResponse();
    }

    @Test
    public void test_missing_redirect_uri() throws Exception {
        client.setRegisteredRedirectUri(Collections.emptySet());
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
    }

    @Test
    public void test_client_not_found() throws Exception {
        reset(clientDetailsService);
        when(clientDetailsService.loadClientByClientId(anyString(), anyString())).thenThrow(new NoSuchClientException("not found"));
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
    }

    @Test
    public void test_redirect_mismatch() throws Exception {
        request.setParameter(OAuth2Utils.REDIRECT_URI, HTTP_SOME_OTHER_SITE_CALLBACK);
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
    }

    @Test
    public void test_redirect_contains_error() throws Exception {
        request.setParameter(OAuth2Utils.REDIRECT_URI, redirectUrl);
        uaaAuthorizationEndpoint.commence(request, response, authException);
        assertEquals(HttpStatus.FOUND.value(), response.getStatus());
        assertTrue(response.getHeader("Location").contains("error=login_required"));
    }

    @Test
    public void test_redirect_honors_ant_matcher() throws Exception {
        BaseClientDetails client = new BaseClientDetails("ant", "", "openid", "implicit", "", "http://example.com/**");
        request.setParameter(OAuth2Utils.REDIRECT_URI, "http://example.com/some/path");
        request.setParameter(OAuth2Utils.CLIENT_ID, client.getClientId());
        String zoneID = IdentityZoneHolder.get().getId();
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), eq(zoneID))).thenReturn(client);
        when(redirectResolver.resolveRedirect(eq(redirectUrl), same(client))).thenReturn(redirectUrl);

        when(redirectResolver.resolveRedirect(eq("http://example.com/some/path"), same(client))).thenReturn("http://example.com/some/path");
        uaaAuthorizationEndpoint.commence(request, response, authException);
    }

}