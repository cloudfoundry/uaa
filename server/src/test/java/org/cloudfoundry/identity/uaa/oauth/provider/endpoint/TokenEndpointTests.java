package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
class TokenEndpointTests {

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private static final String CLIENT_ID = "client";
    private final UaaClientDetails clientDetails = new UaaClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("client", null,
            Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        return new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
    }

    @BeforeEach
    void init() {
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setScope(Set.of("admin", "read", "write"));
    }

    @Test
    void setterAndGetter() throws Exception {
        endpoint.setProviderExceptionHandler(new DefaultWebResponseExceptionTranslator());
        assertThat(endpoint.getExceptionTranslator()).isNotNull();
        endpoint.setOAuth2RequestFactory(null);
        endpoint.afterPropertiesSet();
        assertThat(endpoint.getOAuth2RequestFactory()).isNotNull()
                .isEqualTo(endpoint.getDefaultOAuth2RequestFactory());
    }

    @Test
    void getAccessTokenWithNoClientId() {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.GRANT_TYPE, "authorization_code");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
                expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
                createFromParameters(parameters));

        clientAuthentication = new UsernamePasswordAuthenticationToken(null, null,
                Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));
        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        OAuth2AccessToken body = response.getBody();
        assertThat(expectedToken).isEqualTo(body);
        assertThat(body.getTokenType()).as("Wrong body: " + body).isNotNull();
    }

    @Test
    void getAccessTokenWithScope() {

        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

        when(tokenGranter.grant(eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        OAuth2AccessToken body = response.getBody();
        assertThat(expectedToken).isEqualTo(body);
        assertThat(body.getTokenType()).as("Wrong body: " + body).isNotNull();
        assertThat(captor.getValue().getScope()).as("Scope of token request not cleared").isEmpty();
    }

    @Test
    void getAccessTokenWithUnsupportedRequestParameters() {
        assertThatExceptionOfType(HttpRequestMethodNotSupportedException.class).isThrownBy(() ->
                endpoint.getAccessToken(clientAuthentication, new HashMap<>()));
    }

    @Test
    void getAccessTokenWithSupportedRequestParametersNotPost() throws HttpRequestMethodNotSupportedException {
        endpoint.setAllowedRequestMethods(new HashSet<>(List.of(HttpMethod.GET)));
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
                expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(clientAuthentication, parameters);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        OAuth2AccessToken body = response.getBody();
        assertThat(expectedToken).isEqualTo(body);
        assertThat(body.getTokenType()).as("Wrong body: " + body).isNotNull();
    }

    @Test
    void implicitGrant() {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.GRANT_TYPE, "implicit");
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                createFromParameters(parameters));
        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(clientDetails);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                endpoint.postAccessToken(clientAuthentication, parameters));
    }

    // gh-1268
    @Test
    void getAccessTokenReturnsHeaderContentTypeJson() {
        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().get("Content-Type").getFirst()).isEqualTo("application/json");
    }

    @Test
    void refreshTokenGrantTypeWithoutRefreshTokenParameter() {
        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(clientDetails);
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        parameters.put("grant_type", "refresh_token");
        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->

                endpoint.postAccessToken(clientAuthentication, parameters));
    }

    @Test
    void getAccessTokenWithRefreshToken() {
        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", CLIENT_ID);
        parameters.put("scope", "read");
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("refresh_token"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertThat(response.getBody()).isEqualTo(expectedToken);
    }

    @Test
    void postAccessException() {
        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() ->
                endpoint.postAccessToken(null, Collections.emptyMap()));
    }

    @Test
    void getClientIdException() {
        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() ->
                endpoint.getClientId(new UsernamePasswordAuthenticationToken("FOO", "bar")));
    }

    @Test
    void getClientId() {
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Authentication.isAuthenticated()).thenReturn(true);
        when(oAuth2Request.getClientId()).thenReturn("FOO");
        assertThat(endpoint.getClientId(oAuth2Authentication)).isEqualTo("FOO");
    }

    @Test
    void exceptions() throws Exception {
        endpoint.setOAuth2RequestValidator(new UaaOauth2RequestValidator());
        assertThat(endpoint.handleException(new Exception("exception")).getBody().getOAuth2ErrorCode()).isEqualTo("server_error");
    }

    @Test
    void invalidClient() throws Exception {
        assertThat(endpoint.handleException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void invalidClientException() throws Exception {
        assertThat(endpoint.handleClientRegistrationException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void notSupported() throws Exception {
        assertThat(endpoint.handleHttpRequestMethodNotSupportedException(new HttpRequestMethodNotSupportedException("exception")).getBody().getOAuth2ErrorCode()).isEqualTo("method_not_allowed");
    }
}
