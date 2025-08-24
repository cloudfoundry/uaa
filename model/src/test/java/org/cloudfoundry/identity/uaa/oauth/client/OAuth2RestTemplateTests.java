package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProviderChain;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.util.UriTemplate;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2RestTemplateTests {

    private BaseOAuth2ProtectedResourceDetails resource;

    private OAuth2RestTemplate restTemplate;

    private final AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);

    private ClientHttpRequest request;

    private HttpHeaders headers;

    @BeforeEach
    void open() throws Exception {
        resource = new BaseOAuth2ProtectedResourceDetails();
        // Facebook and older specs:
        resource.setTokenName("bearer_token");
        restTemplate = new OAuth2RestTemplate(resource);
        restTemplate.setAccessTokenProvider(accessTokenProvider);
        request = Mockito.mock(ClientHttpRequest.class);
        headers = new HttpHeaders();
        Mockito.when(request.getHeaders()).thenReturn(headers);
        ClientHttpResponse response = Mockito.mock(ClientHttpResponse.class);
        HttpStatus statusCode = HttpStatus.OK;
        Mockito.when(response.getStatusCode()).thenReturn(statusCode);
        Mockito.when(request.execute()).thenReturn(response);
    }

    @Test
    void nonBearerToken() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        token.setTokenType("MINE");
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
        String auth = http.getHeaders().getFirst("Authorization");
        assertThat(auth).startsWith("MINE ");
    }

    @Test
    void customAuthenticator() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        token.setTokenType("MINE");
        restTemplate.setAuthenticator(new OAuth2RequestAuthenticator() {
            @Override
            public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext, ClientHttpRequest req) {
                req.getHeaders().set("X-Authorization", clientContext.getAccessToken().getTokenType() + " " + "Nah-nah-na-nah-nah");
            }
        });
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        ClientHttpRequest http = restTemplate.createRequest(URI.create("https://nowhere.com/api/crap"), HttpMethod.GET);
        String auth = http.getHeaders().getFirst("X-Authorization");
        assertThat(auth).isEqualTo("MINE Nah-nah-na-nah-nah");
    }

    /**
     * tests appendQueryParameter
     */
    @Test
    void appendQueryParameter() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search?type=checkin"),
                token);
        assertThat(appended).hasToString("https://graph.facebook.com/search?type=checkin&bearer_token=12345");
    }

    /**
     * tests appendQueryParameter
     */
    @Test
    void appendQueryParameterWithNoExistingParameters() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertThat(appended).hasToString("https://graph.facebook.com/search?bearer_token=12345");
    }

    /**
     * tests encoding of access token value
     */
    @Test
    void doubleEncodingOfParameterValue() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1/qIxxx");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertThat(appended).hasToString("https://graph.facebook.com/search?bearer_token=1%2FqIxxx");
    }

    /**
     * tests no double encoding of existing query parameter
     */
    @Test
    void nonEncodingOfUriTemplate() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
        UriTemplate uriTemplate = new UriTemplate("https://graph.facebook.com/fql?q={q}");
        URI expanded = uriTemplate.expand("[q: fql]");
        URI appended = restTemplate.appendQueryParameter(expanded, token);
        assertThat(appended).hasToString("https://graph.facebook.com/fql?q=%5Bq:%20fql%5D&bearer_token=12345");
    }

    /**
     * tests URI with fragment value
     */
    @Test
    void fragmentUri() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1234");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search#foo"), token);
        assertThat(appended).hasToString("https://graph.facebook.com/search?bearer_token=1234#foo");
    }

    /**
     * tests encoding of access token value passed in protected requests ref: SECOAUTH-90
     */
    @Test
    void doubleEncodingOfAccessTokenValue() {
        // try with fictitious token value with many characters to encode
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("1 qI+x:y=z");
        URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
        assertThat(appended).hasToString("https://graph.facebook.com/search?bearer_token=1+qI%2Bx%3Ay%3Dz");
    }

    @Test
    void noRetryAccessDeniedExceptionForNoExistingToken() {
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        restTemplate.setRequestFactory((uri, httpMethod) -> {
            throw new AccessTokenRequiredException(resource);
        });
        assertThatExceptionOfType(AccessTokenRequiredException.class).isThrownBy(() ->
                restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(),
                        new SimpleResponseExtractor()));
    }

    @Test
    void retryAccessDeniedException() throws Exception {
        final AtomicBoolean failed = new AtomicBoolean(false);
        restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("TEST"));
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        restTemplate.setRequestFactory(new ClientHttpRequestFactory() {
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) {
                if (!failed.get()) {
                    failed.set(true);
                    throw new AccessTokenRequiredException(resource);
                }
                return request;
            }
        });
        Boolean result = restTemplate.doExecute(new URI("https://foo"), HttpMethod.GET, new NullRequestCallback(),
                new SimpleResponseExtractor());
        assertThat(result).isTrue();
    }

    @Test
    void newTokenAcquiredIfExpired() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() - 1000));
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertThat(newToken)
                .isNotNull()
                .isNotEqualTo(token);
    }

    // gh-1478
    @Test
    void newTokenAcquiredWithDefaultClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() + 29000));    // Default clock skew is 30 secs
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertThat(newToken)
                .isNotNull()
                .isNotEqualTo(token);
    }

    // gh-1478
    @Test
    void newTokenAcquiredIfLessThanConfiguredClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() + 5000));
        restTemplate.setClockSkew(6);
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertThat(newToken)
                .isNotNull()
                .isNotEqualTo(token);
    }

    // gh-1478
    @Test
    void newTokenNotAcquiredIfGreaterThanConfiguredClockSkew() {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() + 5000));
        restTemplate.setClockSkew(4);
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        OAuth2AccessToken newToken = restTemplate.getAccessToken();
        assertThat(newToken)
                .isNotNull()
                .isEqualTo(token);
    }

    // gh-1478
    @Test
    void negativeClockSkew() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                restTemplate.setClockSkew(-1));
    }

    // gh-1909
    @Test
    void clockSkewPropagationIntoAccessTokenProviderChain() {
        AccessTokenProvider provider = new AccessTokenProviderChain(List.of());
        restTemplate.setAccessTokenProvider(provider);
        restTemplate.setClockSkew(5);

        Field field = ReflectionUtils.findField(provider.getClass(), "clockSkew");
        field.setAccessible(true);

        assertThat(ReflectionUtils.getField(field, provider)).isEqualTo(5);
    }

    // gh-1909
    @Test
    void applyClockSkewOnProvidedAccessTokenProviderChain() {
        AccessTokenProvider provider = new AccessTokenProviderChain(List.of());
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(provider);

        Field field = ReflectionUtils.findField(provider.getClass(), "clockSkew");
        field.setAccessible(true);

        assertThat(ReflectionUtils.getField(field, provider)).isEqualTo(5);
    }

    // gh-1909
    @Test
    void clockSkewPropagationSkippedForNonAccessTokenProviderChainInstances() {
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(null);
        restTemplate.setClockSkew(5);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
        restTemplate.setClockSkew(5);
    }

    @Test
    void tokenIsResetIfInvalid() throws Exception {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        token.setExpiration(new Date(System.currentTimeMillis() - 1000));
        restTemplate.getOAuth2ClientContext().setAccessToken(token);
        restTemplate.setAccessTokenProvider(new StubAccessTokenProvider() {
            @Override
            public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details,
                                                       AccessTokenRequest parameters) throws UserRedirectRequiredException, AccessDeniedException {
                throw new UserRedirectRequiredException("https://www.foo.com/", Collections.<String, String>emptyMap());
            }
        });
        try {
            OAuth2AccessToken newToken = restTemplate.getAccessToken();
            assertThat(newToken).isNotNull();
            fail("Expected UserRedirectRequiredException");
        } catch (UserRedirectRequiredException e) {
            // planned
        }
        // context token should be reset as it is invalid at this point
        assertThat(restTemplate.getOAuth2ClientContext().getAccessToken()).isNull();
    }

    private final class SimpleResponseExtractor implements ResponseExtractor<Boolean> {
        public Boolean extractData(ClientHttpResponse response) {
            return true;
        }
    }

    private static class NullRequestCallback implements RequestCallback {
        public void doWithRequest(ClientHttpRequest request) {
            // do nothing
        }
    }

    private static class StubAccessTokenProvider implements AccessTokenProvider {
        public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters)
                throws UserRedirectRequiredException, AccessDeniedException {
            return new DefaultOAuth2AccessToken("FOO");
        }

        public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
            return false;
        }

        public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
                                                    OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
            return null;
        }

        public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
            return true;
        }
    }
}
