package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class AuthorizationCodeAccessTokenProviderWithConversionTests {

    private static class StubClientHttpRequest implements ClientHttpRequest {

        private static final HttpHeaders DEFAULT_RESPONSE_HEADERS = new HttpHeaders();

        private final HttpStatus responseStatus;

        private final HttpHeaders responseHeaders;

        private final String responseBody;

        static {
            DEFAULT_RESPONSE_HEADERS.setContentType(MediaType.APPLICATION_JSON);
        }

        public StubClientHttpRequest(String responseBody) {
            this(HttpStatus.OK, DEFAULT_RESPONSE_HEADERS, responseBody);
        }

        public StubClientHttpRequest(HttpHeaders responseHeaders, String responseBody) {
            this(HttpStatus.OK, responseHeaders, responseBody);
        }

        public StubClientHttpRequest(HttpStatus responseStatus, String responseBody) {
            this(responseStatus, DEFAULT_RESPONSE_HEADERS, responseBody);
        }

        public StubClientHttpRequest(HttpStatus responseStatus, HttpHeaders responseHeaders, String responseBody) {
            this.responseStatus = responseStatus;
            this.responseHeaders = responseHeaders;
            this.responseBody = responseBody;
        }

        public OutputStream getBody() {
            return new ByteArrayOutputStream();
        }

        public HttpHeaders getHeaders() {
            return new HttpHeaders();
        }

        public URI getURI() {
            try {
                return new URI("https://www.foo.com/");
            } catch (URISyntaxException e) {
                throw new IllegalStateException(e);
            }
        }


        public Map<String, Object> getAttributes() {
            return emptyMap();
        }

        @Override
        public HttpMethod getMethod() {
            return HttpMethod.POST;
        }

        public String getMethodValue() {
            return getMethod().name();
        }

        public ClientHttpResponse execute() throws IOException {
            return new ClientHttpResponse() {

                public HttpHeaders getHeaders() {
                    return responseHeaders;
                }

                public InputStream getBody() {
                    return new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8));
                }

                public String getStatusText() {
                    return responseStatus.getReasonPhrase();
                }

                public HttpStatus getStatusCode() {
                    return responseStatus;
                }

                public void close() {
                    // do nothing
                }

                public int getRawStatusCode() {
                    return responseStatus.value();
                }
            };
        }
    }

    private ClientHttpRequestFactory requestFactory;

    private final AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();

    private final AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

    private void setUpRestTemplate() {
        provider.setRequestFactory(requestFactory);
    }

    @Test
    void getAccessTokenFromJson() throws Exception {
        final OAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
        requestFactory = new ClientHttpRequestFactory() {
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                return new StubClientHttpRequest(new ObjectMapper().writeValueAsString(token));
            }
        };
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        request.setPreservedState(new Object());
        setUpRestTemplate();
        assertThat(provider.obtainAccessToken(resource, request)).isEqualTo(token);
    }

    @Test
    void getErrorFromJson() {
        final InvalidClientException exception = new InvalidClientException("FOO");
        requestFactory = new ClientHttpRequestFactory() {
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                return new StubClientHttpRequest(HttpStatus.BAD_REQUEST,
                        new ObjectMapper().writeValueAsString(exception));
            }
        };
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        setUpRestTemplate();
        assertThatThrownBy(() -> provider.obtainAccessToken(resource, request))
                .isInstanceOf(OAuth2AccessDeniedException.class)
                .hasCauseInstanceOf(InvalidClientException.class);
    }

    @Test
    void getAccessTokenFromForm() throws Exception {
        final OAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
        final HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        requestFactory = new ClientHttpRequestFactory() {
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) {
                return new StubClientHttpRequest(responseHeaders, "access_token=FOO");
            }
        };
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        setUpRestTemplate();
        assertThat(provider.obtainAccessToken(resource, request)).isEqualTo(token);
    }

    @Test
    void getErrorFromForm() {
        final HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        requestFactory = (uri, httpMethod) -> new StubClientHttpRequest(HttpStatus.BAD_REQUEST, responseHeaders,
                "error=invalid_client&error_description=FOO");
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        setUpRestTemplate();
        assertThatThrownBy(() -> provider.obtainAccessToken(resource, request))
                .isInstanceOf(OAuth2AccessDeniedException.class)
                .hasCauseInstanceOf(InvalidClientException.class);
    }
}
