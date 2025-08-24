package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.AbstractClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AccessTokenSupportTests {

    private final ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

    private final HttpHeaders requestHeaders = new HttpHeaders();

    private final MultiValueMap<String, String> form = new LinkedMultiValueMap<>();

    private StubHttpClientResponse response;

    private IOException error;

    private final DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");

    private final AccessTokenRequest request = new DefaultAccessTokenRequest();

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final OAuth2AccessTokenSupport support = new OAuth2AccessTokenSupport() {
    };

    @BeforeEach
    void init() {
        resource.setClientId("client");
        resource.setClientSecret("secret");
        resource.setAccessTokenUri("https://nowhere/token");
        response = new StubHttpClientResponse();
        support.setRequestFactory(new ClientHttpRequestFactory() {
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                return new StubClientHttpRequest(response);
            }
        });
    }

    @Test
    void retrieveTokenFailsWhenTokenEndpointNotAvailable() {
        error = new IOException("Planned");
        response.setStatus(HttpStatus.BAD_REQUEST);
        assertThatExceptionOfType(OAuth2AccessDeniedException.class).isThrownBy(() ->
                support.retrieveToken(request, resource, form, requestHeaders));
    }

    @Test
    void retrieveToken() throws Exception {
        response.setBody(objectMapper.writeValueAsString(accessToken));
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void retrieveTokenFormEncoded() throws Exception {
        // SECOAUTH-306: no need to set message converters
        requestHeaders.setAccept(List.of(MediaType.APPLICATION_FORM_URLENCODED));
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        response.setBody("access_token=FOO");
        response.setHeaders(responseHeaders);
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void requestEnhanced() throws Exception {
        DefaultRequestEnhancer enhancer = new DefaultRequestEnhancer();
        enhancer.setParameterIncludes(List.of("foo"));
        request.set("foo", "bar");
        support.setTokenRequestEnhancer(enhancer);
        response.setBody(objectMapper.writeValueAsString(accessToken));
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(form.get("foo")).hasToString("[bar]");
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void requestNotEnhanced() throws Exception {
        request.set("foo", "bar");
        response.setBody(objectMapper.writeValueAsString(accessToken));
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(form).doesNotContainKey("foo");
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void requestEnhancedFromQuery() throws Exception {
        DefaultRequestEnhancer enhancer = new DefaultRequestEnhancer();
        enhancer.setParameterIncludes(List.of("foo"));
        request.set("foo", "bar");
        support.setTokenRequestEnhancer(enhancer);
        response.setBody(objectMapper.writeValueAsString(accessToken));
        resource.setClientAuthenticationScheme(AuthenticationScheme.form);
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(form.get("foo")).hasToString("[bar]");
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void requestEnhancedEmptySecret() throws Exception {
        DefaultRequestEnhancer enhancer = new DefaultRequestEnhancer();
        enhancer.setParameterIncludes(List.of("foo"));
        request.set("foo", "bar");
        support.setTokenRequestEnhancer(enhancer);
        response.setBody(objectMapper.writeValueAsString(accessToken));
        resource.setClientSecret("");
        resource.setClientAuthenticationScheme(AuthenticationScheme.form);
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(form.get("foo")).hasToString("[bar]");
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    @Test
    void requestEnhancedNonScheme() throws Exception {
        DefaultRequestEnhancer enhancer = new DefaultRequestEnhancer();
        enhancer.setParameterIncludes(List.of("foo"));
        request.set("foo", "bar");
        support.setTokenRequestEnhancer(enhancer);
        response.setBody(objectMapper.writeValueAsString(accessToken));
        resource.setClientId("clientId");
        resource.setClientAuthenticationScheme(AuthenticationScheme.none);
        OAuth2AccessToken retrieveToken = support.retrieveToken(request, resource, form, requestHeaders);
        assertThat(form.get("foo")).hasToString("[bar]");
        assertThat(retrieveToken).isEqualTo(accessToken);
    }

    private final class StubHttpClientResponse implements ClientHttpResponse {
        private HttpStatus status = HttpStatus.OK;

        private String body;

        private HttpHeaders headers = new HttpHeaders();

        {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }


        public void setBody(String body) {
            this.body = body;
        }

        public void setHeaders(HttpHeaders headers) {
            this.headers = headers;
        }

        public void setStatus(HttpStatus status) {
            this.status = status;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return HttpStatusCode.valueOf(status.value());
        }

        public int getRawStatusCode() throws IOException {
            return status.value();
        }

        public String getStatusText() throws IOException {
            return status.toString();
        }

        public void close() {
            // do nothing
        }

        public InputStream getBody() throws IOException {
            if (error != null) {
                throw error;
            }
            return new ByteArrayInputStream(body.getBytes());
        }

        public HttpHeaders getHeaders() {
            return headers;
        }
    }

    private static class StubClientHttpRequest extends AbstractClientHttpRequest {

        private final ClientHttpResponse response;

        public StubClientHttpRequest(ClientHttpResponse response) {
            this.response = response;
        }

        @Override
        public HttpMethod getMethod() {
            return HttpMethod.GET;
        }

        public String getMethodValue() {
            return getMethod().name();
        }

        public URI getURI() {
            return null;
        }

        @Override
        protected OutputStream getBodyInternal(HttpHeaders headers) throws IOException {
            return new ByteArrayOutputStream();
        }

        @Override
        protected ClientHttpResponse executeInternal(HttpHeaders headers) throws IOException {
            return response;
        }
    }
}
