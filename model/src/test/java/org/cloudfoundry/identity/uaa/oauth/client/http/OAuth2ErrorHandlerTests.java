package org.cloudfoundry.identity.uaa.oauth.client.http;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResponseErrorHandler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
class OAuth2ErrorHandlerTests {

    @Mock
    private ClientHttpResponse response;

    private BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();

    private final class TestClientHttpResponse implements ClientHttpResponse {

        private final HttpHeaders headers;

        private final HttpStatus status;

        private final InputStream body;

        public TestClientHttpResponse(HttpHeaders headers, int status) {
            this(headers, status, new ByteArrayInputStream(new byte[0]));
        }

        public TestClientHttpResponse(HttpHeaders headers, int status, InputStream bodyStream) {
            this.headers = headers;
            this.status = HttpStatus.valueOf(status);
            this.body = bodyStream;
        }

        public InputStream getBody() throws IOException {
            return body;
        }

        public HttpHeaders getHeaders() {
            return headers;
        }

        public HttpStatus getStatusCode() throws IOException {
            return status;
        }

        public String getStatusText() throws IOException {
            return status.getReasonPhrase();
        }

        public int getRawStatusCode() throws IOException {
            return status.value();
        }

        public void close() {
            // do nothing
        }
    }

    private OAuth2ErrorHandler handler;

    @BeforeEach
    void setUp() {
        handler = new OAuth2ErrorHandler(resource);
    }

    /**
     * test response with www-authenticate header
     */
    @Test
    void handleErrorClientHttpResponse() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("www-authenticate", "Bearer error=foo");
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
        assertThatThrownBy(() -> handler.handleError(null, null, response))
                .isInstanceOf(HttpClientErrorException.class)
                .hasMessageContaining("401 Unauthorized");
    }

    @Test
    void handleErrorWithInvalidToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("www-authenticate", "Bearer error=\"invalid_token\", description=\"foo\"");
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
        assertThatThrownBy(() -> handler.handleError(null, null, response))
                .isInstanceOf(AccessTokenRequiredException.class)
                .hasMessageContaining("OAuth2 access denied");
    }

    @Test
    void customHandler() {
        OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {

            public boolean hasError(ClientHttpResponse response) throws IOException {
                return true;
            }

            public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
                throw new RuntimeException("planned");
            }
        }, resource);
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401);
        assertThatThrownBy(() -> handler.handleError(null, null, response))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("planned");
    }

    @Test
    void handle500Error() {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 500);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpServerErrorException.class));
    }

    @Test
    void handleGeneric400Error() {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpClientErrorException.class));
    }

    @Test
    void handleGeneric403Error() {
        HttpHeaders headers = new HttpHeaders();
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpClientErrorException.class));
    }

    // See https://github.com/spring-projects/spring-security-oauth/issues/387
    @Test
    void handleGeneric403ErrorWithBody() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403,
                new ByteArrayInputStream("{}".getBytes()));
        handler = new OAuth2ErrorHandler(new DefaultResponseErrorHandler(), resource);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpClientErrorException.class));
    }

    @Test
    void bodyCanBeUsedByCustomHandler() throws Exception {
        final String appSpecificBodyContent = "{\"some_status\":\"app error\"}";
        OAuth2ErrorHandler handler = new OAuth2ErrorHandler(new ResponseErrorHandler() {
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return true;
            }

            public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
                InputStream body = response.getBody();
                byte[] buf = new byte[appSpecificBodyContent.length()];
                int readResponse = body.read(buf);
                assertThat(readResponse).isEqualTo(buf.length);
                assertThat(new String(buf, "UTF-8")).isEqualTo(appSpecificBodyContent);
                throw new RuntimeException("planned");
            }
        }, resource);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Length", "" + appSpecificBodyContent.length());
        headers.set("Content-Type", "application/json");
        InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400, appSpecificErrorBody);
        assertThatThrownBy(() -> handler.handleError(null, null, response))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("planned");
    }

    @Test
    void handleErrorWithMissingHeader() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        when(response.getHeaders()).thenReturn(headers);
        when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);
        when(response.getBody()).thenReturn(new ByteArrayInputStream(new byte[0]));
        when(response.getStatusText()).thenReturn(HttpStatus.BAD_REQUEST.toString());
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpClientErrorException.class));
    }

    // gh-875
    @Test
    void handleErrorWhenAccessDeniedMessageAndStatus400ThenThrowsUserDeniedAuthorizationException() {
        String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
        ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 400, messageBody);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(UserDeniedAuthorizationException.class));
    }

    // gh-875
    @Test
    void handleErrorWhenAccessDeniedMessageAndStatus403ThenThrowsOAuth2AccessDeniedException() {
        String accessDeniedMessage = "{\"error\":\"access_denied\", \"error_description\":\"some error message\"}";
        ByteArrayInputStream messageBody = new ByteArrayInputStream(accessDeniedMessage.getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ClientHttpResponse response = new TestClientHttpResponse(headers, 403, messageBody);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(OAuth2AccessDeniedException.class));
    }

    @Test
    void handleMessageConversionExceptions() throws Exception {
        HttpMessageConverter<?> extractor = new HttpMessageConverter() {
            @Override
            public boolean canRead(Class clazz, MediaType mediaType) {
                return true;
            }

            @Override
            public boolean canWrite(Class clazz, MediaType mediaType) {
                return false;
            }

            @Override
            public List<MediaType> getSupportedMediaTypes() {
                return null;
            }

            @Override
            public Object read(Class clazz, HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
                throw new HttpMessageConversionException("error");
            }

            @Override
            public void write(Object o, MediaType contentType, HttpOutputMessage outputMessage) throws HttpMessageNotWritableException {
                // do nothing
            }
        };
        ArrayList<HttpMessageConverter<?>> messageConverters = new ArrayList<>();
        messageConverters.add(extractor);
        handler.setMessageConverters(messageConverters);
        HttpHeaders headers = new HttpHeaders();
        final String appSpecificBodyContent = "This user is not authorized";
        InputStream appSpecificErrorBody = new ByteArrayInputStream(appSpecificBodyContent.getBytes("UTF-8"));
        ClientHttpResponse response = new TestClientHttpResponse(headers, 401, appSpecificErrorBody);
        assertThatThrownBy(() ->
                handler.handleError(null, null, response)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpClientErrorException.class));
    }
}
