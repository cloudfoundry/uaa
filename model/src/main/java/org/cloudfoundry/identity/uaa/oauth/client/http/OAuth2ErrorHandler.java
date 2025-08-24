package org.cloudfoundry.identity.uaa.oauth.client.http;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2ErrorHandler implements ResponseErrorHandler {

    private final ResponseErrorHandler errorHandler;

    private final OAuth2ProtectedResourceDetails resource;

    private List<HttpMessageConverter<?>> messageConverters = new RestTemplate().getMessageConverters();

    /**
     * Construct an error handler that can deal with OAuth2 concerns before handling the error in the default fashion.
     */
    public OAuth2ErrorHandler(OAuth2ProtectedResourceDetails resource) {
        this.resource = resource;
        this.errorHandler = new DefaultResponseErrorHandler();
    }

    /**
     * @param messageConverters the messageConverters to set
     */
    public void setMessageConverters(List<HttpMessageConverter<?>> messageConverters) {
        this.messageConverters = messageConverters;
    }

    /**
     * Construct an error handler that can deal with OAuth2 concerns before delegating to acustom handler.
     *
     * @param errorHandler a delegate handler
     */
    public OAuth2ErrorHandler(ResponseErrorHandler errorHandler, OAuth2ProtectedResourceDetails resource) {
        this.resource = resource;
        this.errorHandler = errorHandler;
    }

    public boolean hasError(ClientHttpResponse response) throws IOException {
        return HttpStatus.Series.CLIENT_ERROR.equals(HttpStatus.resolve(response.getStatusCode().value()).series())
                || this.errorHandler.hasError(response);
    }

    public void handleError(final ClientHttpResponse response) throws IOException {
        if (!HttpStatus.Series.CLIENT_ERROR.equals(HttpStatus.resolve(response.getStatusCode().value()).series())) {
            // We should only care about 400 level errors. Ex: A 500 server error shouldn't
            // be an oauth related error.
            errorHandler.handleError(response);
        } else {
            // Need to use buffered response because input stream may need to be consumed multiple times.
            ClientHttpResponse bufferedResponse = new ClientHttpResponse() {
                private byte[] lazyBody;

                public HttpStatus getStatusCode() throws IOException {
                    return HttpStatus.resolve(response.getStatusCode().value());
                }

                public synchronized InputStream getBody() throws IOException {
                    if (lazyBody == null) {
                        InputStream bodyStream = response.getBody();
                        lazyBody = FileCopyUtils.copyToByteArray(bodyStream);
                    }
                    return new ByteArrayInputStream(lazyBody);
                }

                public HttpHeaders getHeaders() {
                    return response.getHeaders();
                }

                public String getStatusText() throws IOException {
                    return response.getStatusText();
                }

                public void close() {
                    response.close();
                }

                public int getRawStatusCode() throws IOException {
                    return this.getStatusCode().value();
                }
            };

            try {
                HttpMessageConverterExtractor<OAuth2Exception> extractor = new HttpMessageConverterExtractor<>(OAuth2Exception.class, messageConverters);
                try {
                    OAuth2Exception oauth2Exception = extractor.extractData(bufferedResponse);
                    if (oauth2Exception != null) {
                        // gh-875
                        if (oauth2Exception.getClass() == UserDeniedAuthorizationException.class &&
                                bufferedResponse.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                            oauth2Exception = new OAuth2AccessDeniedException(oauth2Exception.getMessage());
                        }
                        // If we can get an OAuth2Exception, it is likely to have more information
                        // than the header does, so just re-throw it here.
                        throw oauth2Exception;
                    }
                }
                catch (RestClientException e) {
                    // ignore
                }
                catch (HttpMessageConversionException e) {
                    // ignore
                }

                // first try: www-authenticate error
                List<String> authenticateHeaders = bufferedResponse.getHeaders().get("WWW-Authenticate");
                if (authenticateHeaders != null) {
                    for (String authenticateHeader : authenticateHeaders) {
                        maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.BEARER_TYPE);
                        maybeThrowExceptionFromHeader(authenticateHeader, OAuth2AccessToken.OAUTH2_TYPE);
                    }
                }

                // then delegate to the custom handler
                errorHandler.handleError(bufferedResponse);
            }
            catch (InvalidTokenException ex) {
                // Special case: an invalid token can be renewed so tell the caller what to do
                throw new AccessTokenRequiredException(resource);
            }
            catch (OAuth2Exception ex) {
                if (!ex.getClass().equals(OAuth2Exception.class)) {
                    // There is more information here than the caller would get from an HttpClientErrorException so
                    // rethrow
                    throw ex;
                }
                // This is not an exception that is really understood, so allow our delegate
                // to handle it in a non-oauth way
                errorHandler.handleError(bufferedResponse);
            }
        }
    }

    private void maybeThrowExceptionFromHeader(String authenticateHeader, String headerType) {
        headerType = headerType.toLowerCase();
        if (authenticateHeader.toLowerCase().startsWith(headerType)) {
            Map<String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap(
                    StringSplitUtils.splitIgnoringQuotes(authenticateHeader.substring(headerType.length()), ','), "=",
                    "\"");
            OAuth2Exception ex = OAuth2Exception.valueOf(headerEntries);
            if (ex instanceof InvalidTokenException) {
                // Special case: an invalid token can be renewed so tell the caller what to do
                throw new AccessTokenRequiredException(resource);
            }
            throw ex;
        }
    }

}
