package org.cloudfoundry.identity.uaa.oauth.advice;

import org.cloudfoundry.identity.uaa.oauth.provider.error.WebResponseExceptionTranslator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.IntrospectEndpoint;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import static org.springframework.http.HttpStatus.NOT_ACCEPTABLE;

@ControllerAdvice(assignableTypes = {CheckTokenEndpoint.class, IntrospectEndpoint.class, UaaTokenEndpoint.class})
public class HttpMethodNotSupportedAdvice {

    protected final Logger logger = LoggerFactory.getLogger(getClass());
    private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<OAuth2Exception> handleMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        logger.info("Handling error: {}, {}", e.getClass().getSimpleName(), e.getMessage());
        ResponseEntity<OAuth2Exception> result = exceptionTranslator.translate(e);
        if (HttpMethod.POST.matches(e.getMethod())) {
            OAuth2Exception cause = new OAuth2Exception("Parameters must be passed in the body of the request", result.getBody().getCause()) {
                public String getOAuth2ErrorCode() {
                    return "query_string_not_allowed";
                }

                public int getHttpErrorCode() {
                    return NOT_ACCEPTABLE.value();
                }
            };
            result = new ResponseEntity<>(cause, result.getHeaders(), NOT_ACCEPTABLE);
        }
        return result;
    }

}
