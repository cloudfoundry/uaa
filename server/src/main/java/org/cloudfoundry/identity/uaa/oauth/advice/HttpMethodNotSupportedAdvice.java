package org.cloudfoundry.identity.uaa.oauth.advice;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.IntrospectEndpoint;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import static org.springframework.http.HttpStatus.NOT_ACCEPTABLE;

@ControllerAdvice(assignableTypes = {CheckTokenEndpoint.class, IntrospectEndpoint.class, UaaTokenEndpoint.class})
public class HttpMethodNotSupportedAdvice {

    protected final Log logger = LogFactory.getLog(getClass());
    private WebResponseExceptionTranslator exceptionTranslator = new DefaultWebResponseExceptionTranslator();

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<OAuth2Exception> handleMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        logger.info("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage());
        ResponseEntity<OAuth2Exception> result =  exceptionTranslator.translate(e);
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
