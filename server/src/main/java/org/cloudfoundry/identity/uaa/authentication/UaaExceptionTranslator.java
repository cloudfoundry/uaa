package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;

public class UaaExceptionTranslator extends DefaultWebResponseExceptionTranslator {

    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
        if (e instanceof AccountNotVerifiedException) {
            return handleOAuth2Exception(new ForbiddenException(e.getMessage(), e));
        }

        return super.translate(e);
    }

    private ResponseEntity<OAuth2Exception> handleOAuth2Exception(OAuth2Exception e) {

        int status = e.getHttpErrorCode();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");

        return new ResponseEntity<OAuth2Exception>(e, headers,
            HttpStatus.valueOf(status));

    }

    private static class ForbiddenException extends OAuth2Exception {

        public ForbiddenException(String msg, Throwable t) {
            super(msg, t);
        }

        public String getOAuth2ErrorCode() {
            return "access_denied";
        }

        public int getHttpErrorCode() {
            return 403;
        }

    }
}
