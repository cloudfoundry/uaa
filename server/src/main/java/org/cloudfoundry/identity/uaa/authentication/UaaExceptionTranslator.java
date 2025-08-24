package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;

public class UaaExceptionTranslator extends DefaultWebResponseExceptionTranslator {

    @Override
    public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
        if (e instanceof AccountNotVerifiedException) {
            return handleOAuth2Exception(new ForbiddenException(e.getMessage(), e));
        } else if (e instanceof BadCredentialsException) {
            return handleOAuth2Exception(OAuth2Exception.create(OAuth2Exception.INVALID_CLIENT, e.getMessage()));
        }

        return super.translate(e);
    }

    private ResponseEntity<OAuth2Exception> handleOAuth2Exception(OAuth2Exception e) {

        int status = e.getHttpErrorCode();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        if (status == HttpStatus.UNAUTHORIZED.value() && (e instanceof InvalidClientException)) {
            headers.set("WWW-Authenticate", "Basic error=\"unauthorized\", error_description=\"Bad credentials\"");
        }
        return new ResponseEntity<>(e, headers,
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
