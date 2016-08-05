package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;

public class DisallowedIdpException extends UnauthorizedClientException {
    public DisallowedIdpException(String msg) {
        super(msg, null);
    }
}
