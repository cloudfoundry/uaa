package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;

public class DisallowedIdpException extends UnauthorizedClientException {
    public DisallowedIdpException(String msg) {
        super(msg, null);
    }
}
