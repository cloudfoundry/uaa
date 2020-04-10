

package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.AuthenticationException;

public class AuthenticationPolicyRejectionException  extends AuthenticationException {
    public AuthenticationPolicyRejectionException(String msg, Throwable t) {
        super(msg, t);
    }

    public AuthenticationPolicyRejectionException(String msg) {
        super(msg);
    }
}
