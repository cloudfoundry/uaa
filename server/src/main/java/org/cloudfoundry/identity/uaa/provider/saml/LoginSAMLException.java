package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.authentication.BadCredentialsException;

public class LoginSAMLException extends BadCredentialsException {
    /**
     * Generated serialization id.
     */
    private static final long serialVersionUID = 9115629621572693116L;

    /**
     * Constructs a <code>LoginSAMLAddUserNotAllowException</code> with the
     * specified message.
     * 
     * @param msg
     *            the detail message
     */
    public LoginSAMLException(final String msg) {
        super(msg);
    }

    public LoginSAMLException(final String msg, final Throwable e) {
        super(msg, e);
    }
}
