
package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.AuthenticationException;

public class AccountNotPreCreatedException extends AuthenticationException {
    public AccountNotPreCreatedException(String msg) {
        super(msg);
    }
}
