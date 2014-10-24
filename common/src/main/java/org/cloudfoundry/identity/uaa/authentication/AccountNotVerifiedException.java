package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.authentication.AccountStatusException;

public class AccountNotVerifiedException extends AccountStatusException {
    public AccountNotVerifiedException(String msg) {
        super(msg);
    }
}
