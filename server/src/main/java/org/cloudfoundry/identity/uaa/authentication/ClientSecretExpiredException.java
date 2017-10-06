package org.cloudfoundry.identity.uaa.authentication;


import org.springframework.security.authentication.BadCredentialsException;

public class ClientSecretExpiredException extends BadCredentialsException {
    public ClientSecretExpiredException(String msg) {
        super(msg);
    }
}
