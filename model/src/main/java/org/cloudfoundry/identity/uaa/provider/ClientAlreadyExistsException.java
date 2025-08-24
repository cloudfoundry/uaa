package org.cloudfoundry.identity.uaa.provider;

public class ClientAlreadyExistsException extends ClientRegistrationException {

    public ClientAlreadyExistsException(String msg) {
        super(msg);
    }

}
