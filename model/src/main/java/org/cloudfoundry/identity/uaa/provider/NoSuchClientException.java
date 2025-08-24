package org.cloudfoundry.identity.uaa.provider;

public class NoSuchClientException extends ClientRegistrationException {

    public NoSuchClientException(String msg) {
        super(msg);
    }

}
