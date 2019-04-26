package org.cloudfoundry.identity.uaa.cypto;

public class NoActiveEncryptionKeyProvided extends RuntimeException {
    public NoActiveEncryptionKeyProvided(String message) {
        super(message);
    }
}
