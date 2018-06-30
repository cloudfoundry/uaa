package org.cloudfoundry.identity.uaa.cypto;

public class EncryptionServiceException extends Throwable {
    public EncryptionServiceException(Exception e) {
        super(e);
    }
}
