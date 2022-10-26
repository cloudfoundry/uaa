package org.cloudfoundry.identity.uaa.error;

public class UaaDBException extends RuntimeException {

    public UaaDBException(String msg) {
        super(msg);
    }

    public UaaDBException(String msg, Exception ex) {
        super(msg, ex);
    }

}