package org.cloudfoundry.identity.uaa.provider.oauth;

public class OidcMetadataFetchingException extends Exception {
    public OidcMetadataFetchingException(String message) {
        super(message);
    }

    public OidcMetadataFetchingException(String message, Throwable cause) {
        super(message, cause);
    }

    public OidcMetadataFetchingException(Throwable cause) {
        super(cause);
    }
}
