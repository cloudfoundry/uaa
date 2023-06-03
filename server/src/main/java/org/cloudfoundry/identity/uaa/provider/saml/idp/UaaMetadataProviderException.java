package org.cloudfoundry.identity.uaa.provider.saml.idp;

public class UaaMetadataProviderException extends Exception {
    public UaaMetadataProviderException() {
    }
    public UaaMetadataProviderException(String message) {
        super(message);
    }
    public UaaMetadataProviderException(String message, Throwable cause) {
        super(message, cause);
    }
    public UaaMetadataProviderException(Exception wrappedException) {
        super(wrappedException);
    }
}
