package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;

public class MetadataProviderNotFoundException extends MetadataProviderException {
    public MetadataProviderNotFoundException() {
    }

    public MetadataProviderNotFoundException(String message) {
        super(message);
    }

    public MetadataProviderNotFoundException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }

    public MetadataProviderNotFoundException(Exception wrappedException) {
        super(wrappedException);
    }
}
