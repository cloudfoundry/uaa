package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;

public class SamlBindingNotSupportedException extends MetadataProviderException {
    public SamlBindingNotSupportedException() {
    }

    public SamlBindingNotSupportedException(String message) {
        super(message);
    }

    public SamlBindingNotSupportedException(Exception wrappedException) {
        super(wrappedException);
    }

    public SamlBindingNotSupportedException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}
