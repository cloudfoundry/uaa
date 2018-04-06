package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;

public class MetadataFetcher {
    public byte[] fetch(FixedHttpMetaDataProvider provider) throws MetadataProviderException {
        return provider.fetchMetadata();
    }
}
