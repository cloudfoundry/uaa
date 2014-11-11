package org.cloudfoundry.identity.uaa.login;

import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class ConfigMetadataProvider extends AbstractMetadataProvider {

    private final Logger log = LoggerFactory.getLogger(ConfigMetadataProvider.class);

    private String metadata;

    public ConfigMetadataProvider(String metadata) {
        this.metadata = metadata;
    }

    @Override
    protected XMLObject doGetMetadata() throws MetadataProviderException {

        InputStream stream = new ByteArrayInputStream(metadata.getBytes(StandardCharsets.UTF_8));

        try {
            return unmarshallMetadata(stream);
        } catch (UnmarshallingException e) {
            log.error("Unable to unmarshall metadata", e);
            throw new MetadataProviderException(e);
        }
    }
}
