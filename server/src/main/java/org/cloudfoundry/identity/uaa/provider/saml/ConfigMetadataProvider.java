package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;

@Slf4j
public class ConfigMetadataProvider /* extends AbstractMetadataProvider */ implements ComparableProvider {

    private final String metadata;
    @Getter
    private final String zoneId;
    @Getter
    private final String alias;

    public ConfigMetadataProvider(String zoneId, String alias, String metadata) {
        this.metadata = metadata;
        this.alias = alias;
        this.zoneId = zoneId;
    }

    public byte[] fetchMetadata() {
        return metadata.getBytes(StandardCharsets.UTF_8);
    }

    @Override
//    public XMLObject doGetMetadata() throws MetadataProviderException {
//
//        InputStream stream = new ByteArrayInputStream(metadata.getBytes(StandardCharsets.UTF_8));
//
//        try {
//            return unmarshallMetadata(stream);
//        } catch (UnmarshallingException e) {
//            log.error("Unable to unmarshall metadata", e);
//            throw new MetadataProviderException(e);
//        }
//    }

//    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ComparableProvider)) return false;
        return this.compareTo((ComparableProvider) o) == 0;
    }

    @Override
    public int hashCode() {
        return getHashCode();
    }
}
