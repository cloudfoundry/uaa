package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.xml.security.credential.Credential;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.trust.MetadataCredentialResolver;

import java.util.Collection;


public class NonCachingMetadataCredentialResolver extends MetadataCredentialResolver {

    public NonCachingMetadataCredentialResolver(MetadataManager metadataProvider, KeyManager keyManager) {
        super(metadataProvider, keyManager);
    }

    @Override
    protected void cacheCredentials(MetadataCacheKey cacheKey, Collection<Credential> credentials) {
        //no op
    }
}
