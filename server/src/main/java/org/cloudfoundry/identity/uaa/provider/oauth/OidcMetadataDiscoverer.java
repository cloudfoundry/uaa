package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;

public class OidcMetadataDiscoverer {
    private final UrlContentCache contentCache;
    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;

    public OidcMetadataDiscoverer(UrlContentCache contentCache,
                                  RestTemplate trustingRestTemplate,
                                  RestTemplate nonTrustingRestTemplate
    ) {
        this.contentCache = contentCache;
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
    }

    public void performDiscoveryAndUpdateDefinition(OIDCIdentityProviderDefinition definition) throws IOException {
        if (shouldPerformDiscovery(definition)) {
            OidcMetadata oidcMetadata =
                    performDiscovery(definition.getDiscoveryUrl(), definition.isSkipSslValidation());

            updateIdpDefinition(definition, oidcMetadata);
        }
    }

    private OidcMetadata performDiscovery(URL discoveryUrl, boolean shouldDoSslValidation) throws IOException {
        byte[] rawContents;
        if (shouldDoSslValidation) {
            rawContents = contentCache.getUrlContent(discoveryUrl.toString(), trustingRestTemplate);
        } else {
            rawContents = contentCache.getUrlContent(discoveryUrl.toString(), nonTrustingRestTemplate);
        }
        return new ObjectMapper().readValue(rawContents, OidcMetadata.class);
    }

    private void updateIdpDefinition(OIDCIdentityProviderDefinition definition, OidcMetadata oidcMetadata) {
        definition.setAuthUrl(oidcMetadata.getAuthorizationEndpoint());
        definition.setTokenUrl(oidcMetadata.getTokenEndpoint());
        definition.setTokenKeyUrl(oidcMetadata.getJsonWebKeysUri());
        definition.setUserInfoUrl(oidcMetadata.getUserinfoEndpoint());
        definition.setIssuer(oidcMetadata.getIssuer());
    }

    private boolean shouldPerformDiscovery(OIDCIdentityProviderDefinition definition) {
        return definition.getDiscoveryUrl() != null && !StringUtils.isBlank(definition.getDiscoveryUrl().toString());
    }
}
