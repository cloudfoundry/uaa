package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;

import static java.util.Optional.ofNullable;

public class OidcMetadataFetcher {
    private final UrlContentCache contentCache;
    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;

    public OidcMetadataFetcher(UrlContentCache contentCache,
                               RestTemplate trustingRestTemplate,
                               RestTemplate nonTrustingRestTemplate
    ) {
        this.contentCache = contentCache;
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
    }

    public void fetchMetadataAndUpdateDefinition(OIDCIdentityProviderDefinition definition) throws OidcMetadataFetchingException {
        if (shouldFetchMetadata(definition)) {
            OidcMetadata oidcMetadata =
                    fetchMetadata(definition.getDiscoveryUrl(), definition.isSkipSslValidation());

            updateIdpDefinition(definition, oidcMetadata);
        }
    }

    private OidcMetadata fetchMetadata(URL discoveryUrl, boolean shouldDoSslValidation) throws OidcMetadataFetchingException {
        byte[] rawContents;
        if (shouldDoSslValidation) {
            rawContents = contentCache.getUrlContent(discoveryUrl.toString(), trustingRestTemplate);
        } else {
            rawContents = contentCache.getUrlContent(discoveryUrl.toString(), nonTrustingRestTemplate);
        }
        try {
            return new ObjectMapper().readValue(rawContents, OidcMetadata.class);
        } catch (IOException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    private void updateIdpDefinition(OIDCIdentityProviderDefinition definition, OidcMetadata oidcMetadata) {
        definition.setAuthUrl(ofNullable(definition.getAuthUrl()).orElse(oidcMetadata.getAuthorizationEndpoint()));
        definition.setTokenUrl(ofNullable(definition.getTokenUrl()).orElse(oidcMetadata.getTokenEndpoint()));
        definition.setTokenKeyUrl(ofNullable(definition.getTokenKeyUrl()).orElse(oidcMetadata.getJsonWebKeysUri()));
        definition.setUserInfoUrl(ofNullable(definition.getUserInfoUrl()).orElse(oidcMetadata.getUserinfoEndpoint()));
        definition.setIssuer(ofNullable(definition.getIssuer()).orElse(oidcMetadata.getIssuer()));
    }

    private boolean shouldFetchMetadata(OIDCIdentityProviderDefinition definition) {
        return definition.getDiscoveryUrl() != null && !StringUtils.isBlank(definition.getDiscoveryUrl().toString());
    }
}
