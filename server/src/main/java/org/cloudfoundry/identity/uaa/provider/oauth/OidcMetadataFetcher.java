package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

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

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(AbstractExternalOAuthIdentityProviderDefinition config)
        throws OidcMetadataFetchingException {
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if (tokenKeyUrl == null || !org.springframework.util.StringUtils.hasText(tokenKeyUrl.toString())) {
            return new JsonWebKeySet<>(Collections.emptyList());
        }
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", getClientAuthHeader(config));
        headers.add("Accept", "application/json");
        HttpEntity tokenKeyRequest = new HttpEntity<>(null, headers);
        byte[] rawContents;
        if (config.isSkipSslValidation()) {
            rawContents = contentCache.getUrlContent(tokenKeyUrl.toString(), trustingRestTemplate, HttpMethod.GET, tokenKeyRequest);
        } else {
            rawContents = contentCache.getUrlContent(tokenKeyUrl.toString(), nonTrustingRestTemplate, HttpMethod.GET, tokenKeyRequest);
        }
        if (rawContents == null || rawContents.length == 0) {
            throw new OidcMetadataFetchingException("Unable to fetch verification keys");
        }
        try {
            return JsonWebKeyHelper.deserialize(new String(rawContents, StandardCharsets.UTF_8));
        } catch (JsonUtils.JsonUtilException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    private String getClientAuthHeader(AbstractExternalOAuthIdentityProviderDefinition config) {
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
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
