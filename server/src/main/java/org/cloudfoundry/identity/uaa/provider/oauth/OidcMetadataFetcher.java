package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(AbstractExternalOAuthIdentityProviderDefinition<?> config)
            throws OidcMetadataFetchingException {
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if (tokenKeyUrl == null || !org.springframework.util.StringUtils.hasText(tokenKeyUrl.toString())) {
            return new JsonWebKeySet<>(Collections.emptyList());
        }
        byte[] rawContents = getJsonBody(tokenKeyUrl.toString(), config.isSkipSslValidation(), config.isCacheJwks(), getClientAuthHeader(config));
        if (rawContents == null || rawContents.length == 0) {
            throw new OidcMetadataFetchingException("Unable to fetch verification keys");
        }
        try {
            return JsonWebKeyHelper.deserialize(new String(rawContents, StandardCharsets.UTF_8));
        } catch (JsonUtils.JsonUtilException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(ClientJwtConfiguration clientJwtConfiguration) throws OidcMetadataFetchingException {
        if (clientJwtConfiguration.getJwkSet() != null) {
            return clientJwtConfiguration.getJwkSet();
        } else if (clientJwtConfiguration.getJwksUri() != null) {
            byte[] rawContents = getJsonBody(clientJwtConfiguration.getJwksUri(), false, true, null);
            if (rawContents != null && rawContents.length > 0) {
                ClientJwtConfiguration clientKeys = ClientJwtConfiguration.parse(null, new String(rawContents, StandardCharsets.UTF_8));
                if (clientKeys != null && clientKeys.getJwkSet() != null) {
                    return clientKeys.getJwkSet();
                }
            }
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private byte[] getJsonBody(String uri, boolean isSkipSslValidation, boolean isCached, String authorizationValue) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        if (authorizationValue != null) {
            headers.add("Authorization", authorizationValue);
        }
        headers.add("Accept", "application/json,application/jwk-set+json");
        HttpEntity<Object> tokenKeyRequest = new HttpEntity<>(null, headers);
        if (isCached) {
            return getCachedResponse(uri, isSkipSslValidation, HttpMethod.GET, tokenKeyRequest);
        } else {
            return getResponse(uri, isSkipSslValidation, HttpMethod.GET, tokenKeyRequest);
        }
    }

    private byte[] getResponse(String uri, boolean isSkipSslValidation, HttpMethod method, HttpEntity<Object> header) {
        ResponseEntity<byte[]> responseEntity;
        if (isSkipSslValidation) {
            responseEntity = trustingRestTemplate.exchange(uri, method, header, byte[].class);
        } else {
            responseEntity = nonTrustingRestTemplate.exchange(uri, method, header, byte[].class);
        }
        if (responseEntity.getStatusCode() == HttpStatus.OK) {
            return responseEntity.getBody();
        } else {
            throw new IllegalArgumentException(
                    "Unable to fetch content, status:" + HttpStatus.resolve(responseEntity.getStatusCode().value()).getReasonPhrase());
        }
    }

    private byte[] getCachedResponse(String uri, boolean isSkipSslValidation, HttpMethod method, HttpEntity<Object> header) {
        if (isSkipSslValidation) {
            return contentCache.getUrlContent(uri, trustingRestTemplate, method, header);
        } else {
            return contentCache.getUrlContent(uri, nonTrustingRestTemplate, method, header);
        }
    }

    private String getClientAuthHeader(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        if (config.getRelyingPartySecret() == null) {
            return null;
        }
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
        definition.setLogoutUrl(ofNullable(definition.getLogoutUrl()).orElse(oidcMetadata.getLogoutEndpoint()));
    }

    private boolean shouldFetchMetadata(OIDCIdentityProviderDefinition definition) {
        return definition.getDiscoveryUrl() != null && !StringUtils.isBlank(definition.getDiscoveryUrl().toString());
    }
}
