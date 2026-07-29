package org.cloudfoundry.identity.uaa.provider.oauth;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import tools.jackson.core.JacksonException;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static java.util.Optional.ofNullable;

public class OidcMetadataFetcher {
    private static final ObjectMapper OBJECT_MAPPER = new JsonMapper();

    private final UrlContentCache contentCache;
    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final RestTemplate safeRestTemplate;
    private final IdpOutboundTrustCache trustCache;
    private final RestTemplateConfig restTemplateConfig;

    public OidcMetadataFetcher(UrlContentCache contentCache,
            RestTemplate trustingRestTemplate,
            RestTemplate nonTrustingRestTemplate
    ) {
        this(contentCache, trustingRestTemplate, nonTrustingRestTemplate, nonTrustingRestTemplate);
    }

    public OidcMetadataFetcher(UrlContentCache contentCache,
            RestTemplate trustingRestTemplate,
            RestTemplate nonTrustingRestTemplate,
            RestTemplate safeRestTemplate
    ) {
        this(contentCache, trustingRestTemplate, nonTrustingRestTemplate, safeRestTemplate,
                new IdpOutboundTrustCache(), RestTemplateConfig.createDefaults());
    }

    public OidcMetadataFetcher(UrlContentCache contentCache,
            RestTemplate trustingRestTemplate,
            RestTemplate nonTrustingRestTemplate,
            RestTemplate safeRestTemplate,
            IdpOutboundTrustCache trustCache,
            RestTemplateConfig restTemplateConfig
    ) {
        this.contentCache = contentCache;
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
        this.safeRestTemplate = safeRestTemplate;
        this.trustCache = trustCache;
        this.restTemplateConfig = restTemplateConfig;
    }

    public void fetchMetadataAndUpdateDefinition(OIDCIdentityProviderDefinition definition) throws OidcMetadataFetchingException {
        if (shouldFetchMetadata(definition)) {
            OidcMetadata oidcMetadata = fetchMetadata(definition);
            updateIdpDefinition(definition, oidcMetadata);
        }
    }

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(AbstractExternalOAuthIdentityProviderDefinition<?> config)
            throws OidcMetadataFetchingException {
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if (tokenKeyUrl == null || !org.springframework.util.StringUtils.hasText(tokenKeyUrl.toString())) {
            return new JsonWebKeySet<>(Collections.emptyList());
        }
        byte[] rawContents = getJsonBody(tokenKeyUrl.toString(), config, config.isCacheJwks(), getClientAuthHeader(config));
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
            String jwksUri = clientJwtConfiguration.getJwksUri();
            // Client JWKS (private_key_jwt) is a different trust boundary than the IdP's own endpoints --
            // it relies on the client's own public infra, not the private-CA IdP -- so it intentionally
            // never consults caCertificates. localhost is allowed via nonTrustingRestTemplate (local/test
            // scenarios); everything else goes through safeRestTemplate for SSRF protection.
            RestTemplate template = isLocalhost(jwksUri) ? nonTrustingRestTemplate : safeRestTemplate;
            byte[] rawContents = getJsonBody(jwksUri, template, true, null);
            if (rawContents != null && rawContents.length > 0) {
                ClientJwtConfiguration clientKeys = ClientJwtConfiguration.parse(null, new String(rawContents, StandardCharsets.UTF_8));
                if (clientKeys != null && clientKeys.getJwkSet() != null) {
                    return clientKeys.getJwkSet();
                }
            }
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private byte[] getJsonBody(String uri, AbstractExternalOAuthIdentityProviderDefinition<?> config, boolean isCached, String authorizationValue) {
        HttpEntity<Object> tokenKeyRequest = jsonRequestEntity(authorizationValue);
        RestTemplate restTemplate = resolveRestTemplate(config);
        if (isCached && !hasCustomTrust(config)) {
            return contentCache.getUrlContent(uri, restTemplate, HttpMethod.GET, tokenKeyRequest);
        }
        return getResponse(uri, restTemplate, HttpMethod.GET, tokenKeyRequest);
    }

    private byte[] getJsonBody(String uri, RestTemplate restTemplate, boolean isCached, String authorizationValue) {
        HttpEntity<Object> tokenKeyRequest = jsonRequestEntity(authorizationValue);
        if (isCached) {
            return contentCache.getUrlContent(uri, restTemplate, HttpMethod.GET, tokenKeyRequest);
        }
        return getResponse(uri, restTemplate, HttpMethod.GET, tokenKeyRequest);
    }

    private static HttpEntity<Object> jsonRequestEntity(String authorizationValue) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        if (authorizationValue != null) {
            headers.add("Authorization", authorizationValue);
        }
        headers.add("Accept", "application/json,application/jwk-set+json");
        return new HttpEntity<>(null, headers);
    }

    private byte[] getResponse(String uri, RestTemplate restTemplate, HttpMethod method, HttpEntity<Object> header) {
        ResponseEntity<byte[]> responseEntity = restTemplate.exchange(uri, method, header, byte[].class);
        if (responseEntity.getStatusCode() == HttpStatus.OK) {
            return responseEntity.getBody();
        } else {
            throw new IllegalArgumentException(
                    "Unable to fetch content, status:" + HttpStatus.resolve(responseEntity.getStatusCode().value()).getReasonPhrase());
        }
    }

    private static boolean isLocalhost(String uri) {
        try {
            String host = java.net.URI.create(uri).getHost();
            return "localhost".equals(host);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String getClientAuthHeader(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        if (config.getRelyingPartySecret() == null) {
            return null;
        }
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
    }

    private OidcMetadata fetchMetadata(OIDCIdentityProviderDefinition definition) throws OidcMetadataFetchingException {
        String uri = definition.getDiscoveryUrl().toString();
        RestTemplate restTemplate = resolveRestTemplate(definition);
        // A per-IdP merged-trust RestTemplate can't safely share contentCache's entries with other
        // IdPs/zones that happen to point at the same discoveryUrl but a different trust config --
        // contentCache keys purely on the URL, not on which RestTemplate fetched it -- so bypass the
        // cache entirely whenever caCertificates is in play.
        byte[] rawContents = hasCustomTrust(definition)
                ? restTemplate.getForObject(uri, byte[].class)
                : contentCache.getUrlContent(uri, restTemplate);
        try {
            return OBJECT_MAPPER.readValue(rawContents, OidcMetadata.class);
        } catch (JacksonException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    private RestTemplate resolveRestTemplate(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        return trustCache.resolveRestTemplate(identityKeyFor(config), config.getCaCertificates(), config.isSkipSslValidation(),
                restTemplateConfig.timeout, restTemplateConfig.timeout, restTemplateConfig, trustingRestTemplate, nonTrustingRestTemplate);
    }

    private static boolean hasCustomTrust(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        return !config.isSkipSslValidation() && config.getCaCertificates() != null && !config.getCaCertificates().isEmpty();
    }

    /**
     * OidcMetadataFetcher's callers (ExternalOAuthProviderConfigurator, JwtClientAuthentication,
     * ExternalOAuthLogoutSuccessHandler, ExternalOAuthAuthenticationManager) only ever hand this class the
     * IdP's config object, not the owning IdentityProvider entity/id -- so the cache identity key is
     * derived from stable, already-available config content instead. This is safe regardless of
     * uniqueness: IdpOutboundTrustCache's own equals-on-read check against the actual caCertificates
     * content is what guarantees correct trust material is returned, not the quality of this key -- a
     * key collision (e.g. two IdPs sharing a discoveryUrl with different CAs) only costs a redundant
     * rebuild, it can never return the wrong IdP's trust material.
     */
    private static String identityKeyFor(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        if (config instanceof OIDCIdentityProviderDefinition oidc && oidc.getDiscoveryUrl() != null) {
            return oidc.getDiscoveryUrl().toString();
        }
        if (config.getTokenUrl() != null) {
            return config.getTokenUrl().toString();
        }
        if (config.getIssuer() != null) {
            return config.getIssuer();
        }
        return String.valueOf(config.hashCode());
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
