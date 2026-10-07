package org.cloudfoundry.identity.uaa.provider.oauth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.Optional.ofNullable;

public class OidcMetadataFetcher {
    private static final ObjectMapper OBJECT_MAPPER = new JsonMapper();
    private static final int MAX_JWKS_RESPONSE_SIZE = 1024 * 1024; // 1MB limit for JWKS

    private final UrlContentCache contentCache;
    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final RestTemplate safeRestTemplate;
    private final IdpOutboundTrustCache trustCache;
    private final RestTemplateConfig restTemplateConfig;

    private final LoadingCache<String, JsonWebKeySet<JsonWebKey>> clientJwksCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(10_000)
            .build(this::fetchAndParseClientJwks);

    private final LoadingCache<JwksRequest, JsonWebKeySet<JsonWebKey>> idpJwksCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(10_000)
            .build(this::fetchAndParseIdpJwks);

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

        RestTemplate restTemplate = resolveRestTemplate(config);
        String authHeader = getClientAuthHeader(config);
        JwksRequest request = new JwksRequest(tokenKeyUrl.toString(), restTemplate, authHeader);

        if (config.isCacheJwks() && !hasCustomTrust(config)) {
            try {
                return idpJwksCache.get(request);
            } catch (Exception e) {
                if (e.getCause() instanceof OidcMetadataFetchingException) {
                    throw (OidcMetadataFetchingException) e.getCause();
                }
                throw new OidcMetadataFetchingException("Unable to fetch verification keys", e);
            }
        } else {
            return fetchAndParseIdpJwks(request);
        }
    }

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(ClientJwtConfiguration clientJwtConfiguration) throws OidcMetadataFetchingException {
        if (clientJwtConfiguration.getJwkSet() != null) {
            return clientJwtConfiguration.getJwkSet();
        } else if (clientJwtConfiguration.getJwksUri() != null) {
            String jwksUri = clientJwtConfiguration.getJwksUri();
            try {
                return clientJwksCache.get(jwksUri);
            } catch (Exception e) {
                if (e.getCause() instanceof OidcMetadataFetchingException) {
                    throw (OidcMetadataFetchingException) e.getCause();
                }
                throw new OidcMetadataFetchingException("Unable to fetch verification keys", e);
            }
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private JsonWebKeySet<JsonWebKey> fetchAndParseClientJwks(String jwksUri) throws OidcMetadataFetchingException {
        RestTemplate template = isLocalhost(jwksUri) ? nonTrustingRestTemplate : safeRestTemplate;
        byte[] rawContents = getResponseWithLimit(jwksUri, template, HttpMethod.GET, jsonRequestEntity(null), MAX_JWKS_RESPONSE_SIZE);
        if (rawContents != null && rawContents.length > 0) {
            ClientJwtConfiguration clientKeys = ClientJwtConfiguration.parse(null, new String(rawContents, StandardCharsets.UTF_8));
            if (clientKeys != null && clientKeys.getJwkSet() != null) {
                return clientKeys.getJwkSet();
            }
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private JsonWebKeySet<JsonWebKey> fetchAndParseIdpJwks(JwksRequest request) throws OidcMetadataFetchingException {
        byte[] rawContents = getResponseWithLimit(request.uri, request.template, HttpMethod.GET, jsonRequestEntity(request.authorizationValue), MAX_JWKS_RESPONSE_SIZE);
        if (rawContents == null || rawContents.length == 0) {
            throw new OidcMetadataFetchingException("Unable to fetch verification keys");
        }
        try {
            return JsonWebKeyHelper.deserialize(new String(rawContents, StandardCharsets.UTF_8));
        } catch (JsonUtils.JsonUtilException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    private byte[] getResponseWithLimit(String uri, RestTemplate restTemplate, HttpMethod method, HttpEntity<Object> header, int maxSize) {
        return restTemplate.execute(uri, method,
                request -> {
                    if (header != null) {
                        header.getHeaders().forEach((k, v) -> request.getHeaders().put(k, v));
                    }
                },
                response -> {
                    if (response.getStatusCode() == HttpStatus.OK) {
                        long contentLength = response.getHeaders().getContentLength();
                        if (contentLength > maxSize) {
                            throw new IllegalArgumentException("Response exceeds maximum allowed size");
                        }
                        InputStream is = response.getBody();
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buffer = new byte[8192];
                        int read;
                        int total = 0;
                        while ((read = is.read(buffer)) != -1) {
                            total += read;
                            if (total > maxSize) {
                                throw new IllegalArgumentException("Response exceeds maximum allowed size");
                            }
                            baos.write(buffer, 0, read);
                        }
                        return baos.toByteArray();
                    } else {
                        throw new IllegalArgumentException(
                                "Unable to fetch content, status:" + HttpStatus.resolve(response.getStatusCode().value()).getReasonPhrase());
                    }
                });
    }

    private static HttpEntity<Object> jsonRequestEntity(String authorizationValue) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        if (authorizationValue != null) {
            headers.add("Authorization", authorizationValue);
        }
        headers.add("Accept", "application/json,application/jwk-set+json");
        return new HttpEntity<>(null, headers);
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
        String clientAuth = Base64.getEncoder().encodeToString((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes(StandardCharsets.UTF_8));
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

    private static class JwksRequest {
        final String uri;
        final RestTemplate template;
        final String authorizationValue;

        JwksRequest(String uri, RestTemplate template, String authorizationValue) {
            this.uri = uri;
            this.template = template;
            this.authorizationValue = authorizationValue;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            JwksRequest that = (JwksRequest) o;
            return Objects.equals(uri, that.uri) &&
                   Objects.equals(template, that.template) &&
                   Objects.equals(authorizationValue, that.authorizationValue);
        }

        @Override
        public int hashCode() {
            return Objects.hash(uri, template, authorizationValue);
        }
    }
}
