package org.cloudfoundry.identity.uaa.provider.oauth;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.Ticker;
import com.nimbusds.jose.jwk.JWKSet;
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
import org.cloudfoundry.identity.uaa.util.BoundedHttpFetch;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.RestTemplate;
import tools.jackson.core.JacksonException;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static java.util.Optional.ofNullable;

public class OidcMetadataFetcher implements DisposableBean {
    private static final ObjectMapper OBJECT_MAPPER = new JsonMapper();
    private static final int MAX_JWKS_RESPONSE_SIZE = 1024 * 1024;
    private static final int MAX_DISCOVERY_RESPONSE_SIZE = 1024 * 1024;
    private static final int MAX_IDP_JWKS_KEYS = 100;
    // Weights are an upper estimate of the heap an entry retains (see CachedKeySet#estimateRetainedBytes), so this
    // also approximates the heap each cache can pin.
    private static final long MAX_JWKS_CACHE_WEIGHT = 16L * 1024 * 1024;
    private static final Duration JWKS_CACHE_REFRESH = Duration.ofMinutes(10);
    private static final int JWKS_REFRESH_THREADS = 4;
    private static final int JWKS_REFRESH_QUEUE_CAPACITY = 1_000;

    private final UrlContentCache contentCache;
    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final RestTemplate safeRestTemplate;
    private final IdpOutboundTrustCache trustCache;
    private final RestTemplateConfig restTemplateConfig;

    // Background refreshes block on remote endpoints, so they must not run on the shared ForkJoinPool. A refresh the
    // full queue rejects is dropped by Caffeine and retried on a later read; the stale key set stays in use meanwhile.
    private final ThreadPoolExecutor jwksRefreshExecutor = newJwksRefreshExecutor();

    // refreshAfterWrite (not expireAfterWrite) keeps serving the last good key set if the remote endpoint is down.
    private final LoadingCache<String, CachedKeySet> clientJwksCache;
    private final LoadingCache<JwksRequest, CachedKeySet> idpJwksCache;

    private static ThreadPoolExecutor newJwksRefreshExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(JWKS_REFRESH_THREADS, JWKS_REFRESH_THREADS,
                1, TimeUnit.MINUTES, new ArrayBlockingQueue<>(JWKS_REFRESH_QUEUE_CAPACITY),
                Thread.ofPlatform().name("uaa-jwks-refresh-", 0).daemon(true).factory());
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

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
        this(contentCache, trustingRestTemplate, nonTrustingRestTemplate, safeRestTemplate, trustCache,
                restTemplateConfig, Ticker.systemTicker());
    }

    OidcMetadataFetcher(UrlContentCache contentCache,
            RestTemplate trustingRestTemplate,
            RestTemplate nonTrustingRestTemplate,
            RestTemplate safeRestTemplate,
            IdpOutboundTrustCache trustCache,
            RestTemplateConfig restTemplateConfig,
            Ticker ticker
    ) {
        this.contentCache = contentCache;
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
        this.safeRestTemplate = safeRestTemplate;
        this.trustCache = trustCache;
        this.restTemplateConfig = restTemplateConfig;
        this.clientJwksCache = Caffeine.newBuilder()
                .refreshAfterWrite(JWKS_CACHE_REFRESH)
                .maximumWeight(MAX_JWKS_CACHE_WEIGHT)
                .weigher((String uri, CachedKeySet entry) -> entry.weight())
                .executor(jwksRefreshExecutor)
                .ticker(ticker)
                .build(this::fetchAndParseClientJwks);
        this.idpJwksCache = Caffeine.newBuilder()
                .refreshAfterWrite(JWKS_CACHE_REFRESH)
                .maximumWeight(MAX_JWKS_CACHE_WEIGHT)
                .weigher((JwksRequest request, CachedKeySet entry) -> entry.weight())
                .executor(jwksRefreshExecutor)
                .ticker(ticker)
                .build(this::fetchAndParseIdpJwks);
    }

    @Override
    public void destroy() {
        jwksRefreshExecutor.shutdownNow();
    }

    ExecutorService jwksRefreshExecutor() {
        return jwksRefreshExecutor;
    }

    public void fetchMetadataAndUpdateDefinition(OIDCIdentityProviderDefinition definition) throws OidcMetadataFetchingException {
        if (shouldFetchMetadata(definition)) {
            OidcMetadata oidcMetadata = fetchMetadata(definition);
            updateIdpDefinition(definition, oidcMetadata);
        }
    }

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(AbstractExternalOAuthIdentityProviderDefinition<?> config)
            throws OidcMetadataFetchingException {
        return loadIdpKeys(config).keys();
    }

    /**
     * Returns the same keys as {@link #fetchWebKeySet(AbstractExternalOAuthIdentityProviderDefinition)} as a Nimbus
     * {@link JWKSet}. When the key set is served from the cache, the conversion happened once at load time.
     */
    public JWKSet fetchJwkSet(AbstractExternalOAuthIdentityProviderDefinition<?> config) throws OidcMetadataFetchingException {
        JwksRequest request = idpJwksRequest(config);
        if (request == null) {
            return CachedKeySet.EMPTY.jwkSet();
        }
        if (config.isCacheJwks()) {
            return getCachedJwkSet(idpJwksCache, request);
        }
        return fetchAndParseIdpJwks(request).jwkSet();
    }

    public JsonWebKeySet<JsonWebKey> fetchWebKeySet(ClientJwtConfiguration clientJwtConfiguration) throws OidcMetadataFetchingException {
        if (clientJwtConfiguration.getJwkSet() != null) {
            return clientJwtConfiguration.getJwkSet();
        } else if (clientJwtConfiguration.getJwksUri() != null) {
            return getCachedKeys(clientJwksCache, clientJwtConfiguration.getJwksUri()).keys();
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    /**
     * Returns the same keys as {@link #fetchWebKeySet(ClientJwtConfiguration)} as a Nimbus {@link JWKSet}. For a
     * {@code jwks_uri} the conversion happens once per cache load, not on every client authentication.
     */
    public JWKSet fetchJwkSet(ClientJwtConfiguration clientJwtConfiguration) throws OidcMetadataFetchingException {
        if (clientJwtConfiguration.getJwkSet() != null) {
            return CachedKeySet.of(clientJwtConfiguration.getJwkSet(), 0).jwkSet();
        } else if (clientJwtConfiguration.getJwksUri() != null) {
            return getCachedJwkSet(clientJwksCache, clientJwtConfiguration.getJwksUri());
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private CachedKeySet loadIdpKeys(AbstractExternalOAuthIdentityProviderDefinition<?> config) throws OidcMetadataFetchingException {
        JwksRequest request = idpJwksRequest(config);
        if (request == null) {
            return CachedKeySet.EMPTY;
        }
        if (config.isCacheJwks()) {
            return getCachedKeys(idpJwksCache, request);
        }
        return fetchAndParseIdpJwks(request);
    }

    // The key includes the resolved RestTemplate, which is distinct per trust configuration, so IdPs with custom
    // CA certificates are cached too without sharing entries across trust configurations.
    private JwksRequest idpJwksRequest(AbstractExternalOAuthIdentityProviderDefinition<?> config) {
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if (tokenKeyUrl == null || !org.springframework.util.StringUtils.hasText(tokenKeyUrl.toString())) {
            return null;
        }
        return new JwksRequest(tokenKeyUrl.toString(), resolveRestTemplate(config), getClientAuthHeader(config));
    }

    // A key set Nimbus rejects stays cached for its keys() callers, but jwkSet() callers would otherwise fail until the
    // regular refresh. Refresh it now so they retry on the next request, as they do after a failed fetch; Caffeine
    // runs at most one refresh per key at a time.
    private static <K> JWKSet getCachedJwkSet(LoadingCache<K, CachedKeySet> cache, K key)
            throws OidcMetadataFetchingException {
        CachedKeySet entry = getCachedKeys(cache, key);
        if (entry.parseError() != null) {
            cache.refresh(key);
        }
        return entry.jwkSet();
    }

    private static <K> CachedKeySet getCachedKeys(LoadingCache<K, CachedKeySet> cache, K key)
            throws OidcMetadataFetchingException {
        try {
            return cache.get(key);
        } catch (CompletionException e) {
            if (e.getCause() instanceof OidcMetadataFetchingException fetchingException) {
                throw fetchingException;
            }
            throw new OidcMetadataFetchingException("Unable to fetch verification keys", e.getCause());
        }
    }

    private CachedKeySet fetchAndParseClientJwks(String jwksUri) throws OidcMetadataFetchingException {
        RestTemplate template = isLocalhost(jwksUri) ? nonTrustingRestTemplate : safeRestTemplate;
        byte[] rawContents = getResponseWithLimit(jwksUri, template, jwksRequestCallback(null), MAX_JWKS_RESPONSE_SIZE, true);
        if (rawContents != null && rawContents.length > 0) {
            String json = new String(rawContents, StandardCharsets.UTF_8);
            requireAtMostKeys(json, ClientJwtConfiguration.MAX_KEY_SIZE);
            ClientJwtConfiguration clientKeys = ClientJwtConfiguration.parse(null, json);
            if (clientKeys != null && clientKeys.getJwkSet() != null) {
                return CachedKeySet.of(clientKeys.getJwkSet(), rawContents.length);
            }
        }
        throw new OidcMetadataFetchingException("Unable to fetch verification keys");
    }

    private CachedKeySet fetchAndParseIdpJwks(JwksRequest request) throws OidcMetadataFetchingException {
        byte[] rawContents = getResponseWithLimit(request.uri(), request.template(), jwksRequestCallback(request.authorizationValue()), MAX_JWKS_RESPONSE_SIZE, true);
        if (rawContents == null || rawContents.length == 0) {
            throw new OidcMetadataFetchingException("Unable to fetch verification keys");
        }
        String json = new String(rawContents, StandardCharsets.UTF_8);
        requireAtMostKeys(json, MAX_IDP_JWKS_KEYS);
        try {
            return CachedKeySet.of(JsonWebKeyHelper.deserialize(json), rawContents.length);
        } catch (JsonUtils.JsonUtilException e) {
            throw new OidcMetadataFetchingException(e);
        }
    }

    // A 1 MiB response of tiny keys maps to roughly 13 MB of key objects (and allocates ~50 MB while doing so),
    // so the key count is checked with a streaming pass before any key object is built.
    private static void requireAtMostKeys(String json, int maxKeys) throws OidcMetadataFetchingException {
        int count;
        try {
            count = JsonWebKeyHelper.countKeys(json);
        } catch (JsonUtils.JsonUtilException e) {
            throw new OidcMetadataFetchingException(e);
        }
        if (count > maxKeys) {
            throw new OidcMetadataFetchingException("JWK set has " + count + " keys, maximum is " + maxKeys);
        }
    }

    private static byte[] getResponseWithLimit(String uri, RestTemplate restTemplate, RequestCallback requestCallback, int maxSize, boolean requireOk) {
        return BoundedHttpFetch.fetch(restTemplate, restTemplate.getUriTemplateHandler().expand(uri), HttpMethod.GET,
                requestCallback, maxSize, requireOk);
    }

    private static RequestCallback jwksRequestCallback(String authorizationValue) {
        return request -> {
            if (authorizationValue != null) {
                request.getHeaders().add(HttpHeaders.AUTHORIZATION, authorizationValue);
            }
            request.getHeaders().add(HttpHeaders.ACCEPT, "application/json,application/jwk-set+json");
        };
    }

    private static boolean isLocalhost(String uri) {
        try {
            String host = java.net.URI.create(uri).getHost();
            return "localhost".equals(host);
        } catch (IllegalArgumentException _) {
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
                ? getResponseWithLimit(uri, restTemplate, restTemplate.acceptHeaderRequestCallback(byte[].class), MAX_DISCOVERY_RESPONSE_SIZE, false)
                : contentCache.getUrlContent(uri, restTemplate, MAX_DISCOVERY_RESPONSE_SIZE);
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

    private record JwksRequest(String uri, RestTemplate template, String authorizationValue) {
    }

    /**
     * A key set together with its Nimbus form, so cache hits do no per-request parsing. A key set Nimbus cannot parse
     * still yields {@link #keys()}; only {@link #jwkSet()} fails, as {@code JWKSet.parse} did for callers before.
     */
    private record CachedKeySet(JsonWebKeySet<JsonWebKey> keys, JWKSet parsedJwkSet, ParseException parseError, int weight) {
        static final CachedKeySet EMPTY = new CachedKeySet(new JsonWebKeySet<>(Collections.emptyList()), new JWKSet(), null, 0);

        // Measured retained heap for both key representations: 1.1-2.7x the raw JSON for realistic key sets, plus
        // roughly 0.6 KiB per key for sets of tiny keys; the cache key and node add a fixed amount per entry.
        private static final int RETAINED_BYTES_PER_RAW_BYTE = 2;
        private static final int RETAINED_BYTES_PER_KEY = 1024;
        private static final int RETAINED_BYTES_PER_ENTRY = 2 * 1024;

        static CachedKeySet of(JsonWebKeySet<JsonWebKey> keys, int rawLength) {
            int keyCount = keys.getKeys() == null ? 0 : keys.getKeys().size();
            int weight = estimateRetainedBytes(rawLength, keyCount);
            if (keyCount == 0) {
                return new CachedKeySet(keys, new JWKSet(), null, weight);
            }
            try {
                return new CachedKeySet(keys, JWKSet.parse(keys.getKeySetMap()), null, weight);
            } catch (ParseException e) {
                return new CachedKeySet(keys, null, e, weight);
            }
        }

        static int estimateRetainedBytes(int rawLength, int keyCount) {
            long estimate = (long) rawLength * RETAINED_BYTES_PER_RAW_BYTE
                    + (long) keyCount * RETAINED_BYTES_PER_KEY
                    + RETAINED_BYTES_PER_ENTRY;
            return (int) Math.min(Integer.MAX_VALUE, estimate);
        }

        JWKSet jwkSet() throws OidcMetadataFetchingException {
            if (parseError != null) {
                throw new OidcMetadataFetchingException("Unable to parse verification keys", parseError);
            }
            return parsedJwkSet;
        }
    }
}
