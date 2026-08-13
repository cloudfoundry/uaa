package org.cloudfoundry.identity.uaa.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.util.PemCertificateParser;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds and caches, per identity key (e.g. IdP id or zone id -- callers decide what identity makes
 * sense for their protocol), a TLS trust context that validates against the JDK default cacerts trust
 * anchors plus a set of caller-supplied CA certificates, without touching the JVM/global truststore.
 * <p>
 * Cache entries are keyed by identity, not by a hash of the certificate content: staleness is detected
 * by comparing the incoming inputs against a stored snapshot via {@code equals()} on each read, and the
 * entry is rebuilt on a mismatch -- the same identity-keyed, equals-on-read-staleness idea as
 * {@code DynamicZoneAwareAuthenticationManager.getLdapAuthenticationManager}, but built on
 * {@code ConcurrentMap#compute} so the check-and-rebuild is atomic per key: concurrent callers racing on
 * the same stale key can never clobber a just-built fresh entry with a redundant rebuild.
 * <p>
 * {@code skipSslValidation} is treated as an escape hatch that is orthogonal to, and takes precedence
 * over, {@code caCertificates}: if set, callers get back their trust-everything fallback directly and
 * {@code caCertificates} is never consulted or cached.
 */
public class IdpOutboundTrustCache {

    private static final int DEFAULT_MAX_ENTRIES = 1_000;

    private final Cache<String, CachedSslContext> sslContexts;
    private final Cache<String, CachedRestTemplate> restTemplates;

    public IdpOutboundTrustCache() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public IdpOutboundTrustCache(int maxEntries) {
        this.sslContexts = Caffeine.newBuilder().maximumSize(maxEntries).build();
        this.restTemplates = Caffeine.newBuilder().maximumSize(maxEntries).build();
    }

    /**
     * Resolves the RestTemplate an HTTP-based consumer (OIDC, SAML) should use for a given identity.
     * Empty/absent caCertificates, or skipSslValidation=true, returns the caller-supplied fallback
     * unchanged -- callers must pass their own trusting/non-trusting pair since different consumers
     * (e.g. SAML's FixedHttpMetaDataProvider) use different timeout-tuned pairs, not one global pair.
     */
    public RestTemplate resolveRestTemplate(String identityKey, List<String> caCertificates, boolean skipSslValidation,
            int connectTimeout, int readTimeout, RestTemplateConfig restTemplateConfig,
            RestTemplate trustingFallback, RestTemplate nonTrustingFallback) {
        if (skipSslValidation) {
            return trustingFallback;
        }
        if (caCertificates == null || caCertificates.isEmpty()) {
            return nonTrustingFallback;
        }
        TrustInputs inputs = new TrustInputs(List.copyOf(caCertificates), false);
        SSLContext sslContext = getOrBuildSslContext(identityKey, inputs);
        return getOrBuildRestTemplate(identityKey, inputs, sslContext, connectTimeout, readTimeout, restTemplateConfig);
    }

    /**
     * Resolves the raw SSLContext for a non-RestTemplate consumer (the LDAP socket factory doesn't use
     * RestTemplate at all). Returns null for the empty/absent/skip-validation cases -- callers fall back
     * to their own existing default/skip SSLContext construction in that case, exactly as today.
     */
    public SSLContext resolveSslContext(String identityKey, List<String> caCertificates, boolean skipSslValidation) {
        if (skipSslValidation || caCertificates == null || caCertificates.isEmpty()) {
            return null;
        }
        TrustInputs inputs = new TrustInputs(List.copyOf(caCertificates), false);
        return getOrBuildSslContext(identityKey, inputs);
    }

    private SSLContext getOrBuildSslContext(String identityKey, TrustInputs inputs) {
        // ConcurrentMap#compute is atomic per key, so a stale-vs-fresh race between two callers can't
        // clobber a just-built fresh entry with a redundant rebuild -- exactly one build wins per
        // actual content transition.
        return sslContexts.asMap().compute(identityKey, (key, existing) ->
                        (existing != null && existing.inputs().equals(inputs))
                                ? existing
                                : new CachedSslContext(inputs, buildSslContext(inputs.caCertificates())))
                .sslContext();
    }

    private RestTemplate getOrBuildRestTemplate(String identityKey, TrustInputs inputs, SSLContext sslContext,
            int connectTimeout, int readTimeout, RestTemplateConfig restTemplateConfig) {
        return restTemplates.asMap().compute(identityKey, (key, existing) ->
                        (existing != null && existing.inputs().equals(inputs))
                                ? existing
                                : new CachedRestTemplate(inputs, new RestTemplate(UaaHttpRequestUtils.createRequestFactory(
                                        sslContext, connectTimeout, readTimeout, restTemplateConfig))))
                .restTemplate();
    }

    /**
     * Builds an X509TrustManager that additively trusts the JDK default cacerts trust anchors plus the
     * supplied CA certificates. Package-private so tests can exercise it directly via
     * getAcceptedIssuers()/checkServerTrusted() without reaching through SSLContext internals.
     */
    static X509TrustManager buildMergedTrustManager(List<String> pemCaCertificates) {
        try {
            List<X509Certificate> customCaCertificates = PemCertificateParser.parseCertificates(pemCaCertificates);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

            TrustManagerFactory defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            defaultTmf.init((KeyStore) null);
            int defaultIndex = 0;
            for (TrustManager tm : defaultTmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509Tm) {
                    for (X509Certificate cert : x509Tm.getAcceptedIssuers()) {
                        trustStore.setCertificateEntry("default-ca-" + defaultIndex++, cert);
                    }
                }
            }

            int customIndex = 0;
            for (X509Certificate cert : customCaCertificates) {
                trustStore.setCertificateEntry("custom-ca-" + customIndex++, cert);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509Tm) {
                    return x509Tm;
                }
            }
            throw new IllegalStateException("No X509TrustManager available from TrustManagerFactory.");
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Unable to build merged trust manager for custom CA certificates.", e);
        }
    }

    private static SSLContext buildSslContext(List<String> pemCaCertificates) {
        try {
            X509TrustManager trustManager = buildMergedTrustManager(pemCaCertificates);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to build merged trust SSLContext for custom CA certificates.", e);
        }
    }

    private record TrustInputs(List<String> caCertificates, boolean skipSslValidation) {
    }

    private record CachedSslContext(TrustInputs inputs, SSLContext sslContext) {
    }

    private record CachedRestTemplate(TrustInputs inputs, RestTemplate restTemplate) {
    }
}
