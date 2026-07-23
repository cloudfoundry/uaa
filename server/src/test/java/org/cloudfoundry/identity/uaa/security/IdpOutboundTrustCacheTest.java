package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.util.SocketUtils.getSelfCertificate;

class IdpOutboundTrustCacheTest {

    private static final String IDENTITY_KEY = "test-idp";

    private IdpOutboundTrustCache cache;
    private RestTemplate trustingFallback;
    private RestTemplate nonTrustingFallback;
    private RestTemplateConfig restTemplateConfig;

    private static String testCaCertificatePem;
    private static String otherTestCaCertificatePem;

    @BeforeAll
    static void generateTestCertificates() throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        testCaCertificatePem = pemEncode(selfSignedCertificate("test-ca-one"));
        otherTestCaCertificatePem = pemEncode(selfSignedCertificate("test-ca-two"));
    }

    @BeforeEach
    void setup() {
        cache = new IdpOutboundTrustCache();
        trustingFallback = new RestTemplate();
        nonTrustingFallback = new RestTemplate();
        restTemplateConfig = RestTemplateConfig.createDefaults();
    }

    private RestTemplate resolveRestTemplate(List<String> caCertificates, boolean skipSslValidation) {
        return cache.resolveRestTemplate(IDENTITY_KEY, caCertificates, skipSslValidation,
                1000, 1000, restTemplateConfig, trustingFallback, nonTrustingFallback);
    }

    @Nested
    class ResolveRestTemplate {

        @Test
        void sameCertListContentTwice_returnsSameCachedInstance() {
            RestTemplate first = resolveRestTemplate(List.of(testCaCertificatePem), false);
            RestTemplate second = resolveRestTemplate(List.of(testCaCertificatePem), false);
            assertThat(second).isSameAs(first);
        }

        @Test
        void changedCertList_buildsNewInstanceAndDiscardsOld() {
            RestTemplate first = resolveRestTemplate(List.of(testCaCertificatePem), false);
            RestTemplate second = resolveRestTemplate(List.of(otherTestCaCertificatePem), false);
            assertThat(second).isNotSameAs(first);
        }

        @ParameterizedTest
        @NullAndEmptySource
        void emptyOrAbsentCerts_returnsExactNonTrustingFallbackByReference(List<String> caCertificates) {
            assertThat(resolveRestTemplate(caCertificates, false)).isSameAs(nonTrustingFallback);
        }

        @Test
        void skipSslValidationTrue_returnsTrustingFallback_evenWithCaCertificatesSet() {
            assertThat(resolveRestTemplate(List.of(testCaCertificatePem), true)).isSameAs(trustingFallback);
        }
    }

    @Nested
    class ResolveSslContext {

        @Test
        void sameCertListContentTwice_returnsSameCachedInstance() {
            SSLContext first = cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), false);
            SSLContext second = cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), false);
            assertThat(second).isSameAs(first);
        }

        @Test
        void changedCertList_buildsNewInstanceAndDiscardsOld() {
            SSLContext first = cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), false);
            SSLContext second = cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false);
            assertThat(second).isNotSameAs(first);
        }

        @ParameterizedTest
        @NullAndEmptySource
        void emptyOrAbsentCerts_returnsNull(List<String> caCertificates) {
            assertThat(cache.resolveSslContext(IDENTITY_KEY, caCertificates, false)).isNull();
        }

        @Test
        void skipSslValidationTrue_returnsNull_evenWithCaCertificatesSet() {
            assertThat(cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), true)).isNull();
        }
    }

    @Test
    void buildMergedTrustManager_trustsBothDefaultCaAndCustomCa() throws Exception {
        TrustManagerFactory defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        defaultTmf.init((KeyStore) null);
        X509Certificate[] defaultIssuers = Arrays.stream(defaultTmf.getTrustManagers())
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .findFirst()
                .orElseThrow()
                .getAcceptedIssuers();

        X509Certificate testCa = decodePem(testCaCertificatePem);
        X509TrustManager merged = IdpOutboundTrustCache.buildMergedTrustManager(List.of(testCaCertificatePem));

        assertThat(merged.getAcceptedIssuers()).contains(defaultIssuers);
        assertThat(merged.getAcceptedIssuers()).contains(testCa);
        merged.checkServerTrusted(new X509Certificate[]{testCa}, "RSA");
    }

    @Test
    void concurrentAccessOnStaleKey_doesNotCorruptCache() throws Exception {
        cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), false);

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<SSLContext>> tasks = List.of(
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false),
                    () -> cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false));
            List<Future<SSLContext>> futures = executor.invokeAll(tasks, 10, SECONDS);

            SSLContext first = futures.get(0).get();
            assertThat(first).isNotNull();
            for (Future<SSLContext> future : futures) {
                assertThat(future.get()).isSameAs(first);
            }
            assertThat(cache.resolveSslContext(IDENTITY_KEY, List.of(otherTestCaCertificatePem), false)).isSameAs(first);
        } finally {
            executor.shutdownNow();
        }
    }

    @Nested
    class RestTemplateActuallyValidatesAgainstMergedTrust {

        @Test
        void createRequestFactory_withMergedSslContext_isUsableForRealRequests() {
            SSLContext sslContext = cache.resolveSslContext(IDENTITY_KEY, List.of(testCaCertificatePem), false);
            RestTemplate restTemplate = new RestTemplate(
                    UaaHttpRequestUtils.createRequestFactory(sslContext, 1000, 1000, restTemplateConfig));
            assertThat(restTemplate).isNotNull();
        }
    }

    private static X509Certificate selfSignedCertificate(String commonName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return getSelfCertificate(keyPair, "UAA Test", "UAA Test Unit", commonName, new Date(), 60L * 60, "SHA256withRSA");
    }

    private static String pemEncode(X509Certificate certificate) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    private static X509Certificate decodePem(String pem) {
        return org.cloudfoundry.identity.uaa.util.PemCertificateParser.parseCertificate(pem);
    }
}
