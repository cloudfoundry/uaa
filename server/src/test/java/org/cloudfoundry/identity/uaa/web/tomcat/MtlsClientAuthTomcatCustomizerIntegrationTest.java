package org.cloudfoundry.identity.uaa.web.tomcat;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Empirically verifies the customizer-ordering assumption underlying {@link MtlsClientAuthTomcatCustomizer}:
 * that a {@code TomcatConnectorCustomizer} registered via {@code addConnectorCustomizers} runs
 * <em>after</em> Spring Boot's own SSL bundle configuration has populated the connector's
 * {@code SSLHostConfig}(s) -- so overriding {@code certificateVerification} there actually takes
 * effect against a real embedded Tomcat TLS handshake, not just against a manually constructed
 * {@code SSLHostConfig} in isolation (see {@link MtlsClientAuthTomcatCustomizerTest}).
 *
 * <p>Uses a real {@link SSLSocket} handshake against a real embedded Tomcat connector. Whether the
 * server actually sent a {@code CertificateRequest} is detected from the client side: JSSE only
 * invokes the client {@link X509ExtendedKeyManager#chooseClientAlias} callback when the server
 * requested a certificate during the handshake.
 */
class MtlsClientAuthTomcatCustomizerIntegrationTest {

    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

    @TempDir
    Path tempDir;

    private WebServer webServer;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @AfterEach
    void tearDown() {
        if (webServer != null) {
            webServer.stop();
        }
    }

    @Test
    void requestsAndAcceptsAnUntrustedClientCertificateWhenMtlsEnabled() throws Exception {
        int port = startServer(true);
        AtomicBoolean clientCertRequested = new AtomicBoolean(false);

        try (SSLSocket socket = clientSocketPresentingArbitraryCert(port, clientCertRequested)) {
            socket.startHandshake();
        }

        assertThat(clientCertRequested)
                .as("server should have requested a client certificate (certificateVerification=optionalNoCA)")
                .isTrue();
    }

    /**
     * Regression test for a real-deployment finding (Task 14 end-to-end verification): even with
     * {@code certificateVerification=optionalNoCA}, Tomcat/JSSE still populates the
     * {@code CertificateRequest}'s "certificate_authorities" field from the connector's trust store --
     * which, absent any explicit trust store configuration, falls back to the JVM's default
     * {@code cacerts} (a large list of public root CAs). Confirmed empirically against a live
     * deployment via {@code openssl s_client -tls1_2}, whose "Acceptable client certificate CA names"
     * output listed only unrelated public root CAs (Certainly, Cybertrust, QuoVadis, etc.), never
     * {@code service_cf_internal_ca} (the CA that signs the Gorouter's own backend mTLS certificate).
     * Go's {@code crypto/tls} client (used by the real Gorouter) correctly implements TLS's client
     * certificate selection rules: when none of its available certificates' issuers appear in that
     * list, it sends an <em>empty</em> Certificate message rather than presenting a cert the server
     * didn't ask for -- confirmed via packet capture showing a zero-length certificate_list. The
     * existing {@link #requestsAndAcceptsAnUntrustedClientCertificateWhenMtlsEnabled()} test only
     * verifies the client's {@code chooseClientAlias} callback fires (proving a
     * {@code CertificateRequest} was sent) -- not that an alias was actually chosen and a certificate
     * actually transmitted, so it did not catch this. This test checks the KeyManager's actual return
     * value (the alias it chose, or {@code null} if none matched), which is what real TLS clients like
     * Go's use to decide whether to present a certificate at all.
     */
    @Test
    void chosenClientAliasIsNotNullEvenWhenCertIssuerIsNotInDefaultCaCerts() throws Exception {
        int port = startServer(true);
        AtomicReference<String> chosenAlias = new AtomicReference<>("not-yet-invoked");

        try (SSLSocket socket = clientSocketTrackingChosenAlias(port, chosenAlias)) {
            socket.startHandshake();
        }

        assertThat(chosenAlias)
                .as("the KeyManager must actually choose an alias (not null) for a certificate whose "
                        + "issuer is not in the JVM's default cacerts -- otherwise real TLS clients "
                        + "(e.g. Go's crypto/tls, used by the Gorouter) will send an empty certificate "
                        + "message instead of the client cert, silently defeating this entire feature "
                        + "for any backend TLS connection whose CA isn't a public root CA")
                .doesNotHaveValue(null);
    }

    /**
     * Regression test for a real-deployment finding (Task 14 end-to-end verification): Tomcat's own
     * startup log emits "The JSSE TLS 1.3 implementation does not support post handshake
     * authentication (PHA) and is therefore incompatible with optional certificate authentication" --
     * and on at least one JDK build used in a real BOSH-deployed environment, a TLS 1.3 handshake
     * against this connector never sends a {@code CertificateRequest} at all (confirmed empirically
     * via {@code openssl s_client -tls1_3} against a live instance, compared against
     * {@code -tls1_2} which does send one). Tomcat's own documented workaround for this exact
     * incompatibility is to exclude TLSv1.3 from the connector's enabled protocols
     * ({@code protocols="all,-TLSv1.3"}) whenever {@code certificateVerification=optionalNoCA} is in
     * use. This test asserts the customizer actually negotiates TLSv1.2 (not TLSv1.3) even when the
     * client is willing to speak both -- which is what actually prevents the silent-no-CertificateRequest
     * failure mode in production, independent of whether any particular local JDK happens to dodge the
     * underlying JSSE limitation.
     */
    @Test
    void negotiatesTlsV12NotTlsV13WhenMtlsEnabled() throws Exception {
        int port = startServer(true);

        try (SSLSocket socket = clientSocketOfferingBothTls12And13(port)) {
            socket.startHandshake();

            assertThat(socket.getSession().getProtocol())
                    .as("connector must not negotiate TLSv1.3 when optionalNoCA client-auth is in "
                            + "effect, since JSSE's TLS 1.3 implementation cannot request a client "
                            + "certificate without post-handshake authentication (PHA), which it does "
                            + "not support -- see MtlsClientAuthTomcatCustomizer's Javadoc")
                    .isEqualTo("TLSv1.2");
        }
    }

    @Test
    void doesNotRequestAClientCertificateWhenMtlsDisabled() throws Exception {
        int port = startServer(false);
        AtomicBoolean clientCertRequested = new AtomicBoolean(false);

        try (SSLSocket socket = clientSocketPresentingArbitraryCert(port, clientCertRequested)) {
            socket.startHandshake();
        }

        assertThat(clientCertRequested)
                .as("server should not request a client certificate (certificateVerification=none, the Tomcat default)")
                .isFalse();
    }

    private int startServer(boolean mtlsEnabled) throws Exception {
        KeyPair serverKeyPair = generateKeyPair();
        X500Name serverName = new X500Name("CN=localhost");
        X509Certificate serverCert = signCert(serverName, serverName, serverKeyPair.getPublic(), serverKeyPair.getPrivate(), false, BigInteger.ONE);

        Path keystorePath = tempDir.resolve("server.p12");
        KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
        serverKeyStore.load(null, null);
        serverKeyStore.setKeyEntry("server", serverKeyPair.getPrivate(), KEYSTORE_PASSWORD, new X509Certificate[]{serverCert});
        try (FileOutputStream out = new FileOutputStream(keystorePath.toFile())) {
            serverKeyStore.store(out, KEYSTORE_PASSWORD);
        }

        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
        Ssl ssl = new Ssl();
        ssl.setEnabled(true);
        ssl.setKeyStore(keystorePath.toString());
        ssl.setKeyStorePassword(new String(KEYSTORE_PASSWORD));
        ssl.setKeyAlias("server");
        ssl.setKeyStoreType("PKCS12");
        factory.setSsl(ssl);

        // This is the exact bean-under-test, invoked exactly as Spring would invoke any
        // WebServerFactoryCustomizer<TomcatServletWebServerFactory> -- after Spring Boot's own
        // SSL auto-configuration would have already called factory.setSsl(...) above.
        new MtlsClientAuthTomcatCustomizer(mtlsEnabled).customize(factory);

        webServer = factory.getWebServer();
        webServer.start();
        return webServer.getPort();
    }

    private SSLSocket clientSocketPresentingArbitraryCert(int port, AtomicBoolean clientCertRequested) throws Exception {
        KeyPair clientKeyPair = generateKeyPair();
        X500Name clientName = new X500Name("CN=arbitrary-untrusted-client");
        X509Certificate clientCert = signCert(clientName, clientName, clientKeyPair.getPublic(), clientKeyPair.getPrivate(), false, BigInteger.TWO);

        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("client", clientKeyPair.getPrivate(), KEYSTORE_PASSWORD, new X509Certificate[]{clientCert});

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, KEYSTORE_PASSWORD);

        KeyManager[] trackingKeyManagers = trackClientAliasRequests(keyManagerFactory.getKeyManagers(), clientCertRequested);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(trackingKeyManagers, new TrustManager[]{trustAnyServerCertificate()}, null);

        return (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", port);
    }

    /**
     * A client socket whose only certificate is signed by a throwaway, arbitrary self-signed CA (i.e.
     * NOT one of the JVM's default {@code cacerts} public root CAs). Tracks the actual alias the
     * KeyManager chooses for {@code chooseClientAlias}/{@code chooseEngineClientAlias} -- {@code null}
     * means no matching certificate was found for the server's advertised acceptable-issuer list, so no
     * certificate will actually be transmitted (see {@link #chosenClientAliasIsNotNullEvenWhenCertIssuerIsNotInDefaultCaCerts()}).
     */
    private SSLSocket clientSocketTrackingChosenAlias(int port, AtomicReference<String> chosenAlias) throws Exception {
        KeyPair clientKeyPair = generateKeyPair();
        X500Name clientName = new X500Name("CN=arbitrary-untrusted-client");
        X509Certificate clientCert = signCert(clientName, clientName, clientKeyPair.getPublic(), clientKeyPair.getPrivate(), false, BigInteger.valueOf(4));

        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("client", clientKeyPair.getPrivate(), KEYSTORE_PASSWORD, new X509Certificate[]{clientCert});

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, KEYSTORE_PASSWORD);

        KeyManager[] trackingKeyManagers = trackChosenClientAlias(keyManagerFactory.getKeyManagers(), chosenAlias);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(trackingKeyManagers, new TrustManager[]{trustAnyServerCertificate()}, null);

        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", port);
        socket.setEnabledProtocols(new String[]{"TLSv1.2"});
        return socket;
    }

    /**
     * Wraps each {@link X509ExtendedKeyManager} so we can observe the actual alias returned by
     * {@code chooseClientAlias}/{@code chooseEngineClientAlias} -- {@code null} means the delegate
     * KeyManager found no certificate whose issuer matched the server's advertised acceptable-issuer
     * list, so nothing will be sent (unlike {@link #trackClientAliasRequests}, which only tracks
     * whether the callback was invoked at all).
     */
    private KeyManager[] trackChosenClientAlias(KeyManager[] keyManagers, AtomicReference<String> chosenAlias) {
        KeyManager[] wrapped = new KeyManager[keyManagers.length];
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509ExtendedKeyManager delegate) {
                wrapped[i] = new X509ExtendedKeyManager() {
                    @Override
                    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                        String alias = delegate.chooseClientAlias(keyType, issuers, socket);
                        chosenAlias.set(alias);
                        return alias;
                    }

                    @Override
                    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
                        String alias = delegate.chooseEngineClientAlias(keyType, issuers, engine);
                        chosenAlias.set(alias);
                        return alias;
                    }

                    @Override
                    public String[] getClientAliases(String keyType, Principal[] issuers) {
                        return delegate.getClientAliases(keyType, issuers);
                    }

                    @Override
                    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                        return delegate.chooseServerAlias(keyType, issuers, socket);
                    }

                    @Override
                    public String[] getServerAliases(String keyType, Principal[] issuers) {
                        return delegate.getServerAliases(keyType, issuers);
                    }

                    @Override
                    public X509Certificate[] getCertificateChain(String alias) {
                        return delegate.getCertificateChain(alias);
                    }

                    @Override
                    public PrivateKey getPrivateKey(String alias) {
                        return delegate.getPrivateKey(alias);
                    }
                };
            } else {
                wrapped[i] = keyManagers[i];
            }
        }
        return wrapped;
    }

    /**
     * A client socket configured to offer both TLSv1.2 and TLSv1.3, presenting an arbitrary
     * untrusted certificate if asked. Used to verify which protocol the connector actually
     * negotiates when both are available to the client (see
     * {@link #negotiatesTlsV12NotTlsV13WhenMtlsEnabled()}).
     */
    private SSLSocket clientSocketOfferingBothTls12And13(int port) throws Exception {
        KeyPair clientKeyPair = generateKeyPair();
        X500Name clientName = new X500Name("CN=arbitrary-untrusted-client");
        X509Certificate clientCert = signCert(clientName, clientName, clientKeyPair.getPublic(), clientKeyPair.getPrivate(), false, BigInteger.valueOf(3));

        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(null, null);
        clientKeyStore.setKeyEntry("client", clientKeyPair.getPrivate(), KEYSTORE_PASSWORD, new X509Certificate[]{clientCert});

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientKeyStore, KEYSTORE_PASSWORD);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{trustAnyServerCertificate()}, null);

        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", port);
        socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        return socket;
    }

    /**
     * Wraps each {@link X509ExtendedKeyManager} so we can observe -- from the client side -- whether
     * the server ever asked for a client certificate during the handshake. JSSE only calls
     * {@code chooseClientAlias}/{@code chooseEngineClientAlias} when the server sent a
     * {@code CertificateRequest}, which is exactly the behavior {@link MtlsClientAuthTomcatCustomizer}
     * is meant to control.
     */
    private KeyManager[] trackClientAliasRequests(KeyManager[] keyManagers, AtomicBoolean clientCertRequested) {
        KeyManager[] wrapped = new KeyManager[keyManagers.length];
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509ExtendedKeyManager delegate) {
                wrapped[i] = new X509ExtendedKeyManager() {
                    @Override
                    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                        clientCertRequested.set(true);
                        return delegate.chooseClientAlias(keyType, issuers, socket);
                    }

                    @Override
                    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
                        clientCertRequested.set(true);
                        return delegate.chooseEngineClientAlias(keyType, issuers, engine);
                    }

                    @Override
                    public String[] getClientAliases(String keyType, Principal[] issuers) {
                        return delegate.getClientAliases(keyType, issuers);
                    }

                    @Override
                    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                        return delegate.chooseServerAlias(keyType, issuers, socket);
                    }

                    @Override
                    public String[] getServerAliases(String keyType, Principal[] issuers) {
                        return delegate.getServerAliases(keyType, issuers);
                    }

                    @Override
                    public X509Certificate[] getCertificateChain(String alias) {
                        return delegate.getCertificateChain(alias);
                    }

                    @Override
                    public PrivateKey getPrivateKey(String alias) {
                        return delegate.getPrivateKey(alias);
                    }
                };
            } else {
                wrapped[i] = keyManagers[i];
            }
        }
        return wrapped;
    }

    private TrustManager trustAnyServerCertificate() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // not used: this is the client-side trust manager for the server's cert
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // the server cert is self-signed and not in any trust store; accept it for this test
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
