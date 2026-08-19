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
        X509Certificate serverCert = signCert(serverName, serverName, serverKeyPair.getPublic(), serverKeyPair.getPrivate(), BigInteger.ONE);

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
        X509Certificate clientCert = signCert(clientName, clientName, clientKeyPair.getPublic(), clientKeyPair.getPrivate(), BigInteger.TWO);

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
            PrivateKey signerKey, BigInteger serial) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
