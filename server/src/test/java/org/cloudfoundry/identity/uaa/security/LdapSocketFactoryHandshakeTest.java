package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real handshakes through {@link BaseLdapSocketFactory} with {@link X509ExpiryCheckingTrustManager}
 * (as in {@link LdapSocketFactory}) on both SunJSSE and BCJSSE. The server certificate is trusted, so
 * a handshake failure can only come from endpoint identification (hostname verification).
 */
class LdapSocketFactoryHandshakeTest {

    private static final String SUN_JSSE = "SunJSSE";
    private static final String BC_JSSE = "BCJSSE";

    private static Provider bcJsse;
    private static X509Certificate certificate;
    private static SSLServerSocket serverSocket;
    private static ExecutorService executor;

    @BeforeAll
    static void startServer() throws Exception {
        Provider bcFips = Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
        if (bcFips == null) {
            bcFips = new BouncyCastleFipsProvider();
            Security.addProvider(bcFips);
        }
        bcJsse = new BouncyCastleJsseProvider(bcFips);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        // BCJSSE (unlike SunJSSE) does not fall back to the CN, so the certificate needs a SAN
        X500Name subject = new X500Name("CN=localhost");
        Instant now = Instant.now();
        certificate = new JcaX509CertificateConverter().setProvider(bcFips).getCertificate(
                new JcaX509v3CertificateBuilder(subject, BigInteger.valueOf(now.toEpochMilli()), Date.from(now),
                        Date.from(now.plus(1, ChronoUnit.HOURS)), subject, keyPair.getPublic())
                        .addExtension(Extension.subjectAlternativeName, false,
                                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")))
                        .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(bcFips).build(keyPair.getPrivate())));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), new char[0], new X509Certificate[]{certificate});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);
        serverSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0);

        executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            while (!serverSocket.isClosed()) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                } catch (IOException _) {
                    // server socket closed, or the client rejected the handshake
                }
            }
        });
    }

    @AfterAll
    static void stopServer() throws IOException {
        serverSocket.close();
        executor.shutdownNow();
    }

    @ParameterizedTest
    @ValueSource(strings = {SUN_JSSE, BC_JSSE})
    void noArgCreateSocket_connectByHostname_handshakeSucceeds(String provider) throws Exception {
        try (Socket socket = factory(provider).createSocket()) {
            socket.connect(new InetSocketAddress("localhost", serverSocket.getLocalPort()), 5000);
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.startHandshake();
            // BCJSSE reports non-resumable TLS 1.3 sessions as !isValid(), so check negotiation instead
            assertThat(sslSocket.getSession().getCipherSuite()).isNotEqualTo("SSL_NULL_WITH_NULL_NULL");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {SUN_JSSE, BC_JSSE})
    void noArgCreateSocket_hostnameMismatch_failsHandshake(String provider) throws Exception {
        BaseLdapSocketFactory factory = factory(provider);
        assertThatThrownBy(() -> {
            try (Socket socket = factory.createSocket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", serverSocket.getLocalPort()), 5000);
                ((SSLSocket) socket).startHandshake();
            }
        }).satisfies(LdapSocketFactoryHandshakeTest::isHostnameMismatch);
    }

    @ParameterizedTest
    @ValueSource(strings = {SUN_JSSE, BC_JSSE})
    void createSocketWithHost_hostnameMismatch_failsHandshake(String provider) throws Exception {
        BaseLdapSocketFactory factory = factory(provider);
        assertThatThrownBy(() -> {
            try (Socket socket = factory.createSocket("127.0.0.1", serverSocket.getLocalPort())) {
                ((SSLSocket) socket).startHandshake();
            }
        }).satisfies(LdapSocketFactoryHandshakeTest::isHostnameMismatch);
    }

    @Test
    void skipSslFactory_hostnameMismatch_handshakeSucceeds() throws Exception {
        try (Socket socket = new SkipSslLdapSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", serverSocket.getLocalPort()), 5000);
            ((SSLSocket) socket).startHandshake();
        }
    }

    /**
     * SunJSSE throws SSLHandshakeException, BCJSSE TlsFatalAlert; both are rooted in a CertificateException.
     * Rejects "No hostname specified" so a missing peer host can't make a mismatch test pass.
     */
    private static void isHostnameMismatch(Throwable thrown) {
        assertThat(thrown).isInstanceOf(IOException.class)
                .rootCause()
                .isInstanceOf(CertificateException.class)
                .hasMessageNotContaining("No hostname specified");
    }

    private static BaseLdapSocketFactory factory(String providerName) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", certificate);

        boolean bc = BC_JSSE.equals(providerName);
        TrustManagerFactory tmf = bc
                ? TrustManagerFactory.getInstance("PKIX", bcJsse)
                : TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        X509ExpiryCheckingTrustManager trustManager = new X509ExpiryCheckingTrustManager();
        trustManager.setDelegate((X509TrustManager) tmf.getTrustManagers()[0]);

        SSLContext sslContext = bc ? SSLContext.getInstance("TLS", bcJsse) : SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, null);

        BaseLdapSocketFactory factory = new BaseLdapSocketFactory() {
        };
        factory.delegate = sslContext.getSocketFactory();
        return factory;
    }
}