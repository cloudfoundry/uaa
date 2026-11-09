package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.cloudfoundry.identity.uaa.security.TlsTestServer.TestCert;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end handshakes through {@link BaseLdapSocketFactory} using the same trust manager as
 * {@link LdapSocketFactory} ({@link X509ExpiryCheckingTrustManager}), run against both the default
 * JSSE provider and the Bouncy Castle JSSE provider ({@code bctls-fips}). The delegate trust manager
 * trusts the test server's self-signed certificate, so a handshake failure can only come from
 * endpoint identification (hostname verification).
 */
class LdapSocketFactoryHandshakeTest {

    private static final String SUN_JSSE = "SunJSSE";
    private static final String BC_JSSE = "BCJSSE";

    private static Provider bcFips;
    private static Provider bcJsse;
    private static TestCert cert;
    private static TlsTestServer server;

    @BeforeAll
    static void startServer() throws Exception {
        bcFips = Security.getProvider("BCFIPS");
        if (bcFips == null) {
            bcFips = new BouncyCastleFipsProvider();
            Security.addProvider(bcFips);
        }
        bcJsse = new BouncyCastleJsseProvider(bcFips);
        cert = TlsTestServer.newTestCert("localhost");
        server = TlsTestServer.start(cert);
    }

    @AfterAll
    static void stopServer() throws Exception {
        server.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {SUN_JSSE, BC_JSSE})
    void noArgCreateSocket_connectByHostname_handshakeSucceeds(String provider) throws Exception {
        try (Socket socket = factory(provider).createSocket()) {
            socket.connect(new InetSocketAddress("localhost", server.port()), 5000);
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
                socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 5000);
                ((SSLSocket) socket).startHandshake();
            }
        }).satisfies(LdapSocketFactoryHandshakeTest::isHostnameMismatch);
    }

    @ParameterizedTest
    @ValueSource(strings = {SUN_JSSE, BC_JSSE})
    void createSocketWithHost_hostnameMismatch_failsHandshake(String provider) throws Exception {
        BaseLdapSocketFactory factory = factory(provider);
        assertThatThrownBy(() -> {
            try (Socket socket = factory.createSocket("127.0.0.1", server.port())) {
                ((SSLSocket) socket).startHandshake();
            }
        }).satisfies(LdapSocketFactoryHandshakeTest::isHostnameMismatch);
    }

    @Test
    void skipSslFactory_hostnameMismatch_handshakeSucceeds() throws Exception {
        try (Socket socket = new SkipSslLdapSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 5000);
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.startHandshake();
            assertThat(sslSocket.getSession().isValid()).isTrue();
        }
    }

    /**
     * SunJSSE reports {@code SSLHandshakeException}, BCJSSE a {@code TlsFatalAlert}; both are
     * {@link IOException}s rooted in a {@link CertificateException}. Rejects the "No hostname
     * specified" failure so a missing peer host cannot make a mismatch test pass vacuously.
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
        trustStore.setCertificateEntry("server", cert.certificate());

        boolean bc = BC_JSSE.equals(providerName);
        TrustManagerFactory tmf = bc
                ? TrustManagerFactory.getInstance("PKIX", bcJsse)
                : TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        X509ExpiryCheckingTrustManager trustManager = new X509ExpiryCheckingTrustManager();
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x509Tm) {
                trustManager.setDelegate(x509Tm);
                break;
            }
        }

        SSLContext sslContext = bc ? SSLContext.getInstance("TLS", bcJsse) : SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

        BaseLdapSocketFactory factory = new BaseLdapSocketFactory() {
        };
        factory.delegate = sslContext.getSocketFactory();
        return factory;
    }
}
