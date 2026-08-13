package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.util.SocketUtils.getSelfCertificate;

class CaCertAwareLdapSocketFactoryTest {

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @AfterEach
    void clearZone() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getDefault_returnsOwnType_notASupertype() {
        SocketFactory factory = CaCertAwareLdapSocketFactory.getDefault();
        assertThat(factory).isExactlyInstanceOf(CaCertAwareLdapSocketFactory.class);
        assertThat(CaCertAwareLdapSocketFactory.getDefault()).isSameAs(factory);
    }

    @Test
    void createSocket_resolvesPerZoneTrust_twoZonesSameHostDifferentCertsDoNotInterfere() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate serverCert = getSelfCertificate(serverKeyPair, "UAA Test", "UAA Test Unit", "server-cert",
                new Date(), 60L * 60, "SHA256withRSA");
        String serverCertPem = pemEncode(serverCert);

        KeyPair otherKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate unrelatedCert = getSelfCertificate(otherKeyPair, "UAA Test", "UAA Test Unit", "unrelated-cert",
                new Date(), 60L * 60, "SHA256withRSA");
        String unrelatedCertPem = pemEncode(unrelatedCert);

        try (ServerHandle server = startTlsServer(serverKeyPair, serverCert)) {
            SocketFactory factory = CaCertAwareLdapSocketFactory.getDefault();

            // Zone A trusts the server's actual cert -- connection succeeds.
            IdentityZoneHolder.set(zone("zone-a"));
            CaCertAwareLdapSocketFactory.registerZoneTrust("zone-a", List.of(serverCertPem), false);
            try (var socket = factory.createSocket("localhost", server.port())) {
                assertThat(((SSLSocket) socket).getSession().isValid()).isTrue();
            }

            // Zone B, connecting to the SAME host, trusts a DIFFERENT (unrelated) cert -- must fail,
            // not silently reuse zone A's trust material. This is the cross-zone leak the zone-keyed
            // (rather than host-keyed) registry design exists to prevent.
            IdentityZoneHolder.set(zone("zone-b"));
            CaCertAwareLdapSocketFactory.registerZoneTrust("zone-b", List.of(unrelatedCertPem), false);
            assertThatThrownBy(() -> {
                try (var socket = factory.createSocket("localhost", server.port())) {
                    ((SSLSocket) socket).startHandshake();
                }
            }).isInstanceOf(SSLHandshakeException.class);

            // Zone A, connecting again after zone B's failure, must still succeed -- proving zone B's
            // lookup didn't clobber zone A's registered trust either.
            IdentityZoneHolder.set(zone("zone-a"));
            try (var socket = factory.createSocket("localhost", server.port())) {
                assertThat(((SSLSocket) socket).getSession().isValid()).isTrue();
            }
        }
    }

    @Test
    void createSocket_noRegisteredTrustForZone_fallsBackToDefaultTrust() throws Exception {
        IdentityZoneHolder.set(zone("zone-with-no-registration"));
        SocketFactory factory = CaCertAwareLdapSocketFactory.getDefault();
        // No server listening on this port -- we only care that resolution doesn't throw before
        // attempting the connection (i.e. the missing-registry-entry fallback path is exercised,
        // not that this specific connection succeeds).
        assertThatThrownBy(() -> factory.createSocket("localhost", 1))
                .isInstanceOf(IOException.class);
    }

    private static IdentityZone zone(String id) {
        IdentityZone zone = new IdentityZone();
        zone.setId(id);
        return zone;
    }

    private static String pemEncode(X509Certificate certificate) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    private static ServerHandle startTlsServer(KeyPair keyPair, X509Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), new char[0], new X509Certificate[]{certificate});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        SSLServerSocketFactory serverSocketFactory = serverContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(0);

        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            while (!serverSocket.isClosed()) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                } catch (IOException _) {
                    // expected once the server socket is closed, or on a client-side handshake failure
                }
            }
        });

        return new ServerHandle(serverSocket, executor);
    }

    private record ServerHandle(SSLServerSocket serverSocket, ExecutorService executor) implements AutoCloseable {
        int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            executor.shutdownNow();
        }
    }
}
