package org.cloudfoundry.identity.uaa.security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal local TLS server (default JSSE provider) that completes a handshake for every accepted
 * connection. Used by LDAP socket factory tests to exercise real client-side handshakes.
 */
record TlsTestServer(SSLServerSocket serverSocket, ExecutorService executor) implements AutoCloseable {

    record TestCert(KeyPair keyPair, X509Certificate certificate) {
        String pem() throws Exception {
            String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
        }
    }

    /**
     * Self-signed certificate with {@code CN=<commonName>} and {@code subjectAltName=DNS:<commonName>}.
     * The SAN is required for BCJSSE, which (unlike SunJSSE) does not fall back to the CN for
     * endpoint identification unless {@code org.bouncycastle.jsse.hostname_check_cn_fallback} is set.
     */
    static TestCert newTestCert(String commonName) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.OU, "UAA Test Unit")
                .addRDN(BCStyle.O, "UAA Test")
                .addRDN(BCStyle.CN, commonName)
                .build();
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject,
                BigInteger.valueOf(now.toEpochMilli()), Date.from(now), Date.from(now.plus(1, ChronoUnit.HOURS)),
                subject, keyPair.getPublic())
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, commonName)));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
        return new TestCert(keyPair, certificate);
    }

    static TlsTestServer start(TestCert cert) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", cert.keyPair().getPrivate(), new char[0], new X509Certificate[]{cert.certificate()});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        SSLServerSocket serverSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0);

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

        return new TlsTestServer(serverSocket, executor);
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        executor.shutdownNow();
    }
}
