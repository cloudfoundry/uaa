package org.cloudfoundry.identity.uaa.oauth.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class TlsClientAuthenticationTest {

    private TlsClientAuthentication service;

    @BeforeEach
    void setUp() {
        service = new TlsClientAuthentication();
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void nullCertReturnsEmptyOptional() {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("...", null);
        assertThat(service.validateClientCert((X509Certificate) null, config)).isEmpty();
    }

    @Test
    void nullConfigReturnsEmptyOptional() {
        X509Certificate cert = mock(X509Certificate.class);
        assertThat(service.validateClientCert(cert, null)).isEmpty();
    }

    @Test
    void invalidCaThrowsInvalidClientDetailsException() {
        X509Certificate cert = mock(X509Certificate.class);
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("not-a-cert", null);
        assertThatThrownBy(() -> service.validateClientCert(cert, config))
                .hasMessageContaining("tls_client_auth");
    }

    @Test
    void validateClientCertSucceedsWhenChainOmitsTrustAnchor() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        Optional<X509Certificate> result = service.validateClientCert(
                new X509Certificate[]{leafCert}, config);

        assertThat(result).contains(leafCert);
    }

    @Test
    void validateClientCertSucceedsWhenChainIncludesTrustAnchor() throws Exception {
        // Reproduces the reviewer's concern (PR #3972 discussion on TlsClientAuthentication.java:113):
        // some proxies/clients forward the full chain including the trust anchor / root CA itself.
        // RFC 5280 section 6.1 excludes trailing self-issued certificates from path validation
        // accounting, and the JDK's PKIX CertPathValidator correctly implements this, so no
        // stripping of the anchor from the presented chain is required.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        // Chain includes the root CA cert itself, at the tail — unlike the "omits" test above.
        Optional<X509Certificate> result = service.validateClientCert(
                new X509Certificate[]{leafCert, rootCert}, config);

        assertThat(result).contains(leafCert);
    }

    @Test
    void validateClientCertSucceedsWithIntermediateChainIncludingTrustAnchor() throws Exception {
        // Same as above but with an intermediate CA between leaf and root, matching a more
        // realistic multi-tier CA hierarchy.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair interKp = generateKeyPair();
        X500Name interName = new X500Name("CN=Test Intermediate CA");
        X509Certificate interCert = signCert(interName, rootName, interKp.getPublic(), rootKp.getPrivate(), true, BigInteger.TWO);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), interName, leafKp.getPublic(), interKp.getPrivate(), false, BigInteger.valueOf(3));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        Optional<X509Certificate> result = service.validateClientCert(
                new X509Certificate[]{leafCert, interCert, rootCert}, config);

        assertThat(result).contains(leafCert);
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

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }
}
