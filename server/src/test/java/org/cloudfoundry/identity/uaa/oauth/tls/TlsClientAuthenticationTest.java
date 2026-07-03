package org.cloudfoundry.identity.uaa.oauth.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
    void extractClaimMappingValuesExtractsSubjectCnOuAndO() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid,OU=app:app-guid-123,OU=space:space-guid-456,O=Cloud Foundry");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_o", null, "org_name")
        ));

        Map<String, String> vars = service.extractClaimMappingValues(cert, config);

        assertThat(vars).containsEntry("cf_instance_guid", "instance-guid");
        assertThat(vars).containsEntry("app_guid", "app-guid-123");
        assertThat(vars).containsEntry("org_name", "Cloud Foundry");
    }

    @Test
    void extractClaimMappingValuesExtractsEveryOuFromMultiValuedRdn() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid,OU=organization:org-guid+OU=space:space-guid+OU=app:app-guid");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$", "space_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^organization:(.+)$", "org_guid")
        ));

        assertThat(service.extractClaimMappingValues(cert, config)).containsExactlyInAnyOrderEntriesOf(Map.of(
                "app_guid", "app-guid",
                "space_guid", "space-guid",
                "org_guid", "org-guid"
        ));
    }

    @Test
    void extractClaimMappingValuesReturnsEmptyMapWhenNoClaimMappingsConfigured() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);

        assertThat(service.extractClaimMappingValues(cert, config)).isEmpty();
    }

    @Test
    void extractClaimMappingValuesReturnsEmptyMapWhenCertOrConfigIsNull() {
        assertThat(service.extractClaimMappingValues(null, new TlsClientAuthConfiguration("ca", null))).isEmpty();
    }

    @Test
    void certificateSatisfiesRequiredClaimsTrueWhenNoConstraintConfigured() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);

        assertThat(service.certificateSatisfiesRequiredClaims(cert, config)).isTrue();
    }

    @Test
    void certificateSatisfiesRequiredClaimsTrueWhenExtractedValueMatchesRequiredValue() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid,OU=space:space-guid-456");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$", "space_guid")
        ));
        config.setRequiredClaims(Map.of("space_guid", "space-guid-456"));

        assertThat(service.certificateSatisfiesRequiredClaims(cert, config)).isTrue();
    }

    @Test
    void certificateSatisfiesRequiredClaimsFalseWhenExtractedValueDiffersFromRequiredValue() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid,OU=space:some-other-space");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$", "space_guid")
        ));
        config.setRequiredClaims(Map.of("space_guid", "space-guid-456"));

        assertThat(service.certificateSatisfiesRequiredClaims(cert, config)).isFalse();
    }

    @Test
    void certificateSatisfiesRequiredClaimsFalseWhenRequiredClaimNeverExtracted() throws Exception {
        KeyPair kp = generateKeyPair();
        X500Name subject = new X500Name("CN=instance-guid");
        X509Certificate cert = signCert(subject, subject, kp.getPublic(), kp.getPrivate(), false, BigInteger.ONE);

        // No claim-mappings configured at all -> "space_guid" is never extracted
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setRequiredClaims(Map.of("space_guid", "space-guid-456"));

        assertThat(service.certificateSatisfiesRequiredClaims(cert, config)).isFalse();
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
    void validateClientCertRejectsExpiredLeafCertificate() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate expiredLeafCert = signCertWithValidity(
                new X500Name("CN=expired-leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false,
                BigInteger.TWO, new Date(System.currentTimeMillis() - 7_200_000), new Date(System.currentTimeMillis() - 3_600_000));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        assertThatThrownBy(() -> service.validateClientCert(new X509Certificate[]{expiredLeafCert}, config))
                .hasMessageContaining("validity check failed");
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

    @Test
    void validateClientCertRejectsLeafThatIsItselfACaCertificate() throws Exception {
        // A CA cert (BasicConstraints CA=true) presented as the "leaf" chain[0] genuinely PKIX-
        // validates -- a 1-cert chain from the intermediate to the root trust anchor is
        // structurally valid -- but must be rejected because the presented end-entity is itself
        // a CA certificate, not a genuine client credential.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair interKp = generateKeyPair();
        X500Name interName = new X500Name("CN=Test Intermediate CA");
        X509Certificate intermediateCaCert = signCert(
                interName, rootName, interKp.getPublic(), rootKp.getPrivate(), true, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        assertThatThrownBy(() -> service.validateClientCert(new X509Certificate[]{intermediateCaCert}, config))
                .hasMessageContaining("is itself a CA certificate");
    }

    @Test
    void validateClientCertRejectsLeafWithExtendedKeyUsageExcludingClientAuth() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO,
                null, List.of(KeyPurposeId.id_kp_serverAuth));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        assertThatThrownBy(() -> service.validateClientCert(new X509Certificate[]{leafCert}, config))
                .hasMessageContaining("does not include clientAuth or anyExtendedKeyUsage");
    }

    @Test
    void validateClientCertAcceptsLeafWithExtendedKeyUsageIncludingClientAuthAndServerAuth() throws Exception {
        // Locks in "contains, not equals" semantics: an EKU listing clientAuth alongside an
        // unrelated purpose must still be accepted.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO,
                null, List.of(KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        Optional<X509Certificate> result = service.validateClientCert(new X509Certificate[]{leafCert}, config);

        assertThat(result).contains(leafCert);
    }

    @Test
    void validateClientCertAcceptsLeafWithExtendedKeyUsageIncludingClientAuth() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO,
                null, List.of(KeyPurposeId.id_kp_clientAuth));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        Optional<X509Certificate> result = service.validateClientCert(new X509Certificate[]{leafCert}, config);

        assertThat(result).contains(leafCert);
    }

    @Test
    void validateClientCertAcceptsLeafWithNoKeyUsageOrExtendedKeyUsageExtensions() throws Exception {
        // Backward compatibility: certs that set neither extension at all (e.g. Diego's
        // instance-identity CA, whose exact extension profile is not assumed here) must still be
        // accepted -- an absent extension imposes no restriction per RFC 5280.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        Optional<X509Certificate> result = service.validateClientCert(new X509Certificate[]{leafCert}, config);

        assertThat(result).contains(leafCert);
    }

    @Test
    void validateClientCertRejectsLeafWithKeyUsageExcludingDigitalSignature() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Test Root CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair leafKp = generateKeyPair();
        // Key Usage present but only keyEncipherment -- digitalSignature explicitly excluded.
        X509Certificate leafCert = signCert(
                new X500Name("CN=leaf-instance"), rootName, leafKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO,
                KeyUsage.keyEncipherment, null);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(rootCert), null);

        assertThatThrownBy(() -> service.validateClientCert(new X509Certificate[]{leafCert}, config))
                .hasMessageContaining("does not permit digitalSignature");
    }

    @Test
    void isCertificateFromTrustedProxyTrueWhenPeerCertSignedByClientsTrustedProxyCa() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter.service.cf.internal"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isTrue();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenPeerCertNotSignedByClientsTrustedProxyCa() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        // An unrelated, self-signed certificate -- e.g. a harvested cert an attacker presents directly.
        KeyPair attackerKp = generateKeyPair();
        X500Name attackerName = new X500Name("CN=attacker");
        X509Certificate attackerCert = signCert(attackerName, attackerName, attackerKp.getPublic(), attackerKp.getPrivate(), false, BigInteger.ONE);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{attackerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenNoPeerCertificatePresent() {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem("some-ca-pem");

        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenClientHasNoTrustedProxyCaConfigured() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Some CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);
        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        // Client has tls-client-auth-ca configured but no tls-client-auth-trusted-proxy-ca.
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenPeerCertIsItselfACaCertificate() throws Exception {
        // Mirrors validateClientCertRejectsLeafThatIsItselfACaCertificate, but for the trusted-
        // proxy leaf: PKIX path validation alone would succeed (a 1-cert chain from the
        // intermediate to the root trust anchor is structurally valid), but the presented
        // end-entity is itself a CA certificate, not a genuine proxy TLS credential.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair interKp = generateKeyPair();
        X500Name interName = new X500Name("CN=Trusted Proxy Intermediate CA");
        X509Certificate intermediateCaCert = signCert(
                interName, rootName, interKp.getPublic(), rootKp.getPrivate(), true, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{intermediateCaCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenPeerCertExtendedKeyUsageExcludesClientAuth() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter.service.cf.internal"), rootName, peerKp.getPublic(), rootKp.getPrivate(),
                false, BigInteger.TWO, null, List.of(KeyPurposeId.id_kp_serverAuth));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenPeerCertKeyUsageExcludesDigitalSignature() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair peerKp = generateKeyPair();
        // Key Usage present but only keyEncipherment -- digitalSignature explicitly excluded.
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter.service.cf.internal"), rootName, peerKp.getPublic(), rootKp.getPrivate(),
                false, BigInteger.TWO, KeyUsage.keyEncipherment, null);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyTrueWhenPeerCertHasClientAuthExtendedKeyUsage() throws Exception {
        // Positive control: a genuinely valid, EKU-restricted-to-clientAuth proxy leaf must
        // still be accepted -- no regression to the happy path from adding end-entity checks.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);

        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter.service.cf.internal"), rootName, peerKp.getPublic(), rootKp.getPrivate(),
                false, BigInteger.TWO, null, List.of(KeyPurposeId.id_kp_clientAuth));

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(config)).isTrue();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void isCertificateFromTrustedProxyFalseWhenConfigIsNull() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.isCertificateFromTrustedProxy(null)).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void hasCertificateFromRequestTrueWhenXfccDerivedCertPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[]{mock(X509Certificate.class)});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.hasCertificateFromRequest()).isTrue();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void hasCertificateFromRequestFalseWhenNoCertPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.hasCertificateFromRequest()).isFalse();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsNullWhenNoTrustedProxyCaConfiguredAndNoPeerCertCaptured() {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        // no trusted-proxy CA configured for this client -> direct-connection-only, but no raw
        // peer certificate was ever captured (e.g. uaa.mtls-enabled=false)

        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).isNull();
            assertThat(service.getCertificateFromRequest(config)).isNull();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsRawPeerCertForDirectConnectionWhenNoTrustedProxyCaConfigured() throws Exception {
        KeyPair clientKp = generateKeyPair();
        X500Name clientCaName = new X500Name("CN=Instance Identity CA");
        X509Certificate clientCaCert = signCert(clientCaName, clientCaName, clientKp.getPublic(), clientKp.getPrivate(), true, BigInteger.ONE);
        KeyPair leafKp = generateKeyPair();
        X509Certificate directPeerCert = signCert(
                new X500Name("CN=app-instance"), clientCaName, leafKp.getPublic(), clientKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(clientCaCert), null);
        // no trusted-proxy CA configured for this client -> direct-connection-only

        MockHttpServletRequest request = new MockHttpServletRequest();
        // No X-Forwarded-Client-Cert header, no ClientCertificateMapper rewriting: the standard
        // attribute would ordinarily equal the raw peer cert here, but this client never reads the
        // standard attribute at all.
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{directPeerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).containsExactly(directPeerCert);
            assertThat(service.getCertificateFromRequest(config)).isEqualTo(directPeerCert);
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestIgnoresXfccWhenNoTrustedProxyCaConfigured() throws Exception {
        KeyPair clientKp = generateKeyPair();
        X500Name clientCaName = new X500Name("CN=Instance Identity CA");
        X509Certificate clientCaCert = signCert(clientCaName, clientCaName, clientKp.getPublic(), clientKp.getPrivate(), true, BigInteger.ONE);
        KeyPair leafKp = generateKeyPair();
        X509Certificate directPeerCert = signCert(
                new X500Name("CN=app-instance"), clientCaName, leafKp.getPublic(), clientKp.getPrivate(), false, BigInteger.TWO);
        X509Certificate xfccDerivedCert = mock(X509Certificate.class);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(toPem(clientCaCert), null);
        // no trusted-proxy CA configured for this client -> direct-connection-only

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{directPeerCert});
        // A different certificate somehow ended up in the standard attribute, and an XFCC header
        // is present -- e.g. noise from an unrelated proxy somewhere in the network path. Neither
        // should matter for a client with no trusted-proxy CA configured.
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{xfccDerivedCert});
        request.addHeader("X-Forwarded-Client-Cert", "irrelevant-base64-value");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).containsExactly(directPeerCert);
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsChainWhenFromClientsTrustedProxy() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);
        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        X509Certificate[] xfccDerivedChain = new X509Certificate[]{mock(X509Certificate.class)};
        MockHttpServletRequest request = new MockHttpServletRequest();
        // The genuine TLS peer cert (captured separately) validates against this client's trusted-proxy CA...
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        // ...so the XFCC-header-derived certificate (a completely different value) is trusted too,
        // given the header that ClientCertificateMapper would have parsed it from is present.
        request.setAttribute("jakarta.servlet.request.X509Certificate", xfccDerivedChain);
        request.addHeader("X-Forwarded-Client-Cert", "irrelevant-base64-value");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).isEqualTo(xfccDerivedChain);
            assertThat(service.getCertificateFromRequest(config)).isEqualTo(xfccDerivedChain[0]);
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsNullWhenTrustedProxyCaConfiguredButXfccHeaderAbsent() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);
        // A direct peer whose own certificate happens to validate against the SAME CA configured
        // as tls-client-auth-trusted-proxy-ca -- e.g. an operator who set them equal, or a
        // coincidence. This must NOT be enough on its own: the client is proxy-only.
        KeyPair peerKp = generateKeyPair();
        X509Certificate directPeerCert = signCert(
                new X500Name("CN=direct-caller"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{directPeerCert});
        // No X-Forwarded-Client-Cert header at all -- ClientCertificateMapper never touched the
        // standard attribute, so (if read) it would equal the raw peer cert above. But this client
        // is proxy-only and must reject a request with no XFCC header, regardless.
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{directPeerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).isNull();
            assertThat(service.getCertificateFromRequest(config)).isNull();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsNullWhenTrustedProxyCaConfiguredButXfccHeaderBlank() throws Exception {
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);
        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        // X-Forwarded-Client-Cert header is present but blank -- e.g. a proxy or intermediate
        // that clears the header without removing it. Per the design doc, this must be treated
        // the same as the header being entirely absent: reject the request, even though the
        // genuine peer certificate would otherwise validate against tls-client-auth-trusted-proxy-ca.
        request.addHeader("X-Forwarded-Client-Cert", "");
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{peerCert});
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).isNull();
            assertThat(service.getCertificateFromRequest(config)).isNull();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    @Test
    void getCertificateChainFromRequestReturnsNullWhenClientCertificateMapperSilentlyFailedToParseXfcc() throws Exception {
        // Reproduces the reviewer's concern (PR #3972 discussion on TlsClientAuthentication.java:138):
        // a trusted proxy (e.g. the Gorouter) sends a well-formed mTLS connection whose own
        // certificate validates against tls-client-auth-trusted-proxy-ca, and a nonblank (but
        // malformed) X-Forwarded-Client-Cert header. ClientCertificateMapper fails to parse the
        // header and -- per its decompiled behavior -- never calls setAttribute, leaving the
        // standard jakarta.servlet.request.X509Certificate attribute equal to the raw peer
        // certificate captured by RawPeerCertificateCaptureFilter. This must be rejected, even
        // though the XFCC header is present and the peer validates as a trusted proxy: reading
        // the standard attribute here would wrongly authenticate the proxy's own certificate as
        // the OAuth client.
        KeyPair rootKp = generateKeyPair();
        X500Name rootName = new X500Name("CN=Trusted Proxy CA");
        X509Certificate rootCert = signCert(rootName, rootName, rootKp.getPublic(), rootKp.getPrivate(), true, BigInteger.ONE);
        KeyPair peerKp = generateKeyPair();
        X509Certificate peerCert = signCert(
                new X500Name("CN=gorouter"), rootName, peerKp.getPublic(), rootKp.getPrivate(), false, BigInteger.TWO);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("client-ca-pem", null);
        config.setTrustedProxyCaPem(toPem(rootCert));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE,
                new X509Certificate[]{peerCert});
        // ClientCertificateMapper did NOT replace the standard attribute -- it still holds the
        // same certificate as the raw peer capture, because parsing the (malformed) XFCC header
        // failed and the mapper filter never called setAttribute.
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{peerCert});
        request.addHeader("X-Forwarded-Client-Cert", "malformed-or-corrupted-base64-value");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            assertThat(service.getCertificateChainFromRequest(config)).isNull();
            assertThat(service.getCertificateFromRequest(config)).isNull();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial) throws Exception {
        return signCert(subject, issuer, subjectKey, signerKey, isCa, serial, null, null);
    }

    /**
     * Overload allowing tests to optionally set a Key Usage extension ({@code keyUsageBits}, a
     * bitmask built from {@link KeyUsage} constants, or {@code null} to omit the extension
     * entirely) and/or an Extended Key Usage extension ({@code ekuPurposes}, or {@code null}/empty
     * to omit it entirely). Existing call sites using the 6-arg overload above are unaffected,
     * matching production certificates that typically don't set these extensions.
     */
    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial,
            Integer keyUsageBits, List<KeyPurposeId> ekuPurposes) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        return signCertWithValidity(subject, issuer, subjectKey, signerKey, isCa, serial, notBefore, notAfter, keyUsageBits, ekuPurposes);
    }

    private static X509Certificate signCertWithValidity(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial, Date notBefore, Date notAfter) throws Exception {
        return signCertWithValidity(subject, issuer, subjectKey, signerKey, isCa, serial, notBefore, notAfter, null, null);
    }

    private static X509Certificate signCertWithValidity(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial, Date notBefore, Date notAfter,
            Integer keyUsageBits, List<KeyPurposeId> ekuPurposes) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (keyUsageBits != null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBits));
        }
        if (ekuPurposes != null && !ekuPurposes.isEmpty()) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(ekuPurposes.toArray(new KeyPurposeId[0])));
        }
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
