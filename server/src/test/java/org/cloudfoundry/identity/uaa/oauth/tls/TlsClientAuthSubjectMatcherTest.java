package org.cloudfoundry.identity.uaa.oauth.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 8705 section 2.1.2 subject binding.
 *
 * <p>Every negative case asserts a positive control alongside it, so that an implementation which
 * simply never matches cannot make these tests pass.
 */
class TlsClientAuthSubjectMatcherTest {

    @BeforeAll
    static void registerFipsProvider() {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    @Nested
    @DisplayName("tls_client_auth_subject_dn")
    class SubjectDn {

        @Test
        void matchesExactSubjectDn() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one,OU=space-a,O=acme");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one,OU=space-a,O=acme")))
                    .isTrue();
        }

        @Test
        void rejectsDifferentSubjectDn() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one,OU=space-a,O=acme");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-two,OU=space-a,O=acme")))
                    .as("a different CN is a different client")
                    .isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one,OU=space-a,O=acme")))
                    .as("positive control")
                    .isTrue();
        }

        @Test
        @DisplayName("RFC 4517 distinguishedNameMatch: attribute type case and spacing are not significant")
        void matchesRegardlessOfAttributeTypeCaseAndSpacing() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one,OU=space-a,O=acme");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("cn=app-one, ou=space-a, o=acme")))
                    .as("attribute types are case-insensitive and optional whitespace after commas is ignored")
                    .isTrue();
        }

        @Test
        @DisplayName("RFC 4517 distinguishedNameMatch: RDN order IS significant")
        void rejectsReorderedRelativeDistinguishedNames() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one,OU=space-a,O=acme");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("O=acme,OU=space-a,CN=app-one")))
                    .as("a DN is an ordered sequence of RDNs; reordering names a different entry")
                    .isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one,OU=space-a,O=acme")))
                    .as("positive control")
                    .isTrue();
        }

        @Test
        void rejectsUnparseableConfiguredDn() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("not a distinguished name")))
                    .as("a malformed registered DN must fail closed, not throw")
                    .isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one")))
                    .as("positive control")
                    .isTrue();
        }
    }

    @Nested
    @DisplayName("subjectAltName bindings")
    class SubjectAltNames {

        @Test
        void matchesDnsSan() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.dNSName, "app.example.com"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com"))).isTrue();
        }

        @Test
        void rejectsDifferentDnsSan() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.dNSName, "app.example.com"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "evil.example.com"))).isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com")))
                    .as("positive control").isTrue();
        }

        @Test
        @DisplayName("a DNS SAN must not be satisfied by a SAN entry of a different type")
        void rejectsCrossTypeSanConfusion() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.rfc822Name, "app.example.com"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com")))
                    .as("the value appears in the certificate, but as an email SAN, not a dNSName")
                    .isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL, "app.example.com")))
                    .as("positive control: matched against the right SAN type it succeeds")
                    .isTrue();
        }

        @Test
        void matchesUriSan() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://acme/app/one"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI, "spiffe://acme/app/one"))).isTrue();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI, "spiffe://acme/app/two"))).isFalse();
        }

        @Test
        void matchesEmailSan() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.rfc822Name, "svc@example.com"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL, "svc@example.com"))).isTrue();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL, "other@example.com"))).isFalse();
        }

        @Test
        @DisplayName("RFC 8705 2.1.2: IP SANs are compared in binary form, not as strings")
        void matchesIpSanInBinaryForm() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.iPAddress, "2001:db8::1"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "2001:db8::1"))).isTrue();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "2001:0db8:0000:0000:0000:0000:0000:0001")))
                    .as("the same address written in expanded form is the same address in binary")
                    .isTrue();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "2001:db8::2"))).isFalse();
        }

        @Test
        void matchesIpv4San() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.iPAddress, "10.0.0.7"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "10.0.0.7"))).isTrue();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "10.0.0.8"))).isFalse();
        }

        @Test
        void matchesWhenCertificateCarriesSeveralSanEntries() throws Exception {
            X509Certificate cert = certWithSans("CN=irrelevant",
                    new GeneralName(GeneralName.dNSName, "other.example.com"),
                    new GeneralName(GeneralName.dNSName, "app.example.com"));

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com")))
                    .as("any one matching entry of the right type is sufficient")
                    .isTrue();
        }

        @Test
        void rejectsWhenCertificateHasNoSansAtAll() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, san(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com"))).isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one")))
                    .as("positive control")
                    .isTrue();
        }
    }

    @Nested
    @DisplayName("exactly-one rule")
    class ExactlyOne {

        @Test
        void rejectsWhenNoSubjectBindingIsConfigured() throws Exception {
            X509Certificate cert = certWithSubject("CN=app-one");
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration();
            config.setTrustedCaPem("irrelevant");

            assertThat(TlsClientAuthSubjectMatcher.matches(cert, config))
                    .as("no configured subject means nothing identifies this client")
                    .isFalse();
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, subjectDn("CN=app-one")))
                    .as("positive control")
                    .isTrue();
        }

        @Test
        @DisplayName("more than one configured subject parameter fails closed")
        void rejectsWhenMoreThanOneSubjectBindingIsConfigured() throws Exception {
            X509Certificate cert = certWithSans("CN=app-one",
                    new GeneralName(GeneralName.dNSName, "app.example.com"));
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration();
            config.setTrustedCaPem("irrelevant");
            config.setSubjectDn("CN=app-one");
            config.setSanDns("app.example.com");

            // Both happen to match, so this cannot pass by accident -- it must be refused purely
            // because RFC 8705 2.1.2 permits exactly one.
            assertThat(TlsClientAuthSubjectMatcher.matches(cert, config)).isFalse();
        }

        @Test
        void reportsConfiguredBindings() {
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration();
            assertThat(config.configuredSubjectBindings()).isEmpty();

            config.setSubjectDn("CN=a");
            assertThat(config.configuredSubjectBindings())
                    .containsExactly(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN);

            config.setSanIp("10.0.0.1");
            assertThat(config.configuredSubjectBindings())
                    .containsExactly(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP);

            config.setSubjectDn("   ");
            assertThat(config.configuredSubjectBindings())
                    .as("a blank value is not a configured binding")
                    .containsExactly(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP);
        }
    }

    private static TlsClientAuthConfiguration subjectDn(String dn) {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration();
        config.setTrustedCaPem("irrelevant");
        config.setSubjectDn(dn);
        return config;
    }

    private static TlsClientAuthConfiguration san(String parameter, String value) {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration();
        config.setTrustedCaPem("irrelevant");
        switch (parameter) {
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS -> config.setSanDns(value);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI -> config.setSanUri(value);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP -> config.setSanIp(value);
            case TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL -> config.setSanEmail(value);
            default -> throw new IllegalArgumentException(parameter);
        }
        return config;
    }

    private static X509Certificate certWithSubject(String subjectDn) throws Exception {
        return buildCert(subjectDn, null);
    }

    private static X509Certificate certWithSans(String subjectDn, GeneralName... sans) throws Exception {
        return buildCert(subjectDn, new GeneralNames(sans));
    }

    private static X509Certificate buildCert(String subjectDn, GeneralNames sans) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 60_000),
                new Date(System.currentTimeMillis() + 3_600_000),
                subject, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (sans != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
