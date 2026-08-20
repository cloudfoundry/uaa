package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.identity.uaa.SpringServletXmlFiltersConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RawPeerCertificateCaptureFilterRegistrationTest {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void rawPeerCertificateCaptureFilterRunsBeforeClientCertificateMapper() {
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();

        FilterRegistrationBean<?> captureBean = config.rawPeerCertificateCaptureFilter();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        assertThat(captureBean.getFilter()).isInstanceOf(RawPeerCertificateCaptureFilter.class);
        // No addUrlPatterns(...): registered on the default (all-requests) pattern -- see
        // isMtlsTokenPathAcceptsTheEffectivePostZoneRewriteServletPath() below for why a container
        // URL-pattern registration cannot correctly scope this filter to zone-path requests.
        assertThat(captureBean.getUrlPatterns()).isEmpty();
        assertThat(captureBean.getOrder()).isLessThan(mapperBean.getOrder());
    }

    @Test
    void isMtlsTokenPathAcceptsTheEffectivePostZoneRewriteServletPath() {
        // ZonePathContextRewritingFilter (which runs first in the filter chain) wraps the request so
        // that request.getServletPath() reflects the effective path *after* the /z/{subdomain} prefix
        // is stripped -- e.g. a request whose original URI is /z/myzone/oauth/mtls/token presents
        // getServletPath() == "/oauth/mtls/token" to filters running after it, same as a direct
        // (non-zone-path) request. A container URL-pattern registration for "/oauth/mtls/*" is matched
        // against the *original* request URI before any filter runs, so it would never include this
        // filter in the chain for a zone-path request -- checking the effective servlet path instead,
        // from inside the filter, works uniformly for both cases.
        MockHttpServletRequest direct = new MockHttpServletRequest();
        direct.setServletPath("/oauth/mtls/token");
        assertThat(RawPeerCertificateCaptureFilter.isMtlsTokenPath(direct)).isTrue();

        MockHttpServletRequest zonePathRewritten = new MockHttpServletRequest();
        zonePathRewritten.setContextPath("/uaa/z/myzone");
        zonePathRewritten.setRequestURI("/uaa/z/myzone/oauth/mtls/token");
        zonePathRewritten.setServletPath("/oauth/mtls/token");
        assertThat(RawPeerCertificateCaptureFilter.isMtlsTokenPath(zonePathRewritten))
                .as("must match the effective (post zone-path-rewrite) servlet path")
                .isTrue();

        MockHttpServletRequest unrelated = new MockHttpServletRequest();
        unrelated.setServletPath("/login");
        assertThat(RawPeerCertificateCaptureFilter.isMtlsTokenPath(unrelated)).isFalse();
    }

    @Test
    void doesNotCaptureAnAttributeForUnrelatedPaths() throws Exception {
        RawPeerCertificateCaptureFilter filter = new RawPeerCertificateCaptureFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/login");
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[]{generateSelfSignedCert("CN=some-peer")});
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> { });

        assertThat(request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE)).isNull();
    }

    @Test
    void capturedAttributeSurvivesClientCertificateMapperOverwritingTheStandardAttribute() throws Exception {
        // Behavioural proof, not just an order-integer comparison: simulates a real TLS handshake
        // having already populated the standard jakarta.servlet.request.X509Certificate attribute
        // with the genuine peer certificate (as Tomcat would when uaa.mtls-enabled configures
        // certificateVerification=optionalNoCA), then runs the real two-filter chain -- this filter
        // followed by the real ClientCertificateMapper -- with an X-Forwarded-Client-Cert header
        // present (a *different* certificate than the genuine peer one). ClientCertificateMapper is
        // expected to overwrite the standard attribute with the XFCC-derived certificate, while
        // RAW_PEER_CERTIFICATE_ATTRIBUTE must retain the original, genuine peer certificate.
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> captureBean = config.rawPeerCertificateCaptureFilter();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        X509Certificate genuinePeerCert = generateSelfSignedCert("CN=gorouter");
        X509Certificate xfccDerivedCert = generateSelfSignedCert("CN=app-instance");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/token");
        // Simulates what Tomcat's TLS handshake would have already set before any filter runs.
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{genuinePeerCert});
        request.addHeader("X-Forwarded-Client-Cert",
                Base64.getEncoder().encodeToString(xfccDerivedCert.getEncoded()));
        MockHttpServletResponse response = new MockHttpServletResponse();

        runContainerFilterChain(List.of(captureBean, mapperBean), request, response);

        X509Certificate[] capturedRawPeerCert =
                (X509Certificate[]) request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE);
        X509Certificate[] finalStandardAttribute =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

        assertThat(capturedRawPeerCert)
                .as("RAW_PEER_CERTIFICATE_ATTRIBUTE must retain the genuine TLS peer cert, unaffected by ClientCertificateMapper")
                .containsExactly(genuinePeerCert);
        assertThat(finalStandardAttribute)
                .as("ClientCertificateMapper should still overwrite the standard attribute with the XFCC-derived cert")
                .containsExactly(xfccDerivedCert);
    }

    @Test
    void capturesTheGenuinePeerCertificateForAZonePathMtlsRequest() throws Exception {
        // Regression test for PR review comment on SpringServletXmlFiltersConfiguration.java:262:
        // simulates a request that arrived as /z/myzone/oauth/mtls/token and was already rewritten by
        // ZonePathContextRewritingFilter (which runs first) before reaching this filter -- same
        // servlet path as a direct request, but a zone-prefixed context path/request URI. Both
        // filters must still run: a container URL-pattern registration for "/oauth/mtls/*" would not
        // have included them in the chain at all for the original /z/myzone/... request URI.
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> captureBean = config.rawPeerCertificateCaptureFilter();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        X509Certificate genuinePeerCert = generateSelfSignedCert("CN=gorouter");
        X509Certificate xfccDerivedCert = generateSelfSignedCert("CN=app-instance");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/uaa/z/myzone");
        request.setRequestURI("/uaa/z/myzone/oauth/mtls/token");
        request.setServletPath("/oauth/mtls/token");
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{genuinePeerCert});
        request.addHeader("X-Forwarded-Client-Cert",
                Base64.getEncoder().encodeToString(xfccDerivedCert.getEncoded()));
        MockHttpServletResponse response = new MockHttpServletResponse();

        runContainerFilterChain(List.of(captureBean, mapperBean), request, response);

        assertThat((X509Certificate[]) request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE))
                .as("must still capture the genuine peer cert for a zone-path mtls request")
                .containsExactly(genuinePeerCert);
        assertThat((X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate"))
                .as("ClientCertificateMapper must still run for a zone-path mtls request")
                .containsExactly(xfccDerivedCert);
    }

    /**
     * Simulates servlet-container filter dispatch: registered filters run in ascending
     * {@link FilterRegistrationBean#getOrder()} value, each delegating to the next via a standard
     * {@link FilterChain}.
     */
    private static void runContainerFilterChain(
            List<FilterRegistrationBean<?>> registrations,
            MockHttpServletRequest request,
            MockHttpServletResponse response) throws Exception {
        List<FilterRegistrationBean<?>> sorted = new ArrayList<>(registrations);
        sorted.sort(Comparator.comparingInt(FilterRegistrationBean::getOrder));

        FilterChain chain = (req, res) -> { };
        for (int i = sorted.size() - 1; i >= 0; i--) {
            Filter filter = sorted.get(i).getFilter();
            FilterChain next = chain;
            chain = (req, res) -> filter.doFilter(req, res, next);
        }
        chain.doFilter(request, response);
    }

    private static X509Certificate generateSelfSignedCert(String subjectDn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name(subjectDn);
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
