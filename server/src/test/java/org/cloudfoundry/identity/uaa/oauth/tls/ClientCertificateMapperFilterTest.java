package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
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
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ClientCertificateMapperFilterTest {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void clientCertificateMapperFilter_registersClientCertificateMapperForMtlsEndpoint() {
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> bean = config.clientCertificateMapperFilter();
        assertThat(bean.getFilter()).isInstanceOf(MtlsPathGuardedFilter.class);
        assertThat(((MtlsPathGuardedFilter) bean.getFilter()).getDelegate().getClass().getName())
                .isEqualTo("org.cloudfoundry.router.jakarta.ClientCertificateMapper");
        // No addUrlPatterns(...): registered on the default (all-requests) pattern, guarded internally
        // by MtlsPathGuardedFilter -- see RawPeerCertificateCaptureFilterRegistrationTest for why a
        // container URL-pattern registration cannot correctly scope this filter to zone-path requests.
        assertThat(bean.getUrlPatterns()).isEmpty();
    }

    @Test
    void doesNotInvokeTheDelegateForUnrelatedPaths() throws Exception {
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/not-token");
        request.addHeader("X-Forwarded-Client-Cert",
                Base64.getEncoder().encodeToString(generateSelfSignedCert().getEncoded()));
        MockHttpServletResponse response = new MockHttpServletResponse();

        mapperBean.getFilter().doFilter(request, response, (req, res) -> { });

        assertThat(request.getAttribute("jakarta.servlet.request.X509Certificate"))
                .as("ClientCertificateMapper must not run for a path other than /oauth/mtls/token/**")
                .isNull();
    }

    @Test
    void clientCertificateMapperFilterPopulatesCertAttributeBeforeSpringSecurityRuns() throws Exception {
        // Behavioural regression test for the ordering bug reported in PR review
        // (SpringServletXmlFiltersConfiguration.java:250): the ClientCertificateMapper filter
        // must run *before* Spring Boot's Security filter in servlet-container dispatch order
        // (filters run in ascending getOrder() value), so that the
        // jakarta.servlet.request.X509Certificate attribute it derives from the
        // X-Forwarded-Client-Cert header is already populated when Spring Security's
        // authentication logic (ClientDetailsAuthenticationProvider / TlsClientAuthentication)
        // reads it for the /oauth/mtls/token request.
        //
        // Rather than asserting on the raw order integer in isolation, this drives a real
        // two-filter chain -- the actual ClientCertificateMapper filter plus a stand-in for
        // Spring Boot's registered Security filter at its real documented order (-100,
        // org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties
        // .DEFAULT_FILTER_ORDER) -- through a real request carrying a real X-Forwarded-Client-Cert
        // header, and observes what the "security" filter actually sees.
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        AtomicReference<Object> certSeenBySecurityFilter = new AtomicReference<>();
        FilterRegistrationBean<Filter> securityFilterBean =
                fakeSpringSecurityFilterBean(certSeenBySecurityFilter, -100);

        MockHttpServletRequest request = requestWithClientCertHeader();
        MockHttpServletResponse response = new MockHttpServletResponse();

        runContainerFilterChain(List.of(mapperBean, securityFilterBean), request, response);

        assertThat(certSeenBySecurityFilter.get())
                .as("X509Certificate request attribute must be populated before Spring Security's filter runs")
                .isInstanceOf(X509Certificate[].class);
    }

    @Test
    void securityFilterOrderedFirstWouldNotSeeCertAttribute() throws Exception {
        // Companion/control test proving the pre-fix behaviour really was broken: with the
        // ClientCertificateMapper filter's order set the way it was before this fix (10, which
        // is *after* Spring Security's -100), the cert attribute is not yet populated when
        // Spring Security's filter runs.
        Filter clientCertificateMapper =
                new SpringServletXmlFiltersConfiguration().clientCertificateMapperFilter().getFilter();
        FilterRegistrationBean<Filter> mapperBeanWithBuggyOrder = new FilterRegistrationBean<>(clientCertificateMapper);
        mapperBeanWithBuggyOrder.setOrder(10); // the old, buggy order

        AtomicReference<Object> certSeenBySecurityFilter = new AtomicReference<>();
        FilterRegistrationBean<Filter> securityFilterBean =
                fakeSpringSecurityFilterBean(certSeenBySecurityFilter, -100);

        MockHttpServletRequest request = requestWithClientCertHeader();
        MockHttpServletResponse response = new MockHttpServletResponse();

        runContainerFilterChain(List.of(mapperBeanWithBuggyOrder, securityFilterBean), request, response);

        assertThat(certSeenBySecurityFilter.get())
                .as("with the old buggy order, Spring Security runs first and must NOT see the cert attribute yet")
                .isNull();
    }

    private static FilterRegistrationBean<Filter> fakeSpringSecurityFilterBean(
            AtomicReference<Object> certSeenBySecurityFilter, int order) {
        Filter fakeSpringSecurityFilter = (request, response, chain) -> {
            certSeenBySecurityFilter.set(
                    ((HttpServletRequest) request).getAttribute("jakarta.servlet.request.X509Certificate"));
            chain.doFilter(request, response);
        };
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(fakeSpringSecurityFilter);
        bean.setOrder(order);
        return bean;
    }

    /**
     * Simulates servlet-container filter dispatch: registered filters run in ascending
     * {@link FilterRegistrationBean#getOrder()} value, each delegating to the next via a
     * standard {@link FilterChain}.
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

    private static MockHttpServletRequest requestWithClientCertHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/token");
        request.addHeader("X-Forwarded-Client-Cert",
                Base64.getEncoder().encodeToString(generateSelfSignedCert().getEncoded()));
        return request;
    }

    private static X509Certificate generateSelfSignedCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=leaf-instance");
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
