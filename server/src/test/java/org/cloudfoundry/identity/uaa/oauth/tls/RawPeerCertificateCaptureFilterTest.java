package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RawPeerCertificateCaptureFilterTest {

    @Test
    void copiesGenuinePeerCertificateIntoDedicatedAttributeBeforeChainContinues() throws Exception {
        X509Certificate[] genuinePeerCert = new X509Certificate[]{mock(X509Certificate.class)};
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/token");
        request.setAttribute("jakarta.servlet.request.X509Certificate", genuinePeerCert);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        new RawPeerCertificateCaptureFilter().doFilter(request, response, chain);

        assertThat(request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE))
                .isEqualTo(genuinePeerCert);
        verify(chain).doFilter(request, response);
    }

    @Test
    void setsNullAttributeWhenNoPeerCertificatePresent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/oauth/mtls/token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        new RawPeerCertificateCaptureFilter().doFilter(request, response, chain);

        assertThat(request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE))
                .isNull();
        verify(chain).doFilter(request, response);
    }
}
