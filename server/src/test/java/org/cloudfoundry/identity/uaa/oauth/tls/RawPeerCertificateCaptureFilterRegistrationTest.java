package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.SpringServletXmlFiltersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

class RawPeerCertificateCaptureFilterRegistrationTest {

    @Test
    void rawPeerCertificateCaptureFilterRunsBeforeClientCertificateMapper() {
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();

        FilterRegistrationBean<?> captureBean = config.rawPeerCertificateCaptureFilter();
        FilterRegistrationBean<?> mapperBean = config.clientCertificateMapperFilter();

        assertThat(captureBean.getFilter()).isInstanceOf(RawPeerCertificateCaptureFilter.class);
        assertThat(captureBean.getUrlPatterns()).contains("/oauth/mtls/*");
        assertThat(captureBean.getOrder()).isLessThan(mapperBean.getOrder());
    }
}
