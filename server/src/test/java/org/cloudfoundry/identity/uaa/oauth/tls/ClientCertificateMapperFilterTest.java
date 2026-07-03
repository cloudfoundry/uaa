package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.SpringServletXmlFiltersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

class ClientCertificateMapperFilterTest {

    @Test
    void clientCertificateMapperFilter_registersClientCertificateMapperForMtlsEndpoint() {
        SpringServletXmlFiltersConfiguration config = new SpringServletXmlFiltersConfiguration();
        FilterRegistrationBean<?> bean = config.clientCertificateMapperFilter();
        assertThat(bean.getFilter().getClass().getName())
                .isEqualTo("org.cloudfoundry.router.jakarta.ClientCertificateMapper");
        assertThat(bean.getUrlPatterns()).contains("/oauth/mtls/*");
        assertThat(bean.getOrder()).isLessThan(100);
    }
}
