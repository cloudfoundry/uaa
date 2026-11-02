package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BCJSSEUtilTest {

    @BeforeEach
    void setUp() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();
    }

    @Test
    void enabledProtocolsExcludeSslv2HelloAndIncludeTls13() {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);

        BCJSSEUtil util = new BCJSSEUtil(certificate);

        assertThat(util.getEnabledProtocols()).contains("TLSv1.3", "TLSv1.2");
        assertThat(util.getEnabledProtocols()).doesNotContain("SSLv2Hello", "SSLv3");
    }
}
