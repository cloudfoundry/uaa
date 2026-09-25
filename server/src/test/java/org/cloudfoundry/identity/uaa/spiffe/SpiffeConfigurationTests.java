package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SpiffeConfigurationTests {

    private final SpiffeConfiguration configuration = new SpiffeConfiguration();

    @Test
    void parsesConfiguredCaPemIntoCertificate() throws Exception {
        SpiffeTestCerts.CertKey ca = SpiffeTestCerts.newCa();
        String caPem = SpiffeTestCerts.certificatePem(ca.certificate());
        SpiffeProperties props = new SpiffeProperties("example.org", caPem, null, null, null);

        X509Certificate parsed = configuration.spiffeInstanceIdentityCa(props);

        assertThat(parsed.getSubjectX500Principal())
                .isEqualTo(ca.certificate().getSubjectX500Principal());
    }

    @Test
    void failsFastOnUnparseableCaPem() {
        SpiffeProperties props = new SpiffeProperties("example.org", "not-a-pem", null, null, null);

        assertThatThrownBy(() -> configuration.spiffeInstanceIdentityCa(props))
                .isInstanceOf(IllegalStateException.class);
    }
}
