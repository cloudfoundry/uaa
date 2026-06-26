package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateOuParserTests {

    private final CertificateOuParser parser = new CertificateOuParser();

    @Test
    void extractsOrgSpaceAppFromMultiValuedOuRdn() {
        X509Certificate cert = SpiffeTestCerts
                .newInstanceCert(SpiffeTestCerts.newCa(), "org-guid", "space-guid", "app-guid")
                .certificate();

        CfInstanceIdentity identity = parser.parse(cert);

        assertThat(identity.orgId()).isEqualTo("org-guid");
        assertThat(identity.spaceId()).isEqualTo("space-guid");
        assertThat(identity.appId()).isEqualTo("app-guid");
    }

    @Test
    void throwsWhenRequiredOuMissing() {
        X509Certificate ca = SpiffeTestCerts.newCa().certificate(); // CA cert has only CN, no OUs

        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> parser.parse(ca))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("organization");
    }
}
