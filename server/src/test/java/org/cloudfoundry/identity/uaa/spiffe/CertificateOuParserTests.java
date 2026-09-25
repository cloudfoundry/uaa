package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

        assertThatThrownBy(() -> parser.parse(ca))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("organization");
    }

    /**
     * Letting the last matching OU win would make the extracted identity depend on RDN ordering,
     * so a certificate carrying both {@code app:real} and {@code app:other} would silently
     * resolve to whichever the encoder happened to place last.
     */
    @ParameterizedTest
    @CsvSource({
            "app,        'organization:o,space:s,app:real,app:other'",
            "space,      'organization:o,space:s1,space:s2,app:a'",
            "organization,'organization:o1,organization:o2,space:s,app:a'"
    })
    void throwsWhenAnOuPrefixAppearsTwice(String expectedName, String ous) {
        X509Certificate cert = SpiffeTestCerts
                .newInstanceCertWithOus(SpiffeTestCerts.newCa(), ous.split(","))
                .certificate();

        assertThatThrownBy(() -> parser.parse(cert))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("more than one")
                .hasMessageContaining(expectedName);
    }
}
