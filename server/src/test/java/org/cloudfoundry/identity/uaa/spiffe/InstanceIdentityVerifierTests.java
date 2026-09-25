package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InstanceIdentityVerifierTests {

    private final SpiffeTestCerts.CertKey ca = SpiffeTestCerts.newCa();
    private final InstanceIdentityVerifier verifier = new InstanceIdentityVerifier(ca.certificate());

    @Test
    void acceptsCertSignedByConfiguredCa() {
        SpiffeTestCerts.CertKey leaf = SpiffeTestCerts.newInstanceCert(ca, "o", "s", "a");

        assertThat(verifier.isValid(leaf.certificate())).isTrue();
    }

    @Test
    void rejectsCertSignedByDifferentCa() {
        SpiffeTestCerts.CertKey otherCa = SpiffeTestCerts.newCa();
        SpiffeTestCerts.CertKey leaf = SpiffeTestCerts.newInstanceCert(otherCa, "o", "s", "a");

        assertThatThrownBy(() -> verifier.verify(leaf.certificate()))
                .isInstanceOf(InstanceIdentityVerifier.InvalidInstanceCertificateException.class);
        assertThat(verifier.isValid(leaf.certificate())).isFalse();
    }

    @Test
    void rejectsExpiredCert() {
        SpiffeTestCerts.CertKey leaf = SpiffeTestCerts.newInstanceCert(ca, "o", "s", "a",
                Instant.now().minus(2, ChronoUnit.HOURS), Instant.now().minus(1, ChronoUnit.HOURS));

        assertThat(verifier.isValid(leaf.certificate())).isFalse();
    }

    @Test
    void rejectsNotYetValidCert() {
        SpiffeTestCerts.CertKey leaf = SpiffeTestCerts.newInstanceCert(ca, "o", "s", "a",
                Instant.now().plus(1, ChronoUnit.HOURS), Instant.now().plus(2, ChronoUnit.HOURS));

        assertThat(verifier.isValid(leaf.certificate())).isFalse();
    }
}
