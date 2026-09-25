package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/** Verifies an instance cert chains to the configured CA and is currently time-valid. */
@Component
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class InstanceIdentityVerifier {

    private final X509Certificate caCertificate;

    public InstanceIdentityVerifier(@Qualifier("spiffeInstanceIdentityCa") X509Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }

    /** @throws InvalidInstanceCertificateException if the cert is untrusted or not time-valid. */
    public void verify(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            // An expired trust anchor must stop anchoring trust.
            caCertificate.checkValidity();
            rejectNonLeaf(certificate);
            certificate.verify(caCertificate.getPublicKey(), BouncyCastleFipsProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new InvalidInstanceCertificateException(e.getMessage(), e);
        }
    }

    /**
     * A self-signed certificate verifies against its own public key, so the signature check alone
     * accepts the configured CA certificate as though the CA had issued it as a leaf. The CA
     * certificate is public, so without this the trust anchor doubles as a presentable workload
     * identity. Diego instance certificates are always CA-issued and are never themselves CAs.
     */
    private static void rejectNonLeaf(X509Certificate certificate) throws CertificateException {
        if (certificate.getBasicConstraints() >= 0) {
            throw new CertificateException("A CA certificate is not a workload instance certificate");
        }
        if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            throw new CertificateException("A self-issued certificate is not a workload instance certificate");
        }
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            verify(certificate);
            return true;
        } catch (InvalidInstanceCertificateException e) {
            return false;
        }
    }

    public static class InvalidInstanceCertificateException extends RuntimeException {
        public InvalidInstanceCertificateException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
