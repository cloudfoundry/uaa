package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

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
            certificate.verify(caCertificate.getPublicKey(), BouncyCastleFipsProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new InvalidInstanceCertificateException(e.getMessage(), e);
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
