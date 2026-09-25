package org.cloudfoundry.identity.uaa.spiffe;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/** Enables SPIFFE properties and exposes the parsed instance-identity CA certificate. */
@Configuration
@EnableConfigurationProperties(SpiffeProperties.class)
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class SpiffeConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(SpiffeConfiguration.class);

    @Bean("spiffeInstanceIdentityCa")
    public X509Certificate spiffeInstanceIdentityCa(SpiffeProperties properties) {
        // Fail fast on configuration that would otherwise only show up in issued identities:
        // an unset trust domain mints spiffe://null/cf/org/... for every workload.
        SpiffeId.requireTrustDomain(properties.trustDomain());
        warnIfProofOfPossessionDisabled(properties);
        try {
            return new KeyWithCert(properties.instanceIdentityCa()).getCertificate();
        } catch (CertificateException e) {
            throw new IllegalStateException("Invalid uaa.spiffe.instance-identity-ca", e);
        }
    }

    private static void warnIfProofOfPossessionDisabled(SpiffeProperties properties) {
        if (!properties.popEnabled()) {
            logger.warn("uaa.spiffe.pop-enabled is false. /jwt-svid/sign will issue a JWT-SVID to any "
                    + "caller that presents a workload's instance certificate, without proving the caller "
                    + "holds the matching private key. An instance certificate is not a secret -- it is "
                    + "sent in TLS handshakes and forwarded in X-Forwarded-Client-Cert headers -- so any "
                    + "client holding the uaa.resource authority can impersonate any workload on this "
                    + "foundation. Do not use this setting outside local development.");
        }
    }
}
