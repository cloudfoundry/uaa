package org.cloudfoundry.identity.uaa.spiffe;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
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

    @Bean("spiffeInstanceIdentityCa")
    public X509Certificate spiffeInstanceIdentityCa(SpiffeProperties properties) {
        try {
            return new KeyWithCert(properties.instanceIdentityCa()).getCertificate();
        } catch (CertificateException e) {
            throw new IllegalStateException("Invalid uaa.spiffe.instance_identity_ca", e);
        }
    }
}
