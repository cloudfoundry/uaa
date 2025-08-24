package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import java.security.Security;

@Configuration
@Slf4j
public class IdentityZoneConfig {

    @Bean
    public BouncyCastleFipsProvider setUpBouncyCastle() {
        // Ensure non blocking random if system property java.security.egd is set
        if (System.getProperty("java.security.egd", "/random").endsWith("/urandom") &&
                !Security.getProperty("securerandom.strongAlgorithms").contains("NativePRNGNonBlocking")) {
            String originalStrongAlgorithm = Security.getProperty("securerandom.strongAlgorithms");
            log.info("Current securerandom.strongAlgorithms: {}", originalStrongAlgorithm);
            String newStrongAlgorithm = "NativePRNGNonBlocking:SUN," + originalStrongAlgorithm;
            log.info("New securerandom.strongAlgorithms: {}", newStrongAlgorithm);
            Security.setProperty("securerandom.strongAlgorithms", newStrongAlgorithm);
        }
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        BouncyCastleFipsProvider provider = new BouncyCastleFipsProvider();
        Security.addProvider(provider);
        return provider;
    }

    @Bean
    public ZoneAwareKeyManager zoneAwareSamlSpKeyManager() {
        return new ZoneAwareKeyManager();
    }

    @Bean
    SamlKeyManagerFactory samlKeyManagerFactory(SamlConfigProps samlConfigProps) {
        return new SamlKeyManagerFactory(samlConfigProps);
    }

    @DependsOn({"identityZoneConfigurationBootstrap", "setUpBouncyCastle"})
    @Bean(destroyMethod = "reset")
    public IdentityZoneHolder.Initializer identityZoneHolderInitializer(IdentityZoneProvisioning provisioning,
            SamlKeyManagerFactory samlKeyManagerFactory) {

        return new IdentityZoneHolder.Initializer(provisioning, samlKeyManagerFactory);
    }
}
