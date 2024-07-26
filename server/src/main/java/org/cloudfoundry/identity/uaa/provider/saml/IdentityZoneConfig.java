package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import java.security.Security;

@Configuration
public class IdentityZoneConfig {

    @Bean
    public BouncyCastleFipsProvider setUpBouncyCastle() {
        BouncyCastleFipsProvider provider = new BouncyCastleFipsProvider();
        Security.addProvider(provider);
        return provider;
    }

    @Bean
    public ZoneAwareKeyManager zoneAwareSamlSpKeyManager() {
        return new ZoneAwareKeyManager();
    }

    @Autowired
    @Bean
    SamlKeyManagerFactory samlKeyManagerFactory(SamlConfigProps samlConfigProps) {
        return new SamlKeyManagerFactory(samlConfigProps);
    }

    @Autowired
    @DependsOn({"identityZoneConfigurationBootstrap", "setUpBouncyCastle"})
    @Bean(destroyMethod = "reset")
    public IdentityZoneHolder.Initializer identityZoneHolderInitializer(IdentityZoneProvisioning provisioning,
                                                                        SamlKeyManagerFactory samlKeyManagerFactory) {

        return new IdentityZoneHolder.Initializer(provisioning, samlKeyManagerFactory);
    }
}
