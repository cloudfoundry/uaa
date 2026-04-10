package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.Initializer;
import org.opensaml.security.config.GlobalNamedCurveRegistryInitializer;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

import java.security.Security;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap.CONFIG_PROPERTY_ECDH_DEFAULT_KDF;

@Configuration
@Slf4j
public class IdentityZoneConfig {

    private static final AtomicBoolean samlInitialized = new AtomicBoolean(false);

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

    @Bean
    public static Boolean setupOpenSaml() {
        if (samlInitialized.compareAndSet(false, true)) {
            Properties props = ConfigurationService.getConfigurationProperties();
            props.put(CONFIG_PROPERTY_ECDH_DEFAULT_KDF, DefaultSecurityConfigurationBootstrap.PBKDF2);
            Class<?> toSkip = GlobalNamedCurveRegistryInitializer.class;
            ServiceLoader.load(Initializer.class).stream().filter((provider) -> provider.type() != toSkip).forEach((provider) -> init(provider));
            try {
                OpenSamlInitializationService.initialize();
            } catch (NoClassDefFoundError | NoSuchMethodError e) {
                // ignore
            }
        }
        return Boolean.TRUE;
    }

    private static void init(ServiceLoader.Provider<Initializer> provider) {
        try {
            provider.get().init();
        } catch (InitializationException ex) {
            throw new Saml2Exception(ex);
        }
    }
}
