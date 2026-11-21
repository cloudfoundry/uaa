package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for application-wide beans, as well as "infrastructure" beans
 * that help enable other beans (e.g. during the migration from XML config to Java config).
 */
@Configuration
@EnableConfigurationProperties({
        UaaProperties.Uaa.class,
        UaaProperties.AdminTokenNetworkPolicy.class,
        UaaProperties.Login.class,
        UaaProperties.Logout.class,
        UaaProperties.Servlet.class,
        UaaProperties.RootLevel.class,
        UaaProperties.Csp.class,
        UaaProperties.Metrics.class,
        UaaProperties.Zones.class,
        UaaProperties.GlobalClientSecretPolicy.class,
        UaaProperties.DefaultClientSecretPolicy.class
})
public class UaaConfig {

    @Bean
    public org.cloudfoundry.identity.uaa.oauth.AdminTokenNetworkPolicy adminTokenNetworkPolicy(
            UaaProperties.AdminTokenNetworkPolicy properties) {
        return new org.cloudfoundry.identity.uaa.oauth.AdminTokenNetworkPolicy(properties);
    }

    @Bean
    public KeyInfoService keyInfoService(UaaProperties.Uaa uaaProperties) {
        return new KeyInfoService(uaaProperties.url());
    }

}
