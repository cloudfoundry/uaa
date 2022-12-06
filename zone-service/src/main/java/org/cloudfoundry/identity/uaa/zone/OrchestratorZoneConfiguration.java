package org.cloudfoundry.identity.uaa.zone;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OrchestratorZoneConfiguration {

    @Bean
    @ConditionalOnProperty({ "uaa.dashboard.uri" })
    public OrchestratorZoneService zoneService(IdentityZoneProvisioning zoneProvisioning,
                                               @Value("${uaa.dashboard.uri}") String uaaDashboardUri) {
        return new OrchestratorZoneService(zoneProvisioning, uaaDashboardUri);
    }

}
