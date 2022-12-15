package org.cloudfoundry.identity.uaa.zone;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.springframework.security.oauth2.provider.ClientDetails;

@Configuration
public class OrchestratorZoneConfiguration {

    @Bean
    @ConditionalOnProperty({ "uaa.dashboard.uri" })
    public OrchestratorZoneService orchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                                                           @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning idpProvisioning,
                                                           @Qualifier("scimGroupProvisioning") ScimGroupProvisioning groupProvisioning,
                                                           @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
                                                           @Qualifier("clientDetailsValidator") ClientDetailsValidator clientDetailsValidator,
                                                           @Value("${uaa.dashboard.uri}") String uaaDashboardUri,
                                                           @Value("${issuer.uri}") String uaaUrl) {
        return new OrchestratorZoneService(zoneProvisioning, idpProvisioning, groupProvisioning, clientDetailsService,
                                           clientDetailsValidator, uaaDashboardUri, uaaUrl);
    }

}
