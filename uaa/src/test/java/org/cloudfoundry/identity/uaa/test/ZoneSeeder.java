package org.cloudfoundry.identity.uaa.test;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.JdbcQueryableClientDetailsService;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class ZoneSeeder {
    private final RandomValueStringGenerator generator;
    private final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private final JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private final JdbcQueryableClientDetailsService jdbcClientDetailsService;
    private final ApplicationContext applicationContext;

    private boolean disableInternalUserManagement = false;

    private IdentityZone identityZone;
    private IdentityProvider identityProvider;
    private ClientDetails clientDetails;

    public ZoneSeeder(ApplicationContext applicationContext) {
        jdbcIdentityZoneProvisioning = applicationContext.getBean(JdbcIdentityZoneProvisioning.class);
        jdbcIdentityProviderProvisioning = applicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        jdbcClientDetailsService = applicationContext.getBean(JdbcQueryableClientDetailsService.class);
        this.applicationContext = applicationContext;

        generator = new RandomValueStringGenerator();
    }

    public ZoneSeeder seed() {
        IdentityZone newZone = IdentityZone.getUaa();
        newZone.setSubdomain(generator.generate());
        newZone.setId(generator.generate());
        identityZone = jdbcIdentityZoneProvisioning.create(newZone);

        IdentityProvider<UaaIdentityProviderDefinition> newIdentityProvider = new IdentityProvider<>();
        newIdentityProvider.setIdentityZoneId(identityZone.getId());
        newIdentityProvider.setName(generator.generate());
        UaaIdentityProviderDefinition uaaConfig = new UaaIdentityProviderDefinition();
        newIdentityProvider.setConfig(uaaConfig);
        newIdentityProvider.setType(OriginKeys.UAA);
        newIdentityProvider.setOriginKey(OriginKeys.UAA);

        identityProvider = jdbcIdentityProviderProvisioning.create(newIdentityProvider, newIdentityProvider.getIdentityZoneId());

        BaseClientDetails newClient = new BaseClientDetails(generator.generate(),
                "none",
                "uaa.user,cloud_controller.read,cloud_controller.write,openid,password.write,scim.userids,cloud_controller.admin,scim.read,scim.write",
                "implicit,password,refresh_token",
                "uaa.none",
                "http://localhost:8080/**");
        newClient.setClientSecret("");
        clientDetails = jdbcClientDetailsService.create(newClient, newIdentityProvider.getIdentityZoneId());

        ((UaaIdentityProviderDefinition) identityProvider.getConfig()).setDisableInternalUserManagement(disableInternalUserManagement);
        jdbcIdentityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        return this;
    }

    public ClientDetails getClientDetails() {
        return clientDetails;
    }

    public IdentityZone getIdentityZone() {
        return identityZone;
    }
    
    public ZoneSeeder withDisableInternalUserManagement(boolean disableInternalUserManagement) {
        this.disableInternalUserManagement = disableInternalUserManagement;
        return this;
    }

    public void destroy() {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("id", "name", "", OriginKeys.UAA, "external id", identityZone.getId()), Lists.newArrayList(), null);
        applicationContext.publishEvent(
                new EntityDeletedEvent<>(identityZone, authentication)
        );
    }
}
