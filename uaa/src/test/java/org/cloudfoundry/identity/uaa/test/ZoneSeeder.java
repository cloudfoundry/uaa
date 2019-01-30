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
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;

/**
 * An easy way to create and populate a new Identity Zone for tests to help you isolate your test setup.
 *
 * Can be injected into your before or test method as a parameter (see {@link ZoneSeederExtension}).
 *
 * Use the with*() methods to configure, then call {@link #seed()} to create the data in the db.
 * After calling {@link #seed()}, use the get*() methods to query what was created,
 * and use the create*() methods to keep creating more objects in the zone.
 *
 * {@link #destroy()} will automatically be called by {@link ZoneSeederExtension#afterEach(ExtensionContext)}
 * to perform a cascading delete of the zone and its contents after each test.
 */
public class ZoneSeeder {
    private static final String WITH_IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID = "with_implict_password_refresh_token";

    private final ApplicationContext applicationContext;
    private final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private final JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private final JdbcQueryableClientDetailsService jdbcClientDetailsService;
    private final RandomValueStringGenerator generator;
    private final ScimUserProvisioning scimUserProvisioning;

    private boolean disableInternalUserManagement = false;

    private final List<ClientDetails> clientDetailsToCreate = new ArrayList<>();
    private IdentityProvider identityProviderToCreate;
    private UaaIdentityProviderDefinition uaaIdentityProviderDefinitionToCreate;

    private IdentityZone identityZone;
    private IdentityProvider identityProvider;
    private final Map<String, ClientDetails> clientDetails = new HashMap<>();
    private final Map<String, String> plainTextPasswordsForUsers = new HashMap<>();

    public ZoneSeeder(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;

        jdbcIdentityZoneProvisioning = applicationContext.getBean(JdbcIdentityZoneProvisioning.class);
        jdbcIdentityProviderProvisioning = applicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        jdbcClientDetailsService = applicationContext.getBean(JdbcQueryableClientDetailsService.class);
        scimUserProvisioning = applicationContext.getBean(ScimUserProvisioning.class);

        generator = new RandomValueStringGenerator();
    }

    public ZoneSeeder withDefaults() {
        return withUaaIdentityProvider().withDisableInternalUserManagement(false);
    }

    public ZoneSeeder withUaaIdentityProvider() {
        identityProviderToCreate = new IdentityProvider<UaaIdentityProviderDefinition>();
        identityProviderToCreate.setName(generator.generate());
        uaaIdentityProviderDefinitionToCreate = new UaaIdentityProviderDefinition();
        identityProviderToCreate.setConfig(uaaIdentityProviderDefinitionToCreate);
        identityProviderToCreate.setType(OriginKeys.UAA);
        identityProviderToCreate.setOriginKey(OriginKeys.UAA);

        return this;
    }

    public ZoneSeeder withDisableInternalUserManagement(boolean disableInternalUserManagement) {
        this.disableInternalUserManagement = disableInternalUserManagement;
        return this;
    }

    public ZoneSeeder withImplicitPasswordRefreshTokenClient() {
        BaseClientDetails newClient = new BaseClientDetails(WITH_IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID,
                "none",
                "uaa.user,cloud_controller.read,cloud_controller.write,openid,password.write,scim.userids,cloud_controller.admin,scim.read,scim.write",
                "implicit,password,refresh_token",
                "uaa.none",
                "http://localhost:8080/**");
        newClient.setClientSecret("");
        clientDetailsToCreate.add(newClient);

        return this;
    }

    public ZoneSeeder seed() {
        String zoneId = generator.generate();

        IdentityZone identityZoneToCreate = IdentityZone.getUaa();
        identityZoneToCreate.setSubdomain(generator.generate());
        identityZoneToCreate.setId(zoneId);
        this.identityZone = jdbcIdentityZoneProvisioning.create(identityZoneToCreate);

        identityProviderToCreate.setIdentityZoneId(zoneId);
        uaaIdentityProviderDefinitionToCreate.setDisableInternalUserManagement(disableInternalUserManagement);
        identityProvider = jdbcIdentityProviderProvisioning.create(identityProviderToCreate, zoneId);
        identityProviderToCreate = null;
        uaaIdentityProviderDefinitionToCreate = null;

        for (ClientDetails clientDetails : clientDetailsToCreate) {
            this.clientDetails.put(clientDetails.getClientId(), jdbcClientDetailsService.create(clientDetails, zoneId));
        }
        clientDetailsToCreate.clear();

        return this;
    }

    public void destroy() {
        UaaPrincipal justEnoughPrincipal = new UaaPrincipal(
                "id", "name", "", identityProvider.getOriginKey(), "external id", identityZone.getId()
        );
        UaaAuthentication justEnoughAuthentication = new UaaAuthentication(
                justEnoughPrincipal, Lists.newArrayList(), null
        );
        applicationContext.publishEvent(new EntityDeletedEvent<>(identityZone, justEnoughAuthentication));
    }

    public ScimUser createUser() {
        ScimUser scimUser = newRandomScimUser();
        String password = scimUser.getPassword();
        ScimUser createdUser = scimUserProvisioning.createUser(scimUser, password, getIdentityZoneId());
        plainTextPasswordsForUsers.put(createdUser.getId(), password);
        return createdUser;
    }

    public String getPlainTextPassword(ScimUser user) {
        return plainTextPasswordsForUsers.get(user.getId());
    }

    public String getIdentityZoneId() {
        return identityZone.getId();
    }

    public String getIdentityZoneSubdomain() {
        return identityZone.getSubdomain();
    }

    public HttpHeaders getZoneSubomainRequestHeader() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Host", getIdentityZoneSubdomain() + ".localhost");
        return httpHeaders;
    }

    public HttpHeaders getZoneIdRequestHeader() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HEADER, getIdentityZoneId());
        return httpHeaders;
    }

    public IdentityZone getIdentityZone() {
        return identityZone;
    }

    public IdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    public ClientDetails getImplicitPasswordRefreshTokenClient() {
        return clientDetails.get(WITH_IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID);
    }

    private ScimUser newRandomScimUser() {
        String email = generator.generate().toLowerCase() + "@" + generator.generate().toLowerCase() + ".com";
        ScimUser scimUser = new ScimUser(null, email, generator.generate(), generator.generate());
        scimUser.addEmail(email);
        scimUser.setPassword(generator.generate());
        return scimUser;
    }
}
