package org.cloudfoundry.identity.uaa.test;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.JdbcQueryableClientDetailsService;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;

/**
 * An easy way to create and populate a new Identity Zone for tests to help you isolate your test setup.
 * <p>
 * Can be injected into your before or test method as a parameter (see {@link ZoneSeederExtension}).
 * <p>
 * Use the with*() methods to configure, then call {@link #seed()} to create the data in the db.
 * Add callbacks with the {@link #afterSeeding(AfterSeedCallback)} method if you need to do
 * additional setup after the seed but before your test starts.
 * After seeding has happened, use the get*() methods to query what was created,
 * and use the create*() methods to keep creating more objects in the zone.
 * <p>
 * {@link #seed()} will automatically be called by {@link ZoneSeederExtension#beforeTestExecution(ExtensionContext)}
 * which happens after all beforeEach methods, just before the test itself is executed.
 * <p>
 * {@link #destroy()} will automatically be called by {@link ZoneSeederExtension#afterEach(ExtensionContext)}
 * to perform a cascading delete of the zone and its contents after each test.
 */
public class ZoneSeeder {
    private static final String IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID = "implict_password_refresh_token";
    private static final String ADMIN_CLIENT_CREDENTIALS_CLIENT_ID = "admin_client_credentials";

    private final ApplicationContext applicationContext;
    private final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private final JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private final JdbcQueryableClientDetailsService jdbcClientDetailsService;
    private final RandomValueStringGenerator generator;
    private final ScimUserProvisioning jdbcScimUserProvisioning;
    private final JdbcScimGroupProvisioning jdbcScimGroupProvisioning;
    private final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    private boolean alreadySeeded;
    private final List<AfterSeedCallback> afterSeedCallbacks = new ArrayList<>();

    private boolean disableInternalUserManagement;

    private final List<ClientDetails> clientDetailsToCreate = new ArrayList<>();
    private final HashMap<ScimUser, List<String>> usersInGroupsToCreate = new HashMap<>();
    private IdentityProvider identityProviderToCreate;
    private UaaIdentityProviderDefinition uaaIdentityProviderDefinitionToCreate;

    private IdentityZone identityZone;
    private IdentityProvider identityProvider;
    private final Map<String, ClientDetails> clientDetails = new HashMap<>();
    private final Map<String, ScimUser> users = new HashMap<>();
    private final Map<String, String> plainTextPasswordsForUsers = new HashMap<>();
    private final Map<String, String> plainTextClientSecretsForClients = new HashMap<>();

    ZoneSeeder(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;

        jdbcIdentityZoneProvisioning = applicationContext.getBean(JdbcIdentityZoneProvisioning.class);
        jdbcIdentityProviderProvisioning = applicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        jdbcClientDetailsService = applicationContext.getBean(JdbcQueryableClientDetailsService.class);
        jdbcScimUserProvisioning = applicationContext.getBean(JdbcScimUserProvisioning.class);
        jdbcScimGroupProvisioning = applicationContext.getBean(JdbcScimGroupProvisioning.class);
        jdbcScimGroupMembershipManager = applicationContext.getBean(JdbcScimGroupMembershipManager.class);

        generator = new RandomValueStringGenerator();
    }

    public ZoneSeeder withDefaults() {
        return withUaaIdentityProvider().withDisableInternalUserManagement(false);
    }

    private ZoneSeeder withUaaIdentityProvider() {
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

    public ZoneSeeder withClient(ClientDetails clientDetails) {
        clientDetailsToCreate.add(clientDetails);
        return this;
    }

    public ZoneSeeder withClientWithImplicitPasswordRefreshTokenGrants() {
        return withClientWithImplicitPasswordRefreshTokenGrants(
                IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID,
                "uaa.user,cloud_controller.read,cloud_controller.write,openid," +
                        "password.write,scim.userids,cloud_controller.admin,scim.read,scim.write"
        );
    }

    public ZoneSeeder withClientWithImplicitPasswordRefreshTokenGrants(String clientId, String commaSeparatedScopeNames) {
        UaaClientDetails newClient = new UaaClientDetails(clientId,
                "none",
                commaSeparatedScopeNames,
                "implicit,password,refresh_token",
                "uaa.none",
                "http://localhost:8080/**");
        newClient.setClientSecret(generator.generate());
        clientDetailsToCreate.add(newClient);

        return this;
    }

    public ZoneSeeder withClientWithImplicitAndAuthorizationCodeGrants(
            String clientId,
            String commaSeparatedRedirectUris) {
        UaaClientDetails newClient = new UaaClientDetails(
                clientId,
                "none",
                "openid",
                "implicit,authorization_code",
                "uaa.none",
                commaSeparatedRedirectUris);
        newClient.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);
        newClient.setClientSecret(generator.generate());
        clientDetailsToCreate.add(newClient);

        return this;
    }

    public ZoneSeeder withAdminClientWithClientCredentialsGrant() {
        UaaClientDetails newClient = new UaaClientDetails(ADMIN_CLIENT_CREDENTIALS_CLIENT_ID,
                "none",
                "uaa.none",
                "client_credentials",
                "uaa.admin,clients.read,clients.write,clients.secret,scim.read,scim.write,clients.admin");
        newClient.setClientSecret("adminsecret");
        clientDetailsToCreate.add(newClient);

        return this;
    }

    public ZoneSeeder withUser(ScimUser scimUser) {
        return withUserWhoBelongsToGroups(scimUser, new ArrayList<>());
    }

    public ZoneSeeder withUser(String email) {
        return withUserWhoBelongsToGroups(newScimUser(email), new ArrayList<>());
    }

    public ZoneSeeder withUserWhoBelongsToGroups(String email, List<String> belongsToGroupNames) {
        return withUserWhoBelongsToGroups(newScimUser(email), belongsToGroupNames);
    }

    private ZoneSeeder withUserWhoBelongsToGroups(ScimUser scimUser, List<String> belongsToGroupNames) {
        usersInGroupsToCreate.put(scimUser, belongsToGroupNames);
        return this;
    }

    private ScimUser newScimUser(String email) {
        ScimUser scimUser = new ScimUser(null, email, generator.generate(), generator.generate());
        scimUser.addEmail(email);
        scimUser.setPassword(generator.generate());
        return scimUser;
    }

    public ScimUser newRandomScimUser() {
        String email = generator.generate() + "@" + generator.generate() + ".org";
        return newScimUser(email);
    }

    public String getAdminScope() {
        return "zones." + this.getIdentityZoneId() + ".admin";
    }

    public interface AfterSeedCallback {
        void afterSeed(ZoneSeeder zoneSeeder) throws Exception;
    }

    public ZoneSeeder afterSeeding(AfterSeedCallback callback) {
        afterSeedCallbacks.add(callback);
        return this;
    }

    ZoneSeeder seed() throws Exception {
        if (alreadySeeded) {
            return this;
        }
        alreadySeeded = true;

        String zoneId = generator.generate();

        // Make the zone
        IdentityZone identityZoneToCreate = IdentityZone.getUaa();
        identityZoneToCreate.setSubdomain(generator.generate());
        identityZoneToCreate.setId(zoneId);
        this.identityZone = jdbcIdentityZoneProvisioning.create(identityZoneToCreate);

        // Make the IDP
        identityProviderToCreate.setIdentityZoneId(zoneId);
        uaaIdentityProviderDefinitionToCreate.setDisableInternalUserManagement(disableInternalUserManagement);
        identityProvider = jdbcIdentityProviderProvisioning.create(identityProviderToCreate, zoneId);
        identityProviderToCreate = null;
        uaaIdentityProviderDefinitionToCreate = null;

        // Make the clients
        for (ClientDetails clientDetails : clientDetailsToCreate) {
            plainTextClientSecretsForClients.put(clientDetails.getClientId(), clientDetails.getClientSecret());
            this.clientDetails.put(clientDetails.getClientId(), jdbcClientDetailsService.create(clientDetails, zoneId));
        }
        clientDetailsToCreate.clear();

        // Make the users
        for (Map.Entry<ScimUser, List<String>> entry : usersInGroupsToCreate.entrySet()) {
            ScimUser createdUser = provisionScimUser(entry.getKey());
            for (String groupName : entry.getValue()) {
                provisionGroupMembership(createdUser, groupName);
            }
            ScimUser refreshedUser = jdbcScimUserProvisioning.retrieve(createdUser.getId(), getIdentityZoneId());
            users.put(refreshedUser.getId(), refreshedUser);
        }
        usersInGroupsToCreate.clear();

        for (AfterSeedCallback callback : afterSeedCallbacks) {
            callback.afterSeed(this);
        }

        return this;
    }

    void destroy() {
        UaaPrincipal justEnoughPrincipal = new UaaPrincipal(
                "id", "name", "", identityProvider.getOriginKey(), "external id", identityZone.getId()
        );
        UaaAuthentication justEnoughAuthentication = new UaaAuthentication(
                justEnoughPrincipal, Lists.newArrayList(), null
        );
        applicationContext.publishEvent(new EntityDeletedEvent<>(identityZone, justEnoughAuthentication, IdentityZoneHolder.getCurrentZoneId()));
    }

    public ScimUser createUser() {
        String email = generator.generate().toLowerCase() + "@" + generator.generate().toLowerCase() + ".com";
        return provisionScimUser(newScimUser(email));
    }

    public ScimUser getUserByEmail(String email) {
        return users.entrySet().stream()
                .filter(entry -> entry.getValue().getPrimaryEmail().equals(email))
                .findFirst().get().getValue();
    }

    public ClientDetails getClientById(String clientId) {
        return clientDetails.entrySet().stream()
                .filter(entry -> entry.getKey().equals(clientId))
                .findFirst()
                .get().getValue();
    }

    public String getPlainTextPassword(ScimUser user) {
        return plainTextPasswordsForUsers.get(user.getId());
    }

    public String getPlainTextClientSecret(ClientDetails clientDetails) {
        return plainTextClientSecretsForClients.get(clientDetails.getClientId());
    }

    public String getIdentityZoneId() {
        return identityZone.getId();
    }

    public String getIdentityZoneSubdomain() {
        return identityZone.getSubdomain();
    }

    public HttpHeaders getZoneSubdomainRequestHeader() {
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

    public ClientDetails getClientWithImplicitPasswordRefreshTokenGrants() {
        return clientDetails.get(IMPLICIT_PASSWORD_REFRESH_TOKEN_CLIENT_ID);
    }

    public ClientDetails getAdminClientWithClientCredentialsGrant() {
        return clientDetails.get(ADMIN_CLIENT_CREDENTIALS_CLIENT_ID);
    }

    private void provisionGroupMembership(ScimUser scimUser, String groupName) {
        ScimGroup group = jdbcScimGroupProvisioning.getByName(groupName, getIdentityZoneId());

        String originalZoneId = IdentityZoneHolder.get().getId();
        IdentityZoneHolder.get().setId(getIdentityZoneId()); // jdbcScimGroupMembershipManager#addMember needs this to be set :(

        jdbcScimGroupMembershipManager.addMember(
                group.getId(), new ScimGroupMember(scimUser.getId()), getIdentityZoneId()
        );

        IdentityZoneHolder.get().setId(originalZoneId);
    }

    private ScimUser provisionScimUser(ScimUser scimUser) {
        String password = scimUser.getPassword();
        ScimUser createdUser = jdbcScimUserProvisioning.createUser(scimUser, password, getIdentityZoneId());
        plainTextPasswordsForUsers.put(createdUser.getId(), password);
        users.put(createdUser.getId(), createdUser);
        return createdUser;
    }
}
