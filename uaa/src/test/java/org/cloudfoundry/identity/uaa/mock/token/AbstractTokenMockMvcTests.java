package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentials;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createMfaProvider;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.junit.Assert.assertNull;
import static org.springframework.util.StringUtils.hasText;

@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
@DefaultTestContext
public abstract class AbstractTokenMockMvcTests {

    protected static final String SECRET = "secret";
    static final String GRANT_TYPES = "password,implicit,client_credentials,authorization_code,refresh_token";
    protected static final String TEST_REDIRECT_URI = "http://test.example.org/redirect";

    @Autowired
    protected WebApplicationContext webApplicationContext;
    @Autowired
    @Qualifier("jdbcClientDetailsService")
    protected MultitenantClientServices clientDetailsService;
    @Autowired
    @Qualifier("scimGroupProvisioning")
    protected JdbcScimGroupProvisioning jdbcScimGroupProvisioning;
    @Autowired
    protected JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;
    @Autowired
    protected UaaTokenServices tokenServices;
    @Autowired
    protected IdentityZoneProvisioning identityZoneProvisioning;
    @Autowired
    protected JdbcScimUserProvisioning jdbcScimUserProvisioning;
    @Autowired
    protected IdentityProviderProvisioning identityProviderProvisioning;
    @Autowired
    protected JdbcRevocableTokenProvisioning revocableTokenProvisioning;

    protected String adminToken;
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();

    protected IdentityZone zone;
    protected MfaProvider mfaProvider;
    private IdentityZoneConfiguration uaaZoneConfig;
    protected UserGoogleMfaCredentials credentials;

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected TestClient testClient;

    @Autowired
    protected JdbcTemplate jdbcTemplate;

    @Autowired
    protected UaaUserDatabase uaaUserDatabase;

    @Autowired
    protected UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;

    Set<String> defaultAuthorities;

    @BeforeEach
    public void setUpContext(
            @Autowired @Qualifier("defaultUserAuthorities") Object defaultAuthorities
    ) throws Exception {
        this.defaultAuthorities = new HashSet<>((LinkedHashSet) defaultAuthorities);
        IdentityZoneHolder.clear();

        adminToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        "admin",
                        "adminsecret",
                        "uaa.admin",
                        null
                );
    }

    @AfterEach
    public void cleanup() {
        if (uaaZoneConfig != null) {
            uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
            MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), uaaZoneConfig);
            deleteMfaRegistrations();
        }
    }

    void deleteMfaRegistrations() {
        jdbcTemplate.update("DELETE FROM user_google_mfa_credentials");
    }

    public void setupForMfaPasswordGrant() throws Exception {
        String userId = uaaUserDatabase.retrieveUserByName("marissa", OriginKeys.UAA).getId();
        setupForMfaPasswordGrant(userId);
    }

    protected void setupForMfaPasswordGrant(String userId) throws Exception {
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId());

        cleanup();

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "uaa.admin"
        );
        mfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());

        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), uaaZoneConfig);

        credentials = userGoogleMfaCredentialsProvisioning.createUserCredentials(userId);
        credentials.setMfaProviderId(mfaProvider.getId());
        userGoogleMfaCredentialsProvisioning.saveUserCredentials(credentials);
    }

    protected String createUserForPasswordGrant(
            final JdbcScimUserProvisioning jdbcScimUserProvisioning,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            final JdbcScimGroupProvisioning jdbcScimGroupProvisioning,
            final RandomValueStringGenerator generator) {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        ScimUser scimUser = jdbcScimUserProvisioning.retrieve(user.getId(), IdentityZone.getUaaZoneId());
        assertNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());
        return username;
    }

    IdentityZone setupIdentityZone(String subdomain) {
        return setupIdentityZone(subdomain, UserConfig.DEFAULT_ZONE_GROUPS);
    }

    IdentityZone setupIdentityZone(String subdomain, List<String> defaultUserGroups) {
        IdentityZone zone = new IdentityZone();
        zone.getConfig().getUserConfig().setDefaultGroups(defaultUserGroups);
        zone.getConfig().getTokenPolicy().setKeys(IdentityZone.getUaa().getConfig().getTokenPolicy().getKeys());
        zone.getConfig().setSamlConfig(IdentityZone.getUaa().getConfig().getSamlConfig());
        zone.setId(UUID.randomUUID().toString());
        zone.setName(subdomain);
        zone.setSubdomain(subdomain);
        zone.setDescription(subdomain);
        List<String> defaultGroups = new LinkedList(zone.getConfig().getUserConfig().getDefaultGroups());
        defaultGroups.add("cloud_controller.read");
        zone.getConfig().getUserConfig().setDefaultGroups(defaultGroups);
        identityZoneProvisioning.create(zone);
        return zone;
    }

    IdentityProvider setupIdentityProvider() {
        return setupIdentityProvider(OriginKeys.UAA);
    }

    IdentityProvider setupIdentityProvider(String origin) {
        IdentityProvider defaultIdp = new IdentityProvider();
        defaultIdp.setName(origin);
        defaultIdp.setType(origin);
        defaultIdp.setOriginKey(origin);
        defaultIdp.setIdentityZoneId(IdentityZoneHolder.get().getId());
        return identityProviderProvisioning.create(defaultIdp, defaultIdp.getIdentityZoneId());
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, null);
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, null);
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, -1);
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, accessTokenValidity, null);
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity, IdentityZone zone) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, accessTokenValidity, zone, Collections.emptyMap());
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity, IdentityZone zone, Map<String, Object> additionalInfo) {
        IdentityZone original = IdentityZoneHolder.get();
        if (zone != null) {
            IdentityZoneHolder.set(zone);
        }
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        if (!GRANT_TYPE_IMPLICIT.equals(grantTypes)) {
            c.setClientSecret(SECRET);
        }
        c.setRegisteredRedirectUri(new HashSet<>(Collections.singletonList(TEST_REDIRECT_URI)));
        c.setAutoApproveScopes(Collections.singleton(autoapprove.toString()));
        Map<String, Object> additional = new HashMap<>();
        if (allowedIdps != null && !allowedIdps.isEmpty()) {
            additional.put(ClientConstants.ALLOWED_PROVIDERS, allowedIdps);
        }
        additional.putAll(additionalInfo);
        c.setAdditionalInformation(additional);
        if (hasText(redirectUri)) {
            c.setRegisteredRedirectUri(new HashSet<>(Collections.singletonList(redirectUri)));
        }
        if (accessTokenValidity > 0) {
            c.setAccessTokenValiditySeconds(accessTokenValidity);
        }
        try {
            clientDetailsService.addClientDetails(c);
            return (BaseClientDetails) clientDetailsService.loadClientByClientId(c.getClientId());
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    void deleteClient(String clientId, String zoneId) {
        clientDetailsService.removeClientDetails(clientId, zoneId);
    }

    void deleteUser(ScimUser user, String zoneId) {
        jdbcScimUserProvisioning.delete(user.getId(), user.getVersion(), zoneId);
    }

    protected static ScimUser setUpUser(
            final JdbcScimUserProvisioning jdbcScimUserProvisioning,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            final JdbcScimGroupProvisioning jdbcScimGroupProvisioning,
            final String username,
            final String scopes,
            final String origin,
            final String zoneId) {
        ScimUser user = new ScimUser(null, username, "GivenName", "FamilyName");
        user.setZoneId(zoneId);
        user.setPassword(SECRET);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("test@test.org");
        email.setPrimary(true);
        user.setEmails(Collections.singletonList(email));
        user.setVerified(true);
        user.setOrigin(origin);

        user = jdbcScimUserProvisioning.createUser(user, SECRET, zoneId);

        Set<String> scopeSet = StringUtils.commaDelimitedListToSet(scopes);
        for (String scope : scopeSet) {
            ScimGroup g = createIfNotExist(jdbcScimGroupProvisioning, scope, zoneId);
            addMember(jdbcScimGroupMembershipManager, user, g, zoneId);
        }

        return jdbcScimUserProvisioning.retrieve(user.getId(), zoneId);
    }

    protected ScimUser syncGroups(ScimUser user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroup> directGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(user.getId(), false, IdentityZoneHolder.get().getId());
        Set<ScimGroup> indirectGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(user.getId(), true, IdentityZoneHolder.get().getId());
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    private static void addMember(
            final JdbcScimGroupMembershipManager groupMembershipManager,
            final ScimUser user,
            final ScimGroup group,
            final String zoneId) {
        ScimGroupMember gm = new ScimGroupMember(user.getId());
        try {
            groupMembershipManager.addMember(group.getId(), gm, zoneId);
        } catch (MemberAlreadyExistsException ignored) {

        }
    }

    private static ScimGroup createIfNotExist(
            final JdbcScimGroupProvisioning groupProvisioning,
            final String scope,
            final String zoneId) {
        List<ScimGroup> scimGroups = groupProvisioning.query("displayName eq \"" + scope + "\"", zoneId);
        if (!scimGroups.isEmpty()) {
            return scimGroups.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(null, scope, zoneId), zoneId);
        }
    }
}
