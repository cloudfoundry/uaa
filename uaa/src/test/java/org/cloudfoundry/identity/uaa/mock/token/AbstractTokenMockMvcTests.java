package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.TestSpringContext;
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
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createMfaProvider;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.junit.Assert.assertNull;
import static org.springframework.util.StringUtils.hasText;

@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public abstract class AbstractTokenMockMvcTests {

    public static final String SECRET = "secret";
    static final String GRANT_TYPES = "password,implicit,client_credentials,authorization_code,refresh_token";
    protected static final String TEST_REDIRECT_URI = "http://test.example.org/redirect";

    @Autowired
    protected WebApplicationContext webApplicationContext;
    @Autowired
    @Qualifier("jdbcClientDetailsService")
    ClientServicesExtension clientDetailsService;
    @Autowired
    @Qualifier("scimGroupProvisioning")
    JdbcScimGroupProvisioning groupProvisioning;
    @Autowired
    JdbcScimGroupMembershipManager groupMembershipManager;
    @Autowired
    UaaTokenServices tokenServices;
    @Autowired
    IdentityZoneProvisioning identityZoneProvisioning;
    @Autowired
    protected JdbcScimUserProvisioning jdbcScimUserProvisioning;
    @Autowired
    protected IdentityProviderProvisioning identityProviderProvisioning;
    @Autowired
    JdbcRevocableTokenProvisioning revocableTokenProvisioning;

    Set<String> defaultAuthorities;
    protected String adminToken;
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();

    IdentityZone zone;
    private UaaUserDatabase userDb;
    protected MfaProvider mfaProvider;
    private IdentityZoneConfiguration uaaZoneConfig;
    private UserGoogleMfaCredentialsProvisioning authenticator;
    protected UserGoogleMfaCredentials credentials;

    protected MockMvc mockMvc;
    protected TestClient testClient;

    @BeforeEach
    public void setUpContext() throws Exception {
        defaultAuthorities = (Set<String>) webApplicationContext.getBean("defaultUserAuthorities");

        IdentityZoneHolder.clear();

        FilterChainProxy springSecurityFilterChain =
                webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);

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
        if (uaaZoneConfig!=null) {
            uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
            MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaa().getId(), uaaZoneConfig);
            deleteMfaRegistrations();
        }
    }

    void deleteMfaRegistrations() {
        webApplicationContext.getBean(JdbcTemplate.class).update("DELETE FROM user_google_mfa_credentials");
    }

    public void setupForMfaPasswordGrant() throws Exception {
        userDb = webApplicationContext.getBean(UaaUserDatabase.class);
        String userId = userDb.retrieveUserByName("marissa", OriginKeys.UAA).getId();
        setupForMfaPasswordGrant(userId);
    }
    protected void setupForMfaPasswordGrant(String userId) throws Exception {
        userDb = webApplicationContext.getBean(UaaUserDatabase.class);
        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, IdentityZone.getUaa().getId());

        cleanup();

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "uaa.admin"
        );
        mfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());

        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaa().getId(), uaaZoneConfig);

        authenticator = webApplicationContext.getBean(UserGoogleMfaCredentialsProvisioning.class);

        credentials = authenticator.createUserCredentials(userId);
        credentials.setMfaProviderId(mfaProvider.getId());
        authenticator.saveUserCredentials(credentials);
    }

    protected String setUpUserForPasswordGrant() {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        ScimUserProvisioning provisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimUser scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
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
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity, IdentityZone zone, Map<String,Object> additionalInfo) {
        IdentityZone original = IdentityZoneHolder.get();
        if (zone!=null) {
            IdentityZoneHolder.set(zone);
        }
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        if (!GRANT_TYPE_IMPLICIT.equals(grantTypes)) {
            c.setClientSecret(SECRET);
        }
        c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(TEST_REDIRECT_URI)));
        c.setAutoApproveScopes(Collections.singleton(autoapprove.toString()));
        Map<String, Object> additional = new HashMap<>();
        if (allowedIdps!=null && !allowedIdps.isEmpty()) {
            additional.put(ClientConstants.ALLOWED_PROVIDERS, allowedIdps);
        }
        additional.putAll(additionalInfo);
        c.setAdditionalInformation(additional);
        if (hasText(redirectUri)) {
            c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUri)));
        }
        if (accessTokenValidity>0) {
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

    protected ScimUser setUpUser(String username, String scopes, String origin, String zoneId) {
        IdentityZone original = IdentityZoneHolder.get();
        ScimUser user = new ScimUser(null, username, "GivenName", "FamilyName");
        if (hasText(zoneId)) {
            IdentityZone zone = identityZoneProvisioning.retrieve(zoneId);
            IdentityZoneHolder.set(zone);
            user.setZoneId(zoneId);
        }
        try {

            user.setPassword(SECRET);
            ScimUser.Email email = new ScimUser.Email();
            email.setValue("test@test.org");
            email.setPrimary(true);
            user.setEmails(Arrays.asList(email));
            user.setVerified(true);
            user.setOrigin(origin);


            user = jdbcScimUserProvisioning.createUser(user, SECRET, IdentityZoneHolder.get().getId());

            Set<String> scopeSet = StringUtils.commaDelimitedListToSet(scopes);
            Set<ScimGroup> groups = new HashSet<>();
            for (String scope : scopeSet) {
                ScimGroup g = createIfNotExist(scope, zoneId);
                groups.add(g);
                addMember(user, g);
            }

            return jdbcScimUserProvisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    protected ScimUser syncGroups(ScimUser user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroup> directGroups = groupMembershipManager.getGroupsWithMember(user.getId(), false, IdentityZoneHolder.get().getId());
        Set<ScimGroup> indirectGroups = groupMembershipManager.getGroupsWithMember(user.getId(), true, IdentityZoneHolder.get().getId());
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<ScimUser.Group>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    private ScimGroupMember addMember(ScimUser user, ScimGroup group) {
        ScimGroupMember gm = new ScimGroupMember(user.getId());
        try {
            return groupMembershipManager.addMember(group.getId(), gm, IdentityZoneHolder.get().getId());
        }catch (MemberAlreadyExistsException x) {
            return gm;
        }
    }

    private ScimGroup createIfNotExist(String scope, String zoneId) {
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \"" + scope + "\" and identity_zone_id eq \""+zoneId+"\"", IdentityZoneHolder.get().getId());
        if (exists.size() > 0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(null,scope,zoneId), IdentityZoneHolder.get().getId());
        }
    }
}
