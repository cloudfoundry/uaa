package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.apache.commons.lang3.tuple.Triple;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ScimUserBootstrapTests {

    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;
    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;
    private ScimUserEndpoints scimUserEndpoints;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;
    private ScimUserService scimUserService;
    private JdbcIdentityZoneProvisioning identityZoneProvisioning;
    private IdentityZoneManager identityZoneManager;
    private IdentityProviderProvisioning idpProvisioning;

    @BeforeEach
    void init() throws SQLException {
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter());
        identityZoneManager = new IdentityZoneManagerImpl();
        identityZoneProvisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        jdbcScimUserProvisioning = spy(new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder,
                identityZoneManager, identityZoneProvisioning, new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(), true));
        DbUtils dbUtils = new DbUtils();
        jdbcScimGroupProvisioning = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);
        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(
                identityZoneManager, jdbcTemplate, new TimeServiceImpl(), jdbcScimUserProvisioning, null, dbUtils);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(jdbcScimGroupProvisioning);
        idpProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        final ScimUserAliasHandler scimUserAliasHandler = new ScimUserAliasHandler(
                identityZoneProvisioning,
                jdbcScimUserProvisioning,
                idpProvisioning,
                identityZoneManager,
                false
        );
        scimUserService = new ScimUserService(
                scimUserAliasHandler,
                jdbcScimUserProvisioning,
                identityZoneManager,
                null, // not required since alias is disabled
                false
        );
        scimUserEndpoints = new ScimUserEndpoints(
                identityZoneManager,
                new IsSelfCheck(null),
                jdbcScimUserProvisioning,
                null,
                null,
                null,
                null,
                null,
                null,
                jdbcScimGroupMembershipManager,
                scimUserService,
                null,
                null,
                false,
                5
        );
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());
    }

    @AfterEach
    void tearDown() throws SQLException {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) throws SQLException {
        TestUtils.restoreToDefaults(applicationContext);
    }

    @Test
    void canDeleteUsersButOnlyInDefaultZone() {
        String randomZoneId = "randomZoneId-" + new RandomValueStringGenerator().generate().toLowerCase();
        canAddUsers(OriginKeys.UAA, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager, scimUserService);
        canAddUsers(OriginKeys.LDAP, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager, scimUserService);
        //this is just an update of the same two users, zoneId is ignored
        canAddUsers(OriginKeys.UAA, randomZoneId, jdbcScimUserProvisioning, jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager, scimUserService);
        List<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(4);
        reset(jdbcScimUserProvisioning);
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        doAnswer(invocation -> {
            EntityDeletedEvent event = invocation.getArgument(0);
            jdbcScimUserProvisioning.deleteByUser(event.getObjectId(), IdentityZone.getUaaZoneId());
            return null;
        })
                .when(publisher).publishEvent(any(EntityDeletedEvent.class));

        List<String> usersToDelete = Arrays.asList("joe", "mabel", "non-existent");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, emptyList(), false, usersToDelete, false);
        bootstrap.setApplicationEventPublisher(publisher);
        bootstrap.afterPropertiesSet();
        bootstrap.onApplicationEvent(mock(ContextRefreshedEvent.class));
        ArgumentCaptor<ApplicationEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(publisher, times(2)).publishEvent(captor.capture());
        List<EntityDeletedEvent<ScimUser>> deleted = new LinkedList(ofNullable(captor.getAllValues()).orElse(emptyList()));
        assertThat(deleted)
                .isNotNull()
                .hasSize(2);
        deleted.forEach(event -> assertThat(event.getDeleted().getOrigin()).isEqualTo(OriginKeys.UAA));
        assertThat(jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(2);
    }

    @Test
    void slatedForDeleteDoesNotAdd() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        UaaUser mabel = new UaaUser("mabel", "password", "mabel@blah.com", "Mabel", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Arrays.asList(joe, mabel), false, Arrays.asList("joe", "mabel"), false);
        bootstrap.afterPropertiesSet();
        String zoneId = IdentityZone.getUaaZoneId();
        verify(jdbcScimUserProvisioning, never()).create(any(), eq(zoneId));
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(zoneId);
        assertThat(users).isEmpty();
    }

    @Test
    void canAddUsers() {
        canAddUsers(OriginKeys.UAA, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, scimUserService);
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(2);
    }

    @Test
    void addedUsersAreVerified() {
        UaaUser uaaJoe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(uaaJoe), false, Collections.emptyList(), false);

        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());

        ScimUser scimJoe = users.getFirst();
        assertThat(scimJoe.isVerified()).isTrue();
    }

    @Test
    void canAddUserWithAuthorities() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertThat(users).hasSize(1);

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertThat(user.getGroups()).hasSize(3);
    }

    @Test
    void cannotAddUserWithNoPassword() {
        UaaUser joe = new UaaUser("joe", "", "joe@test.org", "Joe", "User", OriginKeys.UAA, null);
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        assertThatExceptionOfType(InvalidPasswordException.class).isThrownBy(bootstrap::afterPropertiesSet);
    }

    @Test
    void noOverrideByDefault() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "password", "joe@test.org", "Joel", "User");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertThat(users).hasSize(1);

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertThat(user.getGivenName()).isEqualTo("Joe");
    }

    @Test
    void canOverride() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "password", "joe@test.org", "Joel", "User");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), true, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertThat(users).hasSize(1);

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertThat(user.getGivenName()).isEqualTo("Joel");
    }

    @Test
    void canOverrideAuthorities() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read,write"));
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), true, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertThat(users).hasSize(1);

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertThat(user.getGroups()).hasSize(4);
    }

    @Test
    void canRemoveAuthorities() {
        RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator();
        String joeUserId = "joe" + randomValueStringGenerator.generate();
        UaaUser joe = new UaaUser(joeUserId, "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid"));
        System.err.println(jdbcTemplate.queryForList("SELECT * FROM group_membership"));
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), true, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + joeUserId + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);

        ScimUser user = scimUserEndpoints.getUser(users.getFirst().getId(), new MockHttpServletResponse());
        // uaa.user is always added
        assertThat(user.getGroups()).hasSize(2);
    }

    @Test
    void canUpdateUsers() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        String passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0]);

        joe = new UaaUser("joe", "new", "joe@test.org", "Joe", "Bloggs");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), true, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        assertThat(users.iterator().next().getFamilyName()).isEqualTo("Bloggs");
        assertThat(jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0])).isNotEqualTo(passwordHash);

        passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0]);
        bootstrap.afterPropertiesSet();
        assertThat(jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0])).isEqualTo(passwordHash);
    }

    @Test
    void shouldPropagateAliasPropertiesOfExistingUserDuringUpdate() {
        // arrange custom zone exists
        final String customZoneId = new AlphanumericRandomValueStringGenerator(8).generate();
        createCustomZone(customZoneId);

        // create a user with alias
        final String originKey = new AlphanumericRandomValueStringGenerator(8).generate();
        final String userName = "john.doe-" + new AlphanumericRandomValueStringGenerator(8).generate();
        final String givenName = "John";
        final String familyName = "Doe";
        final String emailAddress = "john.doe@example.com";
        final Triple<String, String, ScimUser> userIdsAndOriginalUser = createUserWithAlias(customZoneId, originKey,
                emailAddress, userName, givenName, familyName);
        final String originalUserId = userIdsAndOriginalUser.getLeft();
        final String aliasUserId = userIdsAndOriginalUser.getMiddle();

        // create and emit event that contains the user with changed fields
        final String externalId = new AlphanumericRandomValueStringGenerator(8).generate();
        final String phoneNumber = "12345";
        final UaaUserPrototype userPrototype = new UaaUserPrototype()
                .withVerified(true)
                .withUsername(userName)
                .withPassword("")
                .withEmail(emailAddress)
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withCreated(new Date())
                .withModified(new Date())
                .withOrigin(originKey)
                .withExternalId(externalId) // changed field
                .withZoneId(IdentityZone.getUaaZoneId())
                .withPhoneNumber(phoneNumber); // changed field
        final UaaUser uaaUser = new UaaUser(userPrototype);

        final ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(uaaUser, true, Collections.emptyList(), true);
        final ScimUserBootstrap bootstrap = buildScimUserBootstrapWithAliasEnabled();
        bootstrap.onApplicationEvent(event);

        // should update both users and the alias reference should stay intact
        final ScimUser originalUserAfterEvent = jdbcScimUserProvisioning.retrieve(originalUserId, IdentityZone.getUaaZoneId());
        assertThat(originalUserAfterEvent.getAliasId()).isEqualTo(aliasUserId);
        assertThat(originalUserAfterEvent.getAliasZid()).isEqualTo(customZoneId);
        assertThat(originalUserAfterEvent.getExternalId()).isEqualTo(externalId);
        assertThat(originalUserAfterEvent.getPhoneNumbers().getFirst().getValue()).isEqualTo(phoneNumber);

        final ScimUser aliasUserAfterEvent = jdbcScimUserProvisioning.retrieve(aliasUserId, customZoneId);
        assertThat(aliasUserAfterEvent.getAliasId()).isEqualTo(originalUserId);
        assertThat(aliasUserAfterEvent.getAliasZid()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(aliasUserAfterEvent.getExternalId()).isEqualTo(externalId);
        assertThat(aliasUserAfterEvent.getPhoneNumbers().getFirst().getValue()).isEqualTo(phoneNumber);
    }

    @Test
    void shouldOnlyUpdateOriginalUser_WhenUserHasAliasButAliasEntitiesDisabled() {
        // arrange custom zone exists
        final String customZoneId = new AlphanumericRandomValueStringGenerator(8).generate();
        createCustomZone(customZoneId);

        // create a user with alias
        final String originKey = new AlphanumericRandomValueStringGenerator(8).generate();
        final String userName = "john.doe-" + new AlphanumericRandomValueStringGenerator(8).generate();
        final String givenName = "John";
        final String familyName = "Doe";
        final String emailAddress = "john.doe@example.com";
        final Triple<String, String, ScimUser> userIdsAndOriginalUser = createUserWithAlias(customZoneId, originKey,
                emailAddress, userName, givenName, familyName);
        final String originalUserId = userIdsAndOriginalUser.getLeft();
        final String aliasUserId = userIdsAndOriginalUser.getMiddle();
        final ScimUser originalUser = userIdsAndOriginalUser.getRight();

        // create and emit event that contains the user with changed fields
        final String externalId = new AlphanumericRandomValueStringGenerator(8).generate();
        final String phoneNumber = "12345";
        final UaaUserPrototype userPrototype = new UaaUserPrototype()
                .withVerified(true)
                .withUsername(userName)
                .withPassword("")
                .withEmail(emailAddress)
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withCreated(new Date())
                .withModified(new Date())
                .withOrigin(originKey)
                .withExternalId(externalId) // changed field
                .withZoneId(IdentityZone.getUaaZoneId())
                .withPhoneNumber(phoneNumber); // changed field
        final UaaUser uaaUser = new UaaUser(userPrototype);

        final ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(uaaUser, true, Collections.emptyList(), true);
        final ScimUserBootstrap bootstrapAliasDisabled = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                scimUserService,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                identityZoneManager,
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                false
        );
        bootstrapAliasDisabled.onApplicationEvent(event);

        // should only update the original user and the alias reference should stay intact
        final ScimUser originalUserAfterEvent = jdbcScimUserProvisioning.retrieve(originalUserId, IdentityZone.getUaaZoneId());
        assertThat(originalUserAfterEvent.getAliasId()).isEqualTo(aliasUserId);
        assertThat(originalUserAfterEvent.getAliasZid()).isEqualTo(customZoneId);
        assertThat(originalUserAfterEvent.getExternalId()).isEqualTo(externalId);
        assertThat(originalUserAfterEvent.getPhoneNumbers().getFirst().getValue()).isEqualTo(phoneNumber);

        assertThat(originalUserAfterEvent.getExternalId()).isNotEqualTo(originalUser.getExternalId());
        assertThat(originalUserAfterEvent.getPhoneNumbers()).isNotEqualTo(originalUser.getPhoneNumbers());

        final ScimUser aliasUserAfterEvent = jdbcScimUserProvisioning.retrieve(aliasUserId, customZoneId);
        assertThat(aliasUserAfterEvent.getAliasId()).isEqualTo(originalUserId);
        assertThat(aliasUserAfterEvent.getAliasZid()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(aliasUserAfterEvent.getExternalId()).isEqualTo(originalUser.getExternalId()); // should be left unchanged
        assertThat(aliasUserAfterEvent.getPhoneNumbers()).isEqualTo(originalUser.getPhoneNumbers()); // should be left unchanged
    }

    private void createCustomZone(final String customZoneId) {
        final IdentityZone customZone = new IdentityZone();
        customZone.setId(customZoneId);
        customZone.setSubdomain(customZoneId);
        customZone.setName(customZoneId);
        identityZoneProvisioning.create(customZone);
    }

    /**
     * @return a triple of the original user's ID, the alias user's ID and the original user
     */
    private Triple<String, String, ScimUser> createUserWithAlias(
            final String customZoneId,
            final String originKey,
            final String emailAddress,
            final String userName,
            final String givenName,
            final String familyName
    ) {
        // arrange that a user with alias exists
        final ScimUser scimUser = new ScimUser(null, userName, givenName, familyName);
        final ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(emailAddress);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setOrigin(originKey);
        scimUser.setZoneId(IdentityZone.getUaaZoneId());
        final ScimUser createdOriginalUser = jdbcScimUserProvisioning.createUser(scimUser, "", IdentityZone.getUaaZoneId());
        final String originalUserId = createdOriginalUser.getId();
        assertThat(StringUtils.hasText(originalUserId)).isTrue();

        // create an alias of the user in the custom zone
        createdOriginalUser.setId(null);
        createdOriginalUser.setZoneId(customZoneId);
        createdOriginalUser.setAliasId(originalUserId);
        createdOriginalUser.setAliasZid(IdentityZone.getUaaZoneId());
        final ScimUser createdAliasUser = jdbcScimUserProvisioning.createUser(createdOriginalUser, "", customZoneId);
        final String aliasUserId = createdAliasUser.getId();
        assertThat(StringUtils.hasText(aliasUserId)).isTrue();

        // update the original user to point ot the alias user
        createdOriginalUser.setId(originalUserId);
        createdOriginalUser.setZoneId(IdentityZone.getUaaZoneId());
        createdOriginalUser.setAliasId(aliasUserId);
        createdOriginalUser.setAliasZid(customZoneId);
        final ScimUser originalUser = jdbcScimUserProvisioning.update(originalUserId, createdOriginalUser, IdentityZone.getUaaZoneId());

        return Triple.of(originalUserId, aliasUserId, originalUser);
    }

    private ScimUserBootstrap buildScimUserBootstrapWithAliasEnabled() {
        final ScimUserService scimUserServiceAliasEnabled = buildScimUserServiceAliasEnabled();
        return new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                scimUserServiceAliasEnabled,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                identityZoneManager,
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                true
        );
    }

    private ScimUserService buildScimUserServiceAliasEnabled() {
        final ScimUserAliasHandler aliasHandlerAliasEnabled = buildScimUserAliasHandlerAliasEnabled();
        final TransactionTemplate txTemplate = mock(TransactionTemplate.class);
        when(txTemplate.execute(any())).then(invocationOnMock -> {
            final TransactionCallback<?> action = invocationOnMock.getArgument(0);
            return action.doInTransaction(mock(TransactionStatus.class));
        });
        return new ScimUserService(
                aliasHandlerAliasEnabled,
                jdbcScimUserProvisioning,
                identityZoneManager,
                txTemplate,
                true
        );
    }

    private ScimUserAliasHandler buildScimUserAliasHandlerAliasEnabled() {
        return new ScimUserAliasHandler(
                identityZoneProvisioning,
                jdbcScimUserProvisioning,
                idpProvisioning,
                identityZoneManager,
                true
        );
    }

    @Test
    void unsuccessfulAttemptToUpdateUsersNotFatal() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "new", "joe@test.org", "Joe", "Bloggs");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        assertThat(users.iterator().next().getFamilyName()).isEqualTo("User");
    }

    @Test
    void updateUserWithEmptyPasswordDoesNotChangePassword() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        String passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0]);

        joe = new UaaUser("joe", "", "joe@test.org", "Joe", "Bloggs");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(joe), true, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        assertThat(users.iterator().next().getFamilyName()).isEqualTo("Bloggs");
        assertThat(jdbcTemplate.queryForObject("select password from users where username='joe'", String.class, new Object[0])).isEqualTo(passwordHash);
    }

    @Test
    void uaaUserGetsVerifiedSetToTrue() {
        String origin = OriginKeys.UAA;
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;

        String username = new RandomValueStringGenerator().generate().toLowerCase();
        UaaUser user = getUaaUser(new String[0], origin, email, firstName, lastName, password, externalId, "not-used-id", username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        ScimUser existingUser = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId())
                .stream()
                .filter(u -> username.equals(u.getUserName()))
                .findFirst()
                .get();
        String userId = existingUser.getId();
        existingUser.setVerified(false);
        jdbcScimUserProvisioning.update(userId, existingUser, IdentityZone.getUaaZoneId());
        InvitedUserAuthenticatedEvent event = new InvitedUserAuthenticatedEvent(user);

        bootstrap.onApplicationEvent(event);

        ScimUser modifiedUser = jdbcScimUserProvisioning.retrieve(userId, IdentityZone.getUaaZoneId());

        assertThat(modifiedUser.isVerified()).isTrue();
    }

    @Test
    void externalInvitedUserGetsVerifiedSetToFalse() {
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;

        String username = new RandomValueStringGenerator().generate().toLowerCase();
        UaaUser user = getUaaUser(new String[0], origin, email, firstName, lastName, password, externalId, "not-used-id", username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        ScimUser existingUser = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId())
                .stream()
                .filter(u -> username.equals(u.getUserName()))
                .findFirst()
                .get();
        String userId = existingUser.getId();
        existingUser.setVerified(true);
        jdbcScimUserProvisioning.update(userId, existingUser, IdentityZone.getUaaZoneId());
        InvitedUserAuthenticatedEvent event = new InvitedUserAuthenticatedEvent(user);

        bootstrap.onApplicationEvent(event);

        ScimUser modifiedUser = jdbcScimUserProvisioning.retrieve(userId, IdentityZone.getUaaZoneId());

        assertThat(modifiedUser.isVerified()).isFalse();
    }

    @Test
    void canAddNonExistentGroupThroughEvent() {
        nonExistentGroupThroughEvent(true, jdbcTemplate, jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, scimUserService);
    }

    @Test
    void doNotAddNonExistentUsers() {
        nonExistentGroupThroughEvent(false, jdbcTemplate, jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, scimUserService);
    }

    @Test
    void addNonExistentGroupWithQuote() {
        String[] externalAuthorities = new String[]{"\"extTest1", "extTest2\"", "\"extTest3\""};
        String[] userAuthorities = new String[]{};
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(new String[] {}, origin, email, firstName, lastName, password, externalId, userId, username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                scimUserService,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                new IdentityZoneManagerImpl(),
                Collections.singletonList(user),
                false,
                Collections.emptyList(),
                false
        );
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        userId = users.getFirst().getId();

        user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), true));

        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        ScimUser created = users.getFirst();
        validateAuthoritiesCreated(externalAuthorities, userAuthorities, origin, created, jdbcScimGroupMembershipManager);
    }

    @Test
    void canUpdateEmailThroughEvent() {
        String[] externalAuthorities = new String[]{"extTest1", "extTest2", "extTest3"};
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String newEmail = "test@test2.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(externalAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        userId = users.getFirst().getId();
        user = getUaaUser(externalAuthorities, origin, newEmail, firstName, lastName, password, externalId, userId, username);

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        ScimUser created = users.getFirst();
        assertThat(created.getPrimaryEmail()).isEqualTo(newEmail);

        user = user.modifyEmail("test123@test.org");
        //Ensure email doesn't get updated if event instructs not to update.
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        created = users.getFirst();
        assertThat(created.getPrimaryEmail()).isEqualTo(newEmail);

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        created = users.getFirst();
        assertThat(created.getPrimaryEmail()).isEqualTo("test123@test.org");
    }

    @Test
    void groupsFromEventAreMadeUnique() {
        String[] externalAuthorities = new String[]{"extTest1", "extTest2", "extTest3"};
        String[] userAuthorities = new String[]{"usrTest1", "usrTest2", "usrTest3"};
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String newEmail = "test@test2.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        JdbcScimGroupMembershipManager spy = spy(jdbcScimGroupMembershipManager);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, spy, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        userId = users.getFirst().getId();
        user = getUaaUser(userAuthorities, origin, newEmail, firstName, lastName, password, externalId, userId, username);

        List<GrantedAuthority> authorities = getAuthorities(externalAuthorities);
        authorities.addAll(getAuthorities(externalAuthorities));
        assertThat(authorities).hasSize(2 * externalAuthorities.length);
        verify(spy, times(externalAuthorities.length)).addMember(any(), any(), any());

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, authorities, true));

        verify(spy, times(externalAuthorities.length * 2)).addMember(any(), any(), any());
    }

    @Test
    void addUsersWithSameUsername() {
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(new String[0], origin, email, firstName, lastName, password, externalId, userId, username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        addIdentityProvider(jdbcTemplate, "newOrigin");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Arrays.asList(user, user.modifySource("newOrigin", "")), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();
        assertThat(jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId())).hasSize(2);
    }

    @Test
    void concurrentAuthEventsRaceCondition() throws Exception {
        int numthreads = 5;
        int numgroups = 100;

        String[] externalAuthorities = new String[]{"extTest1", "extTest2", "extTest3"};
        String[] userAuthorities = new String[]{"usrTest1", "usrTest2", "usrTest3"};
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, scimUserService, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, identityZoneManager, Collections.singletonList(user), false, Collections.emptyList(), false);
        bootstrap.afterPropertiesSet();

        List<ScimUser> scimUsers = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(scimUsers).hasSize(1);
        ScimUser scimUser = scimUsers.getFirst();
        ScimGroupMember member = new ScimGroupMember<>(scimUser);
        user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, member.getMemberId(), username);
        for (int i = 0; i < numgroups; i++) {
            jdbcScimGroupProvisioning.create(new ScimGroup("group" + i, "group" + i, IdentityZone.getUaaZoneId()), IdentityZone.getUaaZoneId());
            String gid = jdbcScimGroupProvisioning.query("displayName eq \"group" + i + "\"", IdentityZone.getUaaZoneId()).getFirst().getId();
            jdbcScimGroupMembershipManager.addMember(gid, member, IdentityZone.getUaaZoneId());
        }

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, getAuthorities(externalAuthorities), true));

        ExternalGroupAuthorizationEvent externalGroupAuthorizationEvent = new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), true);

        Thread[] threads = new Thread[numthreads];
        for (int i = 0; i < numthreads; i++) {
            threads[i] = new Thread(new AuthEventRunnable(externalGroupAuthorizationEvent, bootstrap));
            threads[i].start();
        }
        for (int i = 0; i < numthreads; i++) {
            threads[i].join();
        }
        if (AuthEventRunnable.failure != null) {
            throw AuthEventRunnable.failure;
        }
    }

    private static void addIdentityProvider(JdbcTemplate jdbcTemplate, String originKey) {
        jdbcTemplate.update("insert into identity_provider (id,identity_zone_id,name,origin_key,type) values (?,'uaa',?,?,'UNKNOWN')", UUID.randomUUID().toString(), originKey, originKey);
    }

    private static void canAddUsers(
            String origin,
            String zoneId,
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            JdbcScimGroupProvisioning jdbcScimGroupProvisioning,
            JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            ScimUserService scimUserService
    ) {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User", origin, zoneId);
        UaaUser mabel = new UaaUser("mabel", "password", "mabel@blah.com", "Mabel", "User", origin, zoneId);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                scimUserService,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                new IdentityZoneManagerImpl(),
                Arrays.asList(joe, mabel),
                false,
                Collections.emptyList(),
                false
        );
        bootstrap.afterPropertiesSet();
    }

    private static void nonExistentGroupThroughEvent(
            final boolean add,
            final JdbcTemplate jdbcTemplate,
            final JdbcScimUserProvisioning jdbcScimUserProvisioning,
            final JdbcScimGroupProvisioning jdbcScimGroupProvisioning,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            final ScimUserService scimUserService
    ) {
        String[] externalAuthorities = new String[]{"extTest1", "extTest2", "extTest3"};
        String[] userAuthorities = new String[]{"usrTest1", "usrTest2", "usrTest3"};
        String origin = "testOrigin";
        addIdentityProvider(jdbcTemplate, origin);
        String email = "test@test.org";
        String firstName = "FirstName";
        String lastName = "LastName";
        String password = "testPassword";
        String externalId = null;
        String userId = new RandomValueStringGenerator().generate();
        String username = new RandomValueStringGenerator().generate();
        UaaUser user = getUaaUser(new String[]{}, origin, email, firstName, lastName, password, externalId, userId, username);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                scimUserService,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                new IdentityZoneManagerImpl(),
                Collections.singletonList(user),
                false,
                Collections.emptyList(),
                false
        );
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        userId = users.getFirst().getId();

        // add all the user authorities on the uaa origin
        for (String userAuthority : userAuthorities) {
            ScimGroup group = new ScimGroup(null, userAuthority, IdentityZoneHolder.get().getId());
            group = jdbcScimGroupProvisioning.createOrGet(group, IdentityZoneHolder.get().getId());
            ScimGroupMember groupMember = new ScimGroupMember(userId);
            groupMember.setOrigin(OriginKeys.UAA);
            jdbcScimGroupMembershipManager.addMember(group.getId(), groupMember, IdentityZoneHolder.get().getId());
        }

        ScimUser created = users.getFirst();
        validateAuthoritiesCreated(new String[0], userAuthorities, origin, created, jdbcScimGroupMembershipManager);

        user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), add));

        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertThat(users).hasSize(1);
        created = users.getFirst();
        validateAuthoritiesCreated(add ? externalAuthorities : new String[0], userAuthorities, origin, created, jdbcScimGroupMembershipManager);

        externalAuthorities = new String[]{"extTest1", "extTest2"};
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), add));
        validateAuthoritiesCreated(add ? externalAuthorities : new String[0], userAuthorities, origin, created, jdbcScimGroupMembershipManager);
    }

    private static void validateAuthoritiesCreated(
            final String[] externalAuthorities,
            final String[] userAuthorities,
            final String origin,
            final ScimUser created,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager) {
        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember(created.getId(), true, IdentityZone.getUaaZoneId());
        String[] expected = merge(externalAuthorities, userAuthorities);
        String[] actual = getGroupNames(groups);
        assertThat(actual).containsExactlyInAnyOrder(expected);

        List<String> external = Arrays.asList(externalAuthorities);
        for (ScimGroup g : groups) {
            ScimGroupMember m = jdbcScimGroupMembershipManager.getMemberById(g.getId(), created.getId(), IdentityZone.getUaaZoneId());
            if (external.contains(g.getDisplayName())) {
                assertThat(m.getOrigin()).as("Expecting relationship for Group[" + g.getDisplayName() + "] be of different origin.").isEqualTo(origin);
            } else {
                assertThat(m.getOrigin()).as("Expecting relationship for Group[" + g.getDisplayName() + "] be of different origin.").isEqualTo(OriginKeys.UAA);
            }
        }
    }

    private static UaaUser getUaaUser(
            String[] userAuthorities,
            String origin,
            String email,
            String firstName,
            String lastName,
            String password,
            String externalId,
            String userId,
            String username) {
        return new UaaUser(
                userId,
                username,
                password,
                email,
                getAuthorities(userAuthorities),
                firstName,
                lastName,
                new Date(),
                new Date(),
                origin,
                externalId,
                false,
                IdentityZone.getUaaZoneId(),
                userId,
                new Date()
        );
    }

    private static class AuthEventRunnable implements Runnable {

        static volatile AssertionError failure;
        private final int iterations = 50;

        private final ExternalGroupAuthorizationEvent externalGroupAuthorizationEvent;
        private final ScimUserBootstrap bootstrap;

        AuthEventRunnable(ExternalGroupAuthorizationEvent externalGroupAuthorizationEvent, ScimUserBootstrap bootstrap) {
            this.externalGroupAuthorizationEvent = externalGroupAuthorizationEvent;
            this.bootstrap = bootstrap;
        }

        @Override
        public void run() {
            for (int i = 0; i < iterations; i++) {
                if (failure != null) {
                    break;
                }
                try {
                    bootstrap.onApplicationEvent(externalGroupAuthorizationEvent);
                } catch (MemberNotFoundException e) {
                    if (failure == null) {
                        failure = new AssertionError("MemberNotFoundException in Test thread", e);
                        break;
                    }
                } catch (Exception e) {
                    failure = new AssertionError("Exception in Test thread", e);
                }
            }
        }
    }

    private static List<GrantedAuthority> getAuthorities(String[] auth) {
        ArrayList<GrantedAuthority> result = new ArrayList<>();
        for (String s : auth) {
            result.add(new SimpleGrantedAuthority(s));
        }
        return result;
    }

    private static String[] merge(String[] a, String[] b) {
        String[] result = new String[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static String[] getGroupNames(Set<ScimGroup> groups) {
        String[] result = new String[groups != null ? groups.size() : 0];
        if (result.length == 0) {
            return result;
        }
        int index = 0;
        for (ScimGroup group : groups) {
            result[index++] = group.getDisplayName();
        }
        return result;
    }

}
