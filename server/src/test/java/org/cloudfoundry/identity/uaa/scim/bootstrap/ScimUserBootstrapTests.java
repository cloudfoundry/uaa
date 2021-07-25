package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.hamcrest.collection.IsArrayContainingInAnyOrder;
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
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@WithDatabaseContext
class ScimUserBootstrapTests {

    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;
    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;
    private ScimUserEndpoints scimUserEndpoints;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void init() {
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter());
        jdbcScimUserProvisioning = spy(new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, passwordEncoder));
        jdbcScimGroupProvisioning = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate, new TimeServiceImpl(), jdbcScimUserProvisioning, null);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(jdbcScimGroupProvisioning);
        scimUserEndpoints = new ScimUserEndpoints(
                new IdentityZoneManagerImpl(),
                new IsSelfCheck(null),
                jdbcScimUserProvisioning,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                jdbcScimGroupMembershipManager, 5);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());
    }

    @AfterEach
    void tearDown() {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) {
        TestUtils.restoreToDefaults(applicationContext);
    }

    @Test
    void canDeleteUsersButOnlyInDefaultZone() throws Exception {
        String randomZoneId = "randomZoneId-" + new RandomValueStringGenerator().generate().toLowerCase();
        canAddUsers(OriginKeys.UAA, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager);
        canAddUsers(OriginKeys.LDAP, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager);
        canAddUsers(OriginKeys.UAA, randomZoneId, jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager); //this is just an update of the same two users, zoneId is ignored
        List<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertEquals(4, users.size());
        reset(jdbcScimUserProvisioning);
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        doAnswer(invocation -> {
            EntityDeletedEvent event = invocation.getArgument(0);
            jdbcScimUserProvisioning.deleteByUser(event.getObjectId(), IdentityZone.getUaaZoneId());
            return null;
        })
                .when(publisher).publishEvent(any(EntityDeletedEvent.class));

        List<String> usersToDelete = Arrays.asList("joe", "mabel", "non-existent");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, emptyList(), false, usersToDelete);
        bootstrap.setApplicationEventPublisher(publisher);
        bootstrap.afterPropertiesSet();
        bootstrap.onApplicationEvent(mock(ContextRefreshedEvent.class));
        ArgumentCaptor<ApplicationEvent> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(publisher, times(2)).publishEvent(captor.capture());
        List<EntityDeletedEvent<ScimUser>> deleted = new LinkedList(ofNullable(captor.getAllValues()).orElse(emptyList()));
        assertNotNull(deleted);
        assertEquals(2, deleted.size());
        deleted.forEach(event -> assertEquals(OriginKeys.UAA, event.getDeleted().getOrigin()));
        assertEquals(2, jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId()).size());
    }

    @Test
    void slatedForDeleteDoesNotAdd() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        UaaUser mabel = new UaaUser("mabel", "password", "mabel@blah.com", "Mabel", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Arrays.asList(joe, mabel), false, Arrays.asList("joe", "mabel"));
        bootstrap.afterPropertiesSet();
        String zoneId = IdentityZone.getUaaZoneId();
        verify(jdbcScimUserProvisioning, never()).create(any(), eq(zoneId));
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(zoneId);
        assertEquals(0, users.size());
    }

    @Test
    void canAddUsers() throws Exception {
        canAddUsers(OriginKeys.UAA, IdentityZone.getUaaZoneId(), jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager);
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertEquals(2, users.size());
    }

    @Test
    void addedUsersAreVerified() {
        UaaUser uaaJoe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(uaaJoe), false, Collections.emptyList());

        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());

        ScimUser scimJoe = users.get(0);
        assertTrue(scimJoe.isVerified());
    }

    @Test
    void canAddUserWithAuthorities() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertEquals(1, users.size());

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertEquals(3, user.getGroups().size());
    }

    @Test
    void cannotAddUserWithNoPassword() {
        UaaUser joe = new UaaUser("joe", "", "joe@test.org", "Joe", "User", OriginKeys.UAA, null);
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        assertThrows(InvalidPasswordException.class, bootstrap::afterPropertiesSet);
    }

    @Test
    void noOverrideByDefault() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "password", "joe@test.org", "Joel", "User");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertEquals(1, users.size());

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertEquals("Joe", user.getGivenName());
    }

    @Test
    void canOverride() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "password", "joe@test.org", "Joel", "User");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), true, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertEquals(1, users.size());

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertEquals("Joel", user.getGivenName());
    }

    @Test
    void canOverrideAuthorities() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read,write"));
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), true, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        @SuppressWarnings("unchecked")
        Collection<Map<String, Object>> users = (Collection<Map<String, Object>>) scimUserEndpoints.findUsers("id",
                "id pr", "id", "ascending", 1, 100).getResources();
        assertEquals(1, users.size());

        String id = (String) users.iterator().next().get("id");
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        // uaa.user is always added
        assertEquals(4, user.getGroups().size());
    }

    @Test
    void canRemoveAuthorities() {
        RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator();
        String joeUserId = "joe" + randomValueStringGenerator.generate();
        UaaUser joe = new UaaUser(joeUserId, "password", "joe@test.org", "Joe", "User");
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid,read"));
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        joe = joe.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList("openid"));
        System.err.println(jdbcTemplate.queryForList("SELECT * FROM group_membership"));
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), true, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + joeUserId + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());

        ScimUser user = scimUserEndpoints.getUser(users.get(0).getId(), new MockHttpServletResponse());
        // uaa.user is always added
        assertEquals(2, user.getGroups().size());
    }

    @Test
    void canUpdateUsers() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        String passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class);

        joe = new UaaUser("joe", "new", "joe@test.org", "Joe", "Bloggs");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), true, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        assertEquals("Bloggs", users.iterator().next().getFamilyName());
        assertNotEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class));

        passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class);
        bootstrap.afterPropertiesSet();
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class));
    }

    @Test
    void unsuccessfulAttemptToUpdateUsersNotFatal() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        joe = new UaaUser("joe", "new", "joe@test.org", "Joe", "Bloggs");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        assertEquals("User", users.iterator().next().getFamilyName());
    }

    @Test
    void updateUserWithEmptyPasswordDoesNotChangePassword() {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        String passwordHash = jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class);

        joe = new UaaUser("joe", "", "joe@test.org", "Joe", "Bloggs");
        joe = joe.modifyOrigin(OriginKeys.UAA);
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(joe), true, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        Collection<ScimUser> users = jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        assertEquals("Bloggs", users.iterator().next().getFamilyName());
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where username='joe'", new Object[0], String.class));
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(user), false, Collections.emptyList());
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

        assertTrue(modifiedUser.isVerified());
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(user), false, Collections.emptyList());
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

        assertFalse(modifiedUser.isVerified());
    }

    @Test
    void canAddNonExistentGroupThroughEvent() throws Exception {
        nonExistentGroupThroughEvent(true, jdbcTemplate, jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager);
    }

    @Test
    void doNotAddNonExistentUsers() throws Exception {
        nonExistentGroupThroughEvent(false, jdbcTemplate, jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager);
    }

    @Test
    void canUpdateEmailThroughEvent() {
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(user), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        userId = users.get(0).getId();
        user = getUaaUser(userAuthorities, origin, newEmail, firstName, lastName, password, externalId, userId, username);

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        ScimUser created = users.get(0);
        validateAuthoritiesCreated(externalAuthorities, userAuthorities, origin, created, jdbcScimGroupMembershipManager);
        assertEquals(newEmail, created.getPrimaryEmail());

        user = user.modifyEmail("test123@test.org");
        //Ensure email doesn't get updated if event instructs not to update.
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        created = users.get(0);
        validateAuthoritiesCreated(externalAuthorities, userAuthorities, origin, created, jdbcScimGroupMembershipManager);
        assertEquals(newEmail, created.getPrimaryEmail());

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, getAuthorities(externalAuthorities), true));
        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        created = users.get(0);
        validateAuthoritiesCreated(externalAuthorities, userAuthorities, origin, created, jdbcScimGroupMembershipManager);
        assertEquals("test123@test.org", created.getPrimaryEmail());
    }

    @Test
    void testGroupsFromEventAreMadeUnique() {
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, spy, Collections.singletonList(user), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        userId = users.get(0).getId();
        user = getUaaUser(userAuthorities, origin, newEmail, firstName, lastName, password, externalId, userId, username);

        List<GrantedAuthority> authorities = getAuthorities(externalAuthorities);
        authorities.addAll(getAuthorities(externalAuthorities));
        assertEquals(2*externalAuthorities.length, authorities.size());
        verify(spy, times(externalAuthorities.length)).addMember(any(), any(), any());

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, true, authorities, true));

        verify(spy, times(externalAuthorities.length*2)).addMember(any(), any(), any());
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(user), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        addIdentityProvider(jdbcTemplate, "newOrigin");
        bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Arrays.asList(user, user.modifySource("newOrigin", "")), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();
        assertEquals(2, jdbcScimUserProvisioning.retrieveAll(IdentityZone.getUaaZoneId()).size());
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(jdbcScimUserProvisioning, jdbcScimGroupProvisioning, jdbcScimGroupMembershipManager, Collections.singletonList(user), false, Collections.emptyList());
        bootstrap.afterPropertiesSet();

        List<ScimUser> scimUsers = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, scimUsers.size());
        ScimUser scimUser = scimUsers.get(0);
        ScimGroupMember member = new ScimGroupMember<>(scimUser);
        user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, member.getMemberId(), username);
        for (int i = 0; i < numgroups; i++) {
            jdbcScimGroupProvisioning.create(new ScimGroup("group" + i, "group" + i, IdentityZone.getUaaZoneId()), IdentityZone.getUaaZoneId());
            String gid = jdbcScimGroupProvisioning.query("displayName eq \"group" + i + "\"", IdentityZone.getUaaZoneId()).get(0).getId();
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
            JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager) {
        UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User", origin, zoneId);
        UaaUser mabel = new UaaUser("mabel", "password", "mabel@blah.com", "Mabel", "User", origin, zoneId);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                Arrays.asList(joe, mabel),
                false,
                Collections.emptyList());
        bootstrap.afterPropertiesSet();
    }

    private static void nonExistentGroupThroughEvent(
            final boolean add,
            final JdbcTemplate jdbcTemplate,
            final JdbcScimUserProvisioning jdbcScimUserProvisioning,
            final JdbcScimGroupProvisioning jdbcScimGroupProvisioning,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager) {
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
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                jdbcScimUserProvisioning,
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                Collections.singletonList(user),
                false,
                Collections.emptyList());
        bootstrap.afterPropertiesSet();

        List<ScimUser> users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        userId = users.get(0).getId();
        user = getUaaUser(userAuthorities, origin, email, firstName, lastName, password, externalId, userId, username);
        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, getAuthorities(externalAuthorities), add));

        users = jdbcScimUserProvisioning.query("userName eq \"" + username + "\" and origin eq \"" + origin + "\"", IdentityZone.getUaaZoneId());
        assertEquals(1, users.size());
        ScimUser created = users.get(0);
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
        assertThat(actual, IsArrayContainingInAnyOrder.arrayContainingInAnyOrder(expected));

        List<String> external = Arrays.asList(externalAuthorities);
        for (ScimGroup g : groups) {
            ScimGroupMember m = jdbcScimGroupMembershipManager.getMemberById(g.getId(), created.getId(), IdentityZone.getUaaZoneId());
            if (external.contains(g.getDisplayName())) {
                assertEquals(origin, m.getOrigin(), "Expecting relationship for Group[" + g.getDisplayName() + "] be of different origin.");
            } else {
                assertEquals(OriginKeys.UAA, m.getOrigin(), "Expecting relationship for Group[" + g.getDisplayName() + "] be of different origin.");
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

        static volatile AssertionError failure = null;
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
                if (failure != null) break;
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
