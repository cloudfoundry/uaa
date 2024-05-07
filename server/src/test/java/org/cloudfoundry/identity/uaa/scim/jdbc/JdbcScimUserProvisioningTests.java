package org.cloudfoundry.identity.uaa.scim.jdbc;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;

import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.resources.JoinAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;


@WithDatabaseContext
class JdbcScimUserProvisioningTests {

    private static final String SQL_INJECTION_FIELDS = "password,version,created,lastModified,username,email,givenName,familyName";
    private static final String OLD_ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values ('%s','%s','%s','%s','%s', '%s', '%s')";
    private static final String VERIFY_USER_SQL_FORMAT = "select verified from users where id=?";
    private static final String INSERT_MEMBERSHIP = "insert into group_membership (group_id, member_id, member_type,authorities,added, origin, identity_zone_id) values (?,?,?,?,?,?,?)";

    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private RandomValueStringGenerator generator;
    private JdbcPagingListFactory pagingListFactory;
    private String joeId;
    private String currentIdentityZoneId;
    private IdentityZoneManager idzManager;
    private final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning = mock(JdbcIdentityZoneProvisioning.class);

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    NamedParameterJdbcTemplate namedJdbcTemplate;
    private String joeEmail;
    private final String JOE_NAME = "joe";

    @BeforeEach
    void setUp(@Autowired LimitSqlAdapter limitSqlAdapter) {
        generator = new RandomValueStringGenerator();
        joeId = "joeId-" + UUID.randomUUID().toString().substring("joeId-".length());
        joeEmail = "joe@joe.com";
        String mabelId = "mabelId-" + UUID.randomUUID().toString().substring("mabelId-".length());
        pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter);

        currentIdentityZoneId = "currentIdentityZoneId-" + randomString();
        IdentityZone idz = new IdentityZone();
        idz.setId(currentIdentityZoneId);
        idzManager = new IdentityZoneManagerImpl();
        idzManager.setCurrentIdentityZone(idz);

        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder, idzManager, jdbcIdentityZoneProvisioning);

        SimpleSearchQueryConverter filterConverter = new SimpleSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
        jdbcScimUserProvisioning.setQueryConverter(filterConverter);
        SimpleSearchQueryConverter joinConverter = new SimpleSearchQueryConverter();
        joinConverter.setAttributeNameMapper(new JoinAttributeNameMapper("u"));
        jdbcScimUserProvisioning.setJoinConverter(joinConverter);

        addUser(jdbcTemplate, joeId,
                JOE_NAME, passwordEncoder.encode("joespassword"), joeEmail, "Joe", "User", "+1-222-1234567", currentIdentityZoneId);
        addUser(jdbcTemplate, mabelId, "mabel", passwordEncoder.encode("mabelspassword"), "mabel@mabel.com", "Mabel", "User", "", currentIdentityZoneId);
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.execute("delete from users");
    }


    @WithDatabaseContext
    @Nested
    class WhenFindingByEmailAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByEmailAndZone(joeEmail, UAA, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByEmailAndZone("unknown@example.com", UAA, currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndOriginAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone(JOE_NAME, UAA, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone("not-joe", UAA, currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone(JOE_NAME, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone("super-not-joe", currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @Test
    void canCreateUserWithExclamationMarkInUsername() {
        String userName = "jo!!@foo.com";
        ScimUser user = new ScimUser(null, userName, "Jo", "User");
        user.addEmail("email");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals(userName, created.getUserName());
    }

    @Test
    void canDeleteProviderUsersInDefaultZone() {
        arrangeUserConfigExistsForZone(IdentityZone.getUaaZoneId());

        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from users where origin=? and identity_zone_id=?",
                new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()},
                Integer.class
                ), is(1)
        );
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), IdentityZone.getUaaZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, IdentityZone.getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
    }

    @Test
    void retrieveByScimFilterOnlyActive() {
        final String originActive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originActive, true);

        final String originInactive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originInactive, false);

        final ScimUser user1 = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user1.addEmail("jo@blah.com");
        user1.setOrigin(originActive);
        final ScimUser created1 = jdbcScimUserProvisioning.createUser(user1, "j7hyqpassX", currentIdentityZoneId);

        final ScimUser user2 = new ScimUser(null, "jo2@foo.com", "Jo", "User");
        user2.addEmail("jo2@blah.com");
        user2.setOrigin(originInactive);
        final ScimUser created2 = jdbcScimUserProvisioning.createUser(user2, "j7hyqpassX", currentIdentityZoneId);

        final Function<String, List<String>> retrieveByScimFilter = (scimFilter) -> {
            final List<ScimUser> result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
                    scimFilter,
                    "userName",
                    true,
                    currentIdentityZoneId
            );
            Assertions.assertThat(result).isNotNull();
            final List<String> usernames = result.stream().map(ScimUser::getUserName).collect(toList());
            Assertions.assertThat(usernames).isSorted();
            return usernames;
        };

        // case 1: should return only user 1
        String filter = String.format("id eq '%s' or origin eq '%s'", created1.getId(), created2.getOrigin());
        List<String> usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames)
                .hasSize(1)
                .contains(created1.getUserName());

        // case 2: should return empty list
        filter = String.format("origin eq '%s'", created2.getOrigin());
        usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames).isEmpty();

        // case 3: should return empty list (filtered by origin and ID)
        filter = String.format("origin eq '%s' and id eq '%s'", created2.getOrigin(), created2.getId());
        usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames).isEmpty();
    }

    @Test
    void retrieveByScimFilterNoPaging() {
        JdbcPagingListFactory notInUse = mock(JdbcPagingListFactory.class);
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, notInUse, passwordEncoder, new IdentityZoneManagerImpl(),
            new JdbcIdentityZoneProvisioning(jdbcTemplate));
        SimpleSearchQueryConverter joinConverter = new SimpleSearchQueryConverter();
        joinConverter.setAttributeNameMapper(new JoinAttributeNameMapper("u"));
        jdbcScimUserProvisioning.setJoinConverter(joinConverter);
        String originActive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originActive, true);

        String originInactive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originInactive, false);

        ScimUser user1 = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user1.addEmail("jo@blah.com");
        user1.setOrigin(originActive);
        ScimUser created1 = jdbcScimUserProvisioning.createUser(user1, "j8hyqpassX", currentIdentityZoneId);

        ScimUser user2 = new ScimUser(null, "jo2@foo.com", "Jo", "User");
        user2.addEmail("jo2@blah.com");
        user2.setOrigin(originInactive);
        ScimUser created2 = jdbcScimUserProvisioning.createUser(user2, "j8hyqpassX", currentIdentityZoneId);

        String scimFilter = String.format("id eq '%s' or username eq '%s' or origin eq '%s'", created1.getId(), created2.getUserName(), created2.getOrigin());
        jdbcScimUserProvisioning.setPageSize(0);
        List<ScimUser> result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
            scimFilter,
            null,
            false,
            currentIdentityZoneId
        );
        Assertions.assertThat(result).isNotNull();
        List<String> usernames = result.stream().map(ScimUser::getUserName).collect(toList());
        Assertions.assertThat(usernames).isSorted();
        verify(notInUse, never()).createJdbcPagingList(anyString(), any(Map.class), any(RowMapper.class), any(Integer.class));
        // another option to query without paging
        jdbcScimUserProvisioning.setPageSize(Integer.MAX_VALUE);
        jdbcScimUserProvisioning.setPageSize(0);
        jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
            scimFilter,
            null,
            false,
            currentIdentityZoneId
        );
        verify(notInUse, never()).createJdbcPagingList(anyString(), any(Map.class), any(RowMapper.class), any(Integer.class));
        // positive check, now with paging
        jdbcScimUserProvisioning.setPageSize(1);
        jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
            scimFilter,
            null,
            false,
            currentIdentityZoneId
        );
        verify(notInUse, times(1)).createJdbcPagingList(anyString(), any(Map.class), any(RowMapper.class), any(Integer.class));
    }

    @Test
    void retrieveByScimFilterUsingLower() {
        JdbcPagingListFactory notInUse = mock(JdbcPagingListFactory.class);
        NamedParameterJdbcTemplate mockedJdbcTemplate = mock(NamedParameterJdbcTemplate.class);
        SimpleSearchQueryConverter joinConverter = new SimpleSearchQueryConverter();
        joinConverter.setAttributeNameMapper(new JoinAttributeNameMapper("u"));
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(mockedJdbcTemplate, pagingListFactory, passwordEncoder, idzManager, jdbcIdentityZoneProvisioning);
        jdbcScimUserProvisioning.setJoinConverter(joinConverter);

        String scimFilter = "id eq '1111' or username eq 'j4hyqpassX' or origin eq 'uaa'";
        jdbcScimUserProvisioning.setPageSize(0);
        // MYSQL default, no LOWER statement in query
        joinConverter.setDbCaseInsensitive(true);
        List<ScimUser>  result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
            scimFilter,
            null,
            false,
            currentIdentityZoneId
        );
        Assertions.assertThat(result).isNotNull();
        verify(mockedJdbcTemplate).query(contains("u.id = "), any(Map.class), any(RowMapper.class));
        verify(mockedJdbcTemplate, never()).query(contains("LOWER(u.id) = LOWER("), any(Map.class), any(RowMapper.class));
        // POSTGRESQL and HSQL default
        joinConverter.setDbCaseInsensitive(false);
        result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
            scimFilter,
            null,
            false,
            currentIdentityZoneId
        );
        Assertions.assertThat(result).isNotNull();
        verify(notInUse, never()).createJdbcPagingList(anyString(), any(Map.class), any(RowMapper.class), any(Integer.class));
        verify(mockedJdbcTemplate).query(contains("LOWER(u.id) = LOWER("), any(Map.class), any(RowMapper.class));
    }

    @Test
    void retrieveByScimFilter_IncludeInactive() {
        final String originActive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originActive, true);

        final String originInactive = randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, originInactive, false);

        final ScimUser user1 = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user1.addEmail("jo@blah.com");
        user1.setOrigin(originActive);
        final ScimUser created1 = jdbcScimUserProvisioning.createUser(user1, "j7hyqpassX", currentIdentityZoneId);

        final ScimUser user2 = new ScimUser(null, "jo2@foo.com", "Jo", "User");
        user2.addEmail("jo2@blah.com");
        user2.setOrigin(originInactive);
        final ScimUser created2 = jdbcScimUserProvisioning.createUser(user2, "j7hyqpassX", currentIdentityZoneId);

        final Function<String, List<String>> retrieveByScimFilter = (scimFilter) -> {
            final List<ScimUser> result = jdbcScimUserProvisioning.query(
                    scimFilter,
                    "userName",
                    true,
                    currentIdentityZoneId
            );
            Assertions.assertThat(result).isNotNull();
            final List<String> usernames = result.stream().map(ScimUser::getUserName).collect(toList());
            Assertions.assertThat(usernames).isSorted();
            return usernames;
        };

        // case 1: should return both
        String filter = String.format("id eq '%s' or origin eq '%s'", created1.getId(), created2.getOrigin());
        List<String> usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames)
                .hasSize(2)
                .contains(created1.getUserName(), created2.getUserName());

        // case 2: should return user 2
        filter = String.format("origin eq '%s'", created2.getOrigin());
        usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames)
                .hasSize(1)
                .contains(created2.getUserName());

        // case 3: should return user 2 (filtered by origin and ID)
        filter = String.format("origin eq '%s' and id eq '%s'", created2.getOrigin(), created2.getId());
        usernames = retrieveByScimFilter.apply(filter);
        Assertions.assertThat(usernames)
                .hasSize(1)
                .contains(created2.getUserName());
    }

    @Test
    void canDeleteProviderUsersInOtherZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertEquals(currentIdentityZoneId, created.getZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, currentIdentityZoneId}, Integer.class), is(1));
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(currentIdentityZoneId);
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, currentIdentityZoneId}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
    }

    @WithDatabaseContext
    @Nested
    class WithOtherZone {

        String currentIdentityZoneId;

        @BeforeEach
        void setUp() {
            currentIdentityZoneId = "currentIdentityZoneId-nested-" + randomString();
            IdentityZone idz = new IdentityZone();
            idz.setId(currentIdentityZoneId);
            idzManager.setCurrentIdentityZone(idz);
        }

        @Test
        void canDeleteZoneUsers() {
            ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
            user.addEmail("jo@blah.com");
            user.setOrigin(UAA);
            ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
            assertEquals("jo@foo.com", created.getUserName());
            assertNotNull(created.getId());
            assertEquals(UAA, created.getOrigin());
            assertEquals(currentIdentityZoneId, created.getZoneId());
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
            addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));


            IdentityZone zoneToDelete = new IdentityZone();
            zoneToDelete.setId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(zoneToDelete, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(0));
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
        }

        @Test
        void cannotDeleteUaaProviderUsersInOtherZone() {
            ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
            user.addEmail("jo@blah.com");
            user.setOrigin(UAA);
            ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
            assertEquals("jo@foo.com", created.getUserName());
            assertNotNull(created.getId());
            assertEquals(UAA, created.getOrigin());
            assertEquals(currentIdentityZoneId, created.getZoneId());
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
            IdentityProvider loginServer =
                    new IdentityProvider()
                            .setOriginKey(UAA)
                            .setIdentityZoneId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
        }

    }

    private void arrangeUserConfigExistsForZone(final String zoneId) {
        final IdentityZone zone = mock(IdentityZone.class);
        when(jdbcIdentityZoneProvisioning.retrieve(zoneId)).thenReturn(zone);
        final IdentityZoneConfiguration zoneConfig = mock(IdentityZoneConfiguration.class);
        when(zone.getConfig()).thenReturn(zoneConfig);
        final UserConfig userConfig = mock(UserConfig.class);
        when(zoneConfig.getUserConfig()).thenReturn(userConfig);
    }

    @WithDatabaseContext
    @Nested
    class WithAliasProperties {
        private static final String CUSTOM_ZONE_ID = UUID.randomUUID().toString();

        @BeforeEach
        void setUp() {
            arrangeUserConfigExistsForZone(UAA);
            arrangeUserConfigExistsForZone(CUSTOM_ZONE_ID);
        }

        @ParameterizedTest
        @MethodSource("fromUaaToCustomZoneAndViceVersa")
        void testCreateUser_ShouldPersistAliasProperties(final String zone1, final String zone2) {
            final ScimUser userToCreate = new ScimUser(null, "some-user", "John", "Doe");
            final ScimUser.Email email = new ScimUser.Email();
            email.setPrimary(true);
            email.setValue("john.doe@example.com");
            userToCreate.setEmails(singletonList(email));
            final String aliasId = UUID.randomUUID().toString();
            userToCreate.setAliasId(aliasId);
            userToCreate.setAliasZid(zone2);

            final ScimUser createdUser = jdbcScimUserProvisioning.createUser(userToCreate, "some-password", zone1);
            final String userId = createdUser.getId();
            Assertions.assertThat(userId).isNotBlank();
            Assertions.assertThat(createdUser.getAliasId()).isNotBlank().isEqualTo(aliasId);
            Assertions.assertThat(createdUser.getAliasZid()).isNotBlank().isEqualTo(zone2);

            final ScimUser retrievedUser = jdbcScimUserProvisioning.retrieve(userId, zone1);
            Assertions.assertThat(retrievedUser.getAliasId()).isNotBlank().isEqualTo(aliasId);
            Assertions.assertThat(retrievedUser.getAliasZid()).isNotBlank().isEqualTo(zone2);

            // the alias user should not be persisted by this method
            assertUserDoesNotExist(zone2, aliasId);
        }

        @ParameterizedTest
        @MethodSource("fromUaaToCustomZoneAndViceVersa")
        void testUpdateUser_ShouldPersistAliasProperties(final String zone1, final String zone2) {
            // create a user with empty alias properties
            final ScimUser userToCreate = new ScimUser(null, "some-user", "John", "Doe");
            final ScimUser.Email email = new ScimUser.Email();
            email.setPrimary(true);
            email.setValue("john.doe@example.com");
            userToCreate.setEmails(singletonList(email));
            userToCreate.setAliasId(null);
            userToCreate.setAliasZid(null);

            final ScimUser createdUser = jdbcScimUserProvisioning.createUser(userToCreate, "some-password", zone1);
            final String userId = createdUser.getId();
            Assertions.assertThat(userId).isNotBlank();
            Assertions.assertThat(createdUser.getAliasId()).isBlank();
            Assertions.assertThat(createdUser.getAliasZid()).isBlank();

            final ScimUser retrievedUser = jdbcScimUserProvisioning.retrieve(userId, zone1);
            Assertions.assertThat(retrievedUser.getAliasId()).isBlank();
            Assertions.assertThat(retrievedUser.getAliasZid()).isBlank();

            // update the user by setting 'aliasId' and 'aliasZid'
            final String aliasId = UUID.randomUUID().toString();
            retrievedUser.setAliasId(aliasId);
            retrievedUser.setAliasZid(zone2);
            final ScimUser updatedUser = jdbcScimUserProvisioning.update(userId, retrievedUser, zone1);
            Assertions.assertThat(updatedUser.getAliasId()).isEqualTo(aliasId);
            Assertions.assertThat(updatedUser.getAliasZid()).isEqualTo(zone2);

            // no alias user should be created by this method
            assertUserDoesNotExist(zone2, aliasId);
        }

        private void assertUserDoesNotExist(final String zoneId, final String userId) {
            Assertions.assertThatExceptionOfType(ScimResourceNotFoundException.class)
                    .isThrownBy(() -> jdbcScimUserProvisioning.retrieve(userId, zoneId));
        }

        private static Stream<Arguments> fromUaaToCustomZoneAndViceVersa() {
            return Stream.of(Arguments.of(UAA, CUSTOM_ZONE_ID), Arguments.of(CUSTOM_ZONE_ID, UAA));
        }
    }

    @Test
    void cannotDeleteUaaZoneUsers() {
        arrangeUserConfigExistsForZone(IdentityZone.getUaaZoneId());

        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(UAA);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(UAA, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, IdentityZone.getUaaZoneId()}, Integer.class), is(1));
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, IdentityZone.getUaaZoneId()}, Integer.class), is(1));
    }

    @Test
    void canCreateUserInDefaultIdentityZone() {
        arrangeUserConfigExistsForZone(IdentityZone.getUaaZoneId());

        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(IdentityZone.getUaaZoneId(), map.get("identity_zone_id"));
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001); //1 second at most given MySQL fractionless timestamp
    }

    @Test
    void canModifyPassword() throws Exception {
        ScimUser user = new ScimUser(null, randomString() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001);
        Thread.sleep(10);
        jdbcScimUserProvisioning.changePassword(created.getId(), "j7hyqpassX", "j7hyqpassXXX", currentIdentityZoneId);

        user = jdbcScimUserProvisioning.retrieve(created.getId(), currentIdentityZoneId);
        assertNotNull(user.getPasswordLastModified());
        assertTrue(Math.abs(user.getMeta().getLastModified().getTime() - user.getPasswordLastModified().getTime()) < 1001);
    }

    @Test
    void setPasswordChangeRequired() {
        ScimUser user = new ScimUser(null, randomString() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertFalse(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), true, currentIdentityZoneId);
        assertTrue(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), false, currentIdentityZoneId);
        assertFalse(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
    }

    @Test
    void canCreateUserInOtherIdentityZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(currentIdentityZoneId, map.get("identity_zone_id"));
    }

    @Test
    void countUsersAcrossAllZones() {
        createRandomUserInZone(jdbcTemplate, generator, IdentityZone.getUaaZoneId());
        long beginningCount = jdbcScimUserProvisioning.getTotalCount();
        createRandomUserInZone(jdbcTemplate, generator, "zone1");
        assertEquals(beginningCount + 1, jdbcScimUserProvisioning.getTotalCount());
        createRandomUserInZone(jdbcTemplate, generator, "zone2");
        assertEquals(beginningCount + 2, jdbcScimUserProvisioning.getTotalCount());
    }

    @Test
    void validateExternalIdDuringCreateAndUpdate() {
        final String origin = "test-"+randomString();
        addIdentityProvider(jdbcTemplate, IdentityZone.getUaaZoneId(), origin);
        final String externalId = "testId";
        final ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.setOrigin(origin);
        user.setExternalId(externalId);
        user.addEmail("jo@blah.com");
        final ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        final Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(origin, created.getOrigin());
        assertEquals(externalId, created.getExternalId());

        // update external ID
        final String externalId2 = "testId2";
        created.setExternalId(externalId2);
        final ScimUser updated = jdbcScimUserProvisioning.update(created.getId(), created, currentIdentityZoneId);
        assertEquals(externalId2, updated.getExternalId());
    }

    @Test
    void canCreateUserWithoutGivenNameAndFamilyName() {
        ScimUser user = new ScimUser(null, "jonah@foo.com", null, null);
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jonah@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
    }

    @Test
    void canCreateUserWithSingleQuoteInEmailAndUsername() {
        ScimUser user = new ScimUser(null, "ro'gallagher@example.com", "Rob", "O'Gallagher");
        user.addEmail("ro'gallagher@example.com");
        jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
    }

    @Test
    void cannotCreateScimUserWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "joeyjoejoe", "joe", "young");
        assertThrows(IllegalArgumentException.class, () -> user.addEmail(""));
    }

    @Test
    void canReadScimUserWithMissingEmail() {
        // Create a user with no email address, reflecting previous behavior

        JdbcScimUserProvisioning noValidateProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder, new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate)) {
            @Override
            public ScimUser retrieve(String id, String zoneId) {
                ScimUser createdUserId = new ScimUser();
                createdUserId.setId(id);
                return createdUserId;
            }
        };

        ScimUser nohbdy = spy(new ScimUser(null, "nohbdy", "Missing", "Email"));
        ScimUser.Email emptyEmail = new ScimUser.Email();
        emptyEmail.setValue("");
        when(nohbdy.getEmails()).thenReturn(singletonList(emptyEmail));
        when(nohbdy.getPrimaryEmail()).thenReturn("");
        nohbdy.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        nohbdy.setSalt("salt");
        nohbdy.setPassword(randomString());
        nohbdy.setOrigin(OriginKeys.UAA);
        String createdUserId = noValidateProvisioning.create(nohbdy, currentIdentityZoneId).getId();

        jdbcScimUserProvisioning.retrieve(createdUserId, currentIdentityZoneId);
    }

    @Test
    void updateModifiesExpectedData() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        jo.setSalt("salt");

        ScimUser joe = jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);

        // Can change username
        assertEquals("josephine", joe.getUserName());
        assertEquals("jo@blah.com", joe.getPrimaryEmail());
        assertEquals("Jo", joe.getGivenName());
        assertEquals("NewUser", joe.getFamilyName());
        assertEquals(1, joe.getVersion());
        assertEquals(joeId, joe.getId());
        assertNull(joe.getGroups());
        assertEquals("salt", joe.getSalt());
    }

    @Test
    void updateWithEmptyPhoneListWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(new ArrayList<>());
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateWithEmptyPhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(singletonList(emptyNumber));
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateWithWhiteSpacePhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        emptyNumber.setValue(" ");
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(singletonList(emptyNumber));
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateCannotModifyGroups() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setGroups(Collections.singleton(new Group(null, "dash/user")));

        ScimUser joe = jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);

        assertEquals(joeId, joe.getId());
        assertNull(joe.getGroups());
    }

    @Test
    void updateCannotModifyOrigin() {
        final String userId = UUID.randomUUID().toString();

        final ScimUser userToCreate = new ScimUser(userId, "john.doe", "John", "Doe");
        userToCreate.setPassword("some-password");
        userToCreate.setOrigin("origin1");
        userToCreate.setZoneId(currentIdentityZoneId);
        userToCreate.setPhoneNumbers(singletonList(new PhoneNumber("12345")));
        userToCreate.setPrimaryEmail("john.doe@example.com");
        addUser(jdbcTemplate, userToCreate);

        final ScimUser scimUser = jdbcScimUserProvisioning.retrieve(userId, currentIdentityZoneId);

        // change origin
        scimUser.setOrigin("origin2");

        final InvalidScimResourceException exception = assertThrows(InvalidScimResourceException.class, () ->
                jdbcScimUserProvisioning.update(userId, scimUser, currentIdentityZoneId)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals("Cannot change user's origin in update operation.", exception.getMessage());
    }

    @Test
    void updateWithWrongVersionIsError() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setVersion(1);
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
    }

    @Test
    void updateWithBadUsernameIsError() {
        ScimUser jo = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        jo.setUserName("jo$ephione");
        assertThrows(InvalidScimResourceException.class, () -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
    }

    @Test
    void updateWithBadUsernameIsOk_For_Non_UAA() {
        final String id = UUID.randomUUID().toString();
        final ScimUser user = new ScimUser(id, "josephine", "Jo", "NewUser");
        user.setOrigin(OriginKeys.LDAP);
        user.setZoneId(currentIdentityZoneId);
        user.addEmail("jo@blah.com");
        user.setPhoneNumbers(singletonList(new PhoneNumber("12345")));
        addUser(jdbcTemplate, user);

        final ScimUser updatePayload = jdbcScimUserProvisioning.retrieve(id, currentIdentityZoneId);
        updatePayload.setUserName("jo$ephine");
        final ScimUser userAfterUpdate = jdbcScimUserProvisioning.update(id, updatePayload, currentIdentityZoneId);
        assertEquals("jo$ephine", userAfterUpdate.getUserName());
        assertEquals(OriginKeys.LDAP, userAfterUpdate.getOrigin());
    }

    @Test
    void canChangePasswordWithoutOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, null, "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertTrue(passwordEncoder.matches("koala123$marissa", storedPassword));
    }

    @Test
    void canChangePasswordWithCorrectOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, "joespassword", "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertTrue(passwordEncoder.matches("koala123$marissa", storedPassword));
    }

    @Test
    void cannotChangePasswordNonexistentUser() {
        assertThrows(BadCredentialsException.class,
                () -> jdbcScimUserProvisioning.changePassword(joeId, "notjoespassword", "newpassword", currentIdentityZoneId));
    }

    @Test
    void cannotChangePasswordIfOldPasswordDoesntMatch() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.changePassword("9999", null, "newpassword", currentIdentityZoneId));
    }

    @Test
    void canRetrieveExistingUser() {
        ScimUser joe = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertNotNull(joe);
        assertEquals(joeId, joe.getId());
        assertEquals("Joe", joe.getGivenName());
        assertEquals("User", joe.getFamilyName());
        assertEquals("joe@joe.com", joe.getPrimaryEmail());
        assertEquals("joe", joe.getUserName());
        assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
        assertNull(joe.getGroups());
    }

    @Test
    void cannotRetrieveNonexistentUser() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.retrieve("9999", currentIdentityZoneId));
    }

    @Test
    void canDeactivateExistingUser() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(1, jdbcTemplate.queryForList("select * from users where id=? and active=?", tmpUserId, false).size());
        assertFalse(deletedUser.isActive());
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\" and active eq false", currentIdentityZoneId).size());
    }

    @Test
    void cannotDeactivateExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        deletedUser.setActive(true);
        assertThrows(ScimResourceAlreadyExistsException.class,
                () -> jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId));
    }

    @Test
    void cannotDeactivateNonexistentUser() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
    }

    @Test
    void deactivateWithWrongVersionIsError() {
        assertThrows(OptimisticLockingFailureException.class,
                () -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
    }

    @Test
    void canDeleteExistingUserThroughEvent() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserId, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<Object>(user, mock(Authentication.class), currentIdentityZoneId));
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void canDeleteExistingUser() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void canDeleteExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());

        deletedUser.setActive(true);
        ScimUser user = jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId);
        assertNotNull(user);
        assertNotNull(user.getId());
        assertNotSame(tmpUserId, user.getId());
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void createdUserNotVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
    }

    @Test
    void createUserWithDuplicateUsername() {
        addUser(jdbcTemplate, "cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", currentIdentityZoneId);
        ScimUser scimUser = new ScimUser("user-id-2", "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword("password");

        ScimResourceAlreadyExistsException e = assertThrows(ScimResourceAlreadyExistsException.class,
                () -> jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId));

        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("active", true);
        userDetails.put("verified", false);
        userDetails.put("user_id", "cba09242-aa43-4247-9aa0-b5c75c281f94");
        assertEquals(HttpStatus.CONFLICT, e.getStatus());
        assertEquals("Username already in use: user@example.com", e.getMessage());
        assertEquals(userDetails, e.getExtraInfo());
    }

    @Test
    void createUserCheckSalt() {
        ScimUser scimUser = new ScimUser("user-id-3", "user3@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword("password");
        scimUser.setSalt("salt");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser = jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");
        scimUser = jdbcScimUserProvisioning.update(scimUser.getId(), scimUser, currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("newsalt", scimUser.getSalt());
    }

    @Test
    void updateUserPasswordDoesntChange() {
        String username = "user-" + new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser scimUser = new ScimUser(null, username, "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(singletonList(email));
        scimUser.setSalt("salt");
        scimUser = jdbcScimUserProvisioning.createUser(scimUser, "password", currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");

        String passwordHash = jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class);
        assertNotNull(passwordHash);

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), null, "password", currentIdentityZoneId);
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class));

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), "password", "password", currentIdentityZoneId);
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class));

    }

    @Test
    void createUserWithDuplicateUsernameInOtherIdp() {
        addUser(jdbcTemplate, "cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", IdentityZone.getUaaZoneId());

        ScimUser scimUser = new ScimUser(null, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword("password");
        scimUser.setOrigin("test-origin");
        String userId2 = jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId).getId();
        assertNotNull(userId2);
        assertNotEquals("cba09242-aa43-4247-9aa0-b5c75c281f94", userId2);
    }

    @Test
    void updatedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        jdbcScimUserProvisioning.verifyUser(tmpUserIdString, -1, currentIdentityZoneId);
        verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertTrue(verified);
    }

    @Test
    void createUserWithNoZoneDefaultsToUAAZone() {
        String id = UUID.randomUUID().toString();
        jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, id, "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890"));
        ScimUser user = jdbcScimUserProvisioning.retrieve(id, IdentityZone.getUaaZoneId());
        assertEquals(IdentityZone.getUaaZoneId(), user.getZoneId());
        assertNull(user.getSalt());
    }

    @Test
    void createUserWithNoZoneFailsIfUserAlreadyExistsInUaaZone() {
        addUser(jdbcTemplate, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890", IdentityZone.getUaaZoneId());
        assertThrows(DuplicateKeyException.class,
                () -> jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890")));
    }

    @Test
    void updatedVersionedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user = jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion(), currentIdentityZoneId);
        assertTrue(user.isVerified());
    }

    @Test
    void userVerifiedThroughUpdate() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user.setVerified(true);
        user = jdbcScimUserProvisioning.update(tmpUserIdString, user, currentIdentityZoneId);
        assertTrue(user.isVerified());
    }

    @Test
    void userVerifiedInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        assertThrows(ScimResourceNotFoundException.class, () -> jdbcScimUserProvisioning.verifyUser("-1-1-1", -1, currentIdentityZoneId));
    }

    @Test
    void userUpdateInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user.setVerified(true);
        assertThrows(ScimResourceNotFoundException.class, () -> jdbcScimUserProvisioning.update("-1-1-1", user, currentIdentityZoneId));
    }

    @Test
    void updatedIncorrectVersionUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion() + 50, currentIdentityZoneId));
    }

    @Test
    void cannotDeleteNonexistentUser() {
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
    }

    @Test
    void deleteWithWrongVersionIsError() {
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
    }

    @Test
    void canRetrieveUsers() {
        assertTrue(2 <= jdbcScimUserProvisioning.retrieveAll(currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterExists() {
        assertTrue(2 <= jdbcScimUserProvisioning.query("username pr", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterEquals() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterEqualsDoubleQuote() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterKeyCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("USERNAME eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("username EQ \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterValueCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"Joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterContains() {
        assertEquals(2, jdbcScimUserProvisioning.query("username co \"e\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterStartsWith() {
        assertEquals(1, jdbcScimUserProvisioning.query("username sw \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterGreater() {
        assertEquals(1, jdbcScimUserProvisioning.query("username gt \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithEmailFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("emails.value sw \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithGroupsFilter() {
        List<ScimUser> users = jdbcScimUserProvisioning.query("groups.display co \"uaa.user\"", currentIdentityZoneId);
        assertEquals(2, users.size());
        for (ScimUser user : users) {
            assertNotNull(user);
        }
    }

    @Test
    void canRetrieveUsersWithPhoneNumberFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("phoneNumbers.value sw \"+1-222\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithMetaVersionFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("userName eq \"joe\" and meta.version eq 0", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithMetaDateFilter() {
        assertEquals(2, jdbcScimUserProvisioning.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithBooleanFilter() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr and active eq true", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithSortBy() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr", "username", true, currentIdentityZoneId).size());
    }

    @Test
    void throwsExceptionWhenSortByIncludesThePrivateFieldSalt() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("id pr", "ID,     salt     ", true, currentIdentityZoneId).size(),
                is("Invalid sort field: salt")
        );
    }

    @Test
    void canRetrieveUsersWithSortByEmail() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr", "emails.value", true, currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanAnd() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr and emails.value co \".com\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOr() {
        assertEquals(2, jdbcScimUserProvisioning.query("username eq \"joe\" or emails.value co \".com\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"foo\" or username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterField() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("emails.type eq \"bar\"", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithIllegalPhoneNumberFilterField() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("phoneNumbers.type eq \"bar\"", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterQuotes() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("username eq \"bar", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username=\"joe\"; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username gt \"h\"; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class, () -> jdbcScimUserProvisioning.query("username eq \"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class, () -> jdbcScimUserProvisioning.query("username eq \"joe\"\"; select id from users where id='''; select "
                + SQL_INJECTION_FIELDS + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username eq \"joe\"'; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe''", currentIdentityZoneId));
    }

    @Test
    void filterEqWithoutQuotesIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username eq joe", currentIdentityZoneId));
    }

    @Test
    void checkPasswordMatches_returnsTrue_PasswordMatches() {
        assertTrue(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "joespassword", currentIdentityZoneId));
    }

    @Test
    void checkPasswordMatches_ReturnsFalse_newPasswordSameAsOld() {
        assertFalse(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "notjoepassword", currentIdentityZoneId));
    }

    @Test
    void updateLastLogonTime() {
        ScimUser user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        Long timeStampBeforeUpdate = user.getLastLogonTime();
        assertNull(timeStampBeforeUpdate);
        jdbcScimUserProvisioning.updateLastLogonTime(joeId, currentIdentityZoneId);
        user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertNotNull(user.getLastLogonTime());
    }

    @Test
    void cannotCreateMaxUserLimit() {
        ScimUser scimUser = new ScimUser("user-id-1", "user1@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setOrigin(OriginKeys.UAA);
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setMaxUsers(10);
        assertThrowsWithMessageThat(
            InvalidScimResourceException.class,
            () -> {
                for (int i = 1; i < 12; i++) {
                    scimUser.setId("user-id-" + i);
                    scimUser.setUserName("user" +i+ "@example.com");
                    scimUser.setPassword(randomString());
                    jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
                }
            },
            containsString("The maximum allowed numbers of users: 10 is reached already in Identity Zone")
        );
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setMaxUsers(-1);
    }

    @Test
    void canCreateUserWithValidOrigin() {
        String validOrigin = "validOrigin-"+randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, validOrigin);
        String userId = "user-"+randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId+"@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setOrigin(validOrigin);
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(true);
        try {
            jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
        } catch (InvalidScimResourceException e) {
            fail("Can't create user with valid origin when origin is checked");
        } finally {
            idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(false);
        }
    }

    @Test
    void cannotCreateUserWithInvalidOrigin() {
        String invalidOrigin = "invalidOrigin-"+randomString();
        String userId = "user-"+randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId+"@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setOrigin(invalidOrigin);
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(true);
        assertThrowsWithMessageThat(
            InvalidScimResourceException.class,
            () -> jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId),
            containsString("Invalid origin")
        );
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(false);
    }

    @Test
    void cannotCreateUserWithInvalidIdentityZone() {
        String userId = "user-"+randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId+"@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());

        // arrange zone does not exist
        final String invalidZoneId = "invalidZone-" + randomString();
        when(jdbcIdentityZoneProvisioning.retrieve(invalidZoneId))
                .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));

        assertThrowsWithMessageThat(
            InvalidScimResourceException.class,
            () -> jdbcScimUserProvisioning.create(scimUser, invalidZoneId),
            containsString("Invalid identity zone id")
        );
    }

    @Test
    void cannotUpdateUserWithWrongIdentityZone() {
        String userId = "user-"+randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId+"@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setZoneId("wrongZone-"+randomString());
        try {
            jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
        } catch (Exception e) {
            fail("Can't create test user");
        }
        assertThrowsWithMessageThat(
            ScimResourceNotFoundException.class,
            () -> jdbcScimUserProvisioning.update(userId, scimUser, currentIdentityZoneId),
            containsString("does not exist")
        );
    }

    private static String createUserForDelete(final JdbcTemplate jdbcTemplate, String zoneId) {
        String randomUserId = UUID.randomUUID().toString();
        addUser(jdbcTemplate, randomUserId, randomUserId, "password", randomUserId + "@delete.com", "ToDelete", "User", "+1-234-5678910", zoneId);
        return randomUserId;
    }

    private static void addUser(
            final JdbcTemplate jdbcTemplate,
            final String id,
            final String username,
            final String password,
            final String email,
            final String givenName,
            final String familyName,
            final String phoneNumber,
            final String identityZoneId
    ) {
        addUser(jdbcTemplate, id, username, password, email, givenName, familyName, phoneNumber, identityZoneId, null, null);
    }

    private static void addUser(
            final JdbcTemplate jdbcTemplate,
            final String id,
            final String username,
            final String password,
            final String email,
            final String givenName,
            final String familyName,
            final String phoneNumber,
            final String identityZoneId,
            final String aliasId,
            final String aliasZid
    ) {
        String addUserSql = String.format(
                "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id, alias_id, alias_zid) values ('%s','%s','%s','%s','%s','%s','%s','%s', %s, %s)",
                id,
                username,
                password,
                email,
                givenName,
                familyName,
                phoneNumber,
                identityZoneId,
                Optional.ofNullable(aliasId).map(it -> "'" + it + "'").orElse("null"),
                Optional.ofNullable(aliasZid).map(it -> "'" + it + "'").orElse("null")
        );
        jdbcTemplate.execute(addUserSql);
    }

    private static void addUser(final JdbcTemplate jdbcTemplate, final ScimUser scimUser) {
        String addUserSql = String.format(
                "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id, origin) values ('%s','%s','%s','%s','%s','%s','%s','%s', '%s')",
                scimUser.getId(),
                scimUser.getUserName(),
                scimUser.getPassword(),
                scimUser.getPrimaryEmail(),
                scimUser.getName().getGivenName(),
                scimUser.getName().getFamilyName(),
                scimUser.getPhoneNumbers().get(0),
                scimUser.getZoneId(),
                scimUser.getOrigin());
        jdbcTemplate.execute(addUserSql);
    }

    private static void createRandomUserInZone(
            final JdbcTemplate jdbcTemplate,
            final RandomValueStringGenerator generator,
            final String zoneId) {
        final String id = "scimUserId-" + UUID.randomUUID().toString().substring("scimUserId-".length());
        final String username = "username-" + generator.generate();
        final String password = "password-" + generator.generate();
        final String email = "email-" + generator.generate();
        final String givenName = "givenName-" + generator.generate();
        final String familyName = "familyName-" + generator.generate();
        final String phoneNumber = "phoneNumber-" + generator.generate();

        addUser(jdbcTemplate, id, username, password, email, givenName, familyName, phoneNumber, zoneId);
    }

    private static void addMembership(final JdbcTemplate jdbcTemplate,
                                      final String userId,
                                      final String origin,
                                      final String zoneId) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(INSERT_MEMBERSHIP, userId, userId, "USER", "authorities", timestamp, origin, zoneId);
    }

    private static void addIdentityProvider(JdbcTemplate jdbcTemplate, String idzId, String originKey) {
        addIdentityProvider(jdbcTemplate, idzId, originKey, true);
    }

    private static void addIdentityProvider(JdbcTemplate jdbcTemplate, String idzId, String originKey, boolean active) {
        jdbcTemplate.update("insert into identity_provider (id,identity_zone_id,name,origin_key,type,active) values (?,?,?,?,'UNKNOWN',?)", UUID.randomUUID().toString(), idzId, originKey, originKey, active);
    }

    private String randomString() {
        return generator.generate();
    }
}
