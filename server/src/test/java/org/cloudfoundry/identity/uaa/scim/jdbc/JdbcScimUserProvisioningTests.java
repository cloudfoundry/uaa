package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
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
import org.springframework.core.env.Environment;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


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

    @Autowired
    private Environment enviroment;

    private String joeEmail;
    private static final String JOE_NAME = "joe";

    private SimpleSearchQueryConverter joinConverter;
    private SimpleSearchQueryConverter filterConverter;

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

        joinConverter = new SimpleSearchQueryConverter();
        joinConverter.setAttributeNameMapper(new JoinAttributeNameMapper("u"));

        filterConverter = new SimpleSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));

        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(
                namedJdbcTemplate,
                pagingListFactory,
                passwordEncoder,
                idzManager,
                jdbcIdentityZoneProvisioning,
                filterConverter,
                joinConverter,
                new TimeServiceImpl(),
                true
        );

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
            assertThat(found).hasSize(1);

            ScimUser joe = found.getFirst();
            assertThat(joe).isNotNull();
            assertThat(joe.getId()).isEqualTo(joeId);
            assertThat(joe.getGivenName()).isEqualTo("Joe");
            assertThat(joe.getFamilyName()).isEqualTo("User");
            assertThat(joe.getPrimaryEmail()).isEqualTo("joe@joe.com");
            assertThat(joe.getUserName()).isEqualTo("joe");
            assertThat(joe.getPhoneNumbers().getFirst().getValue()).isEqualTo("+1-222-1234567");
            assertThat(joe.getGroups()).isNull();
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByEmailAndZone("unknown@example.com", UAA, currentIdentityZoneId);
            assertThat(found).isEmpty();
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndOriginAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone(JOE_NAME, UAA, currentIdentityZoneId);
            assertThat(found).hasSize(1);

            ScimUser joe = found.getFirst();
            assertThat(joe).isNotNull();
            assertThat(joe.getId()).isEqualTo(joeId);
            assertThat(joe.getGivenName()).isEqualTo("Joe");
            assertThat(joe.getFamilyName()).isEqualTo("User");
            assertThat(joe.getPrimaryEmail()).isEqualTo("joe@joe.com");
            assertThat(joe.getUserName()).isEqualTo("joe");
            assertThat(joe.getPhoneNumbers().getFirst().getValue()).isEqualTo("+1-222-1234567");
            assertThat(joe.getGroups()).isNull();
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone("not-joe", UAA, currentIdentityZoneId);
            assertThat(found).isEmpty();
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone(JOE_NAME, currentIdentityZoneId);
            assertThat(found).hasSize(1);

            ScimUser joe = found.getFirst();
            assertThat(joe).isNotNull();
            assertThat(joe.getId()).isEqualTo(joeId);
            assertThat(joe.getGivenName()).isEqualTo("Joe");
            assertThat(joe.getFamilyName()).isEqualTo("User");
            assertThat(joe.getPrimaryEmail()).isEqualTo("joe@joe.com");
            assertThat(joe.getUserName()).isEqualTo("joe");
            assertThat(joe.getPhoneNumbers().getFirst().getValue()).isEqualTo("+1-222-1234567");
            assertThat(joe.getGroups()).isNull();
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone("super-not-joe", currentIdentityZoneId);
            assertThat(found).isEmpty();
        }
    }

    @Test
    void canCreateUserWithExclamationMarkInUsername() {
        String userName = "jo!!@foo.com";
        ScimUser user = new ScimUser(null, userName, "Jo", "User");
        user.addEmail("email");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(created.getUserName()).isEqualTo(userName);
    }

    @Test
    void canDeleteProviderUsersInDefaultZone() {
        arrangeUserConfigExistsForZone(IdentityZone.getUaaZoneId());

        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(created.getOrigin()).isEqualTo(LOGIN_SERVER);
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from users where origin=? and identity_zone_id=?",
                Integer.class,
                new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()})).isOne();
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), IdentityZone.getUaaZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isOne();

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, IdentityZone.getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isZero();
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

        final Function<String, List<String>> retrieveByScimFilter = scimFilter -> {
            final List<ScimUser> result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
                    scimFilter,
                    "userName",
                    true,
                    currentIdentityZoneId
            );
            assertThat(result).isNotNull();
            final List<String> usernames = result.stream().map(ScimUser::getUserName).toList();
            assertThat(usernames).isSorted();
            return usernames;
        };

        // case 1: should return only user 1
        String filter = "id eq '%s' or origin eq '%s'".formatted(created1.getId(), created2.getOrigin());
        List<String> usernames = retrieveByScimFilter.apply(filter);
        assertThat(usernames)
                .hasSize(1)
                .contains(created1.getUserName());

        // case 2: should return empty list
        filter = "origin eq '%s'".formatted(created2.getOrigin());
        usernames = retrieveByScimFilter.apply(filter);
        assertThat(usernames).isEmpty();

        // case 3: should return empty list (filtered by origin and ID)
        filter = "origin eq '%s' and id eq '%s'".formatted(created2.getOrigin(), created2.getId());
        usernames = retrieveByScimFilter.apply(filter);
        assertThat(usernames).isEmpty();
    }

    @Test
    void retrieveByScimFilterNoPaging() {
        JdbcPagingListFactory notInUse = mock(JdbcPagingListFactory.class);
        SimpleSearchQueryConverter joinConverter = new SimpleSearchQueryConverter();
        joinConverter.setAttributeNameMapper(new JoinAttributeNameMapper("u"));
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, notInUse, passwordEncoder, new IdentityZoneManagerImpl(),
                new JdbcIdentityZoneProvisioning(jdbcTemplate), new SimpleSearchQueryConverter(), joinConverter, new TimeServiceImpl(), true);
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

        String scimFilter = "id eq '%s' or username eq '%s' or origin eq '%s'".formatted(created1.getId(), created2.getUserName(), created2.getOrigin());
        jdbcScimUserProvisioning.setPageSize(0);
        List<ScimUser> result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
                scimFilter,
                null,
                false,
                currentIdentityZoneId
        );
        assertThat(result).isNotNull();
        List<String> usernames = result.stream().map(ScimUser::getUserName).toList();
        assertThat(usernames).isSorted();
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
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(mockedJdbcTemplate, pagingListFactory, passwordEncoder, idzManager, jdbcIdentityZoneProvisioning, new SimpleSearchQueryConverter(), joinConverter, new TimeServiceImpl(), true);

        String scimFilter = "id eq '1111' or username eq 'j4hyqpassX' or origin eq 'uaa'";
        jdbcScimUserProvisioning.setPageSize(0);
        // MYSQL default, no LOWER statement in query
        joinConverter.setDbCaseInsensitive(true);
        List<ScimUser> result = jdbcScimUserProvisioning.retrieveByScimFilterOnlyActive(
                scimFilter,
                null,
                false,
                currentIdentityZoneId
        );
        assertThat(result).isNotNull();
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
        assertThat(result).isNotNull();
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

        final Function<String, List<ScimUser>> retrieveByScimFilter = scimFilter -> jdbcScimUserProvisioning.query(
                scimFilter,
                "created",
                true,
                currentIdentityZoneId
        );

        // case 1: should return both
        String filter = "id eq '%s' or origin eq '%s'".formatted(created1.getId(), created2.getOrigin());
        List<ScimUser> users = retrieveByScimFilter.apply(filter);
        var oldestFirst = Comparator.<ScimUser, Date>comparing(x -> x.getMeta().getCreated());
        assertThat(users)
                .hasSize(2)
                .isSortedAccordingTo(oldestFirst)
                .map(ScimUser::getUserName)
                .contains(created1.getUserName(), created2.getUserName());

        // case 2: should return user 2
        filter = "origin eq '%s'".formatted(created2.getOrigin());
        users = retrieveByScimFilter.apply(filter);
        assertThat(users)
                .hasSize(1)
                .map(ScimUser::getUserName)
                .contains(created2.getUserName());

        // case 3: should return user 2 (filtered by origin and ID)
        filter = "origin eq '%s' and id eq '%s'".formatted(created2.getOrigin(), created2.getId());
        users = retrieveByScimFilter.apply(filter);
        assertThat(users)
                .hasSize(1)
                .map(ScimUser::getUserName)
                .contains(created2.getUserName());
    }

    @Test
    void canDeleteProviderUsersInOtherZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(created.getOrigin()).isEqualTo(LOGIN_SERVER);
        assertThat(created.getZoneId()).isEqualTo(currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{LOGIN_SERVER, currentIdentityZoneId})).isOne();
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isOne();

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(currentIdentityZoneId);
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{LOGIN_SERVER, currentIdentityZoneId})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isZero();
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
            assertThat(created.getUserName()).isEqualTo("jo@foo.com");
            assertThat(created.getId()).isNotNull();
            assertThat(created.getOrigin()).isEqualTo(UAA);
            assertThat(created.getZoneId()).isEqualTo(currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, currentIdentityZoneId})).isOne();
            addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isOne();


            IdentityZone zoneToDelete = new IdentityZone();
            zoneToDelete.setId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(zoneToDelete, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, currentIdentityZoneId})).isZero();
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", Integer.class, new Object[]{created.getId()})).isZero();
        }

        @Test
        void cannotDeleteUaaProviderUsersInOtherZone() {
            ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
            user.addEmail("jo@blah.com");
            user.setOrigin(UAA);
            ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
            assertThat(created.getUserName()).isEqualTo("jo@foo.com");
            assertThat(created.getId()).isNotNull();
            assertThat(created.getOrigin()).isEqualTo(UAA);
            assertThat(created.getZoneId()).isEqualTo(currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, currentIdentityZoneId})).isOne();
            IdentityProvider loginServer =
                    new IdentityProvider()
                            .setOriginKey(UAA)
                            .setIdentityZoneId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, currentIdentityZoneId})).isOne();
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
        void createUserShouldPersistAliasProperties(final String zone1, final String zone2) {
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
            assertThat(userId).isNotBlank();
            assertThat(createdUser.getAliasId()).isNotBlank().isEqualTo(aliasId);
            assertThat(createdUser.getAliasZid()).isNotBlank().isEqualTo(zone2);

            final ScimUser retrievedUser = jdbcScimUserProvisioning.retrieve(userId, zone1);
            assertThat(retrievedUser.getAliasId()).isNotBlank().isEqualTo(aliasId);
            assertThat(retrievedUser.getAliasZid()).isNotBlank().isEqualTo(zone2);

            // the alias user should not be persisted by this method
            assertUserDoesNotExist(zone2, aliasId);
        }

        @ParameterizedTest
        @MethodSource("fromUaaToCustomZoneAndViceVersa")
        void updateUserShouldPersistAliasProperties(final String zone1, final String zone2) {
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
            assertThat(userId).isNotBlank();
            assertThat(createdUser.getAliasId()).isBlank();
            assertThat(createdUser.getAliasZid()).isBlank();

            final ScimUser retrievedUser = jdbcScimUserProvisioning.retrieve(userId, zone1);
            assertThat(retrievedUser.getAliasId()).isBlank();
            assertThat(retrievedUser.getAliasZid()).isBlank();

            // update the user by setting 'aliasId' and 'aliasZid'
            final String aliasId = UUID.randomUUID().toString();
            retrievedUser.setAliasId(aliasId);
            retrievedUser.setAliasZid(zone2);
            final ScimUser updatedUser = jdbcScimUserProvisioning.update(userId, retrievedUser, zone1);
            assertThat(updatedUser.getAliasId()).isEqualTo(aliasId);
            assertThat(updatedUser.getAliasZid()).isEqualTo(zone2);

            // no alias user should be created by this method
            assertUserDoesNotExist(zone2, aliasId);
        }

        private void assertUserDoesNotExist(final String zoneId, final String userId) {
            assertThatExceptionOfType(ScimResourceNotFoundException.class)
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
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(created.getOrigin()).isEqualTo(UAA);
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, IdentityZone.getUaaZoneId()})).isOne();
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", Integer.class, new Object[]{UAA, IdentityZone.getUaaZoneId()})).isOne();
    }

    @Test
    void canCreateUserInDefaultIdentityZone() {
        arrangeUserConfigExistsForZone(IdentityZone.getUaaZoneId());

        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(user.getId()).isNotSameAs(created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertThat(map).containsEntry("userName", user.getUserName())
                .containsEntry("identity_zone_id", IdentityZone.getUaaZoneId())
                .extractingByKey(UaaAuthority.UAA_USER.getUserType()).isEqualTo(user.getUserType());
        assertThat(created.getGroups()).isNull();
        assertThat(user.getPasswordLastModified()).isNull();
        assertThat(created.getPasswordLastModified()).isNotNull();
        assertThat(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime())).isLessThan(1001); //1 second at most given MySQL fractionless timestamp
    }

    @Test
    void canModifyPassword() throws Exception {
        ScimUser user = new ScimUser(null, randomString() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(user.getPasswordLastModified()).isNull();
        assertThat(created.getPasswordLastModified()).isNotNull();
        assertThat(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime())).isLessThan(1001);
        Thread.sleep(10);
        jdbcScimUserProvisioning.changePassword(created.getId(), "j7hyqpassX", "j7hyqpassXXX", currentIdentityZoneId);

        user = jdbcScimUserProvisioning.retrieve(created.getId(), currentIdentityZoneId);
        assertThat(user.getPasswordLastModified()).isNotNull();
        assertThat(Math.abs(user.getMeta().getLastModified().getTime() - user.getPasswordLastModified().getTime())).isLessThan(1001);
    }

    @Test
    void setPasswordChangeRequired() {
        ScimUser user = new ScimUser(null, randomString() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId)).isFalse();
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), true, currentIdentityZoneId);
        assertThat(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId)).isTrue();
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), false, currentIdentityZoneId);
        assertThat(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId)).isFalse();
    }

    @Test
    void canCreateUserInOtherIdentityZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(created.getGroups()).isNull();
        assertThat(user.getId()).isNotSameAs(created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertThat(map).containsEntry("userName", user.getUserName())
                .containsEntry("identity_zone_id", currentIdentityZoneId)
                .extractingByKey(UaaAuthority.UAA_USER.getUserType()).isEqualTo(user.getUserType());
    }

    @Test
    void countUsersAcrossAllZones() {
        createRandomUserInZone(jdbcTemplate, generator, IdentityZone.getUaaZoneId());
        long beginningCount = jdbcScimUserProvisioning.getTotalCount();
        createRandomUserInZone(jdbcTemplate, generator, "zone1");
        assertThat(jdbcScimUserProvisioning.getTotalCount()).isEqualTo(beginningCount + 1);
        createRandomUserInZone(jdbcTemplate, generator, "zone2");
        assertThat(jdbcScimUserProvisioning.getTotalCount()).isEqualTo(beginningCount + 2);
    }

    @Test
    void validateExternalIdDuringCreateAndUpdate() {
        final String origin = "test-" + randomString();
        addIdentityProvider(jdbcTemplate, IdentityZone.getUaaZoneId(), origin);
        final String externalId = "testId";
        final ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.setOrigin(origin);
        user.setExternalId(externalId);
        user.addEmail("jo@blah.com");
        final ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(created.getUserName()).isEqualTo("jo@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(user.getId()).isNotEqualTo(created.getId());
        final Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertThat(map).containsEntry("userName", user.getUserName())
                .extractingByKey(UaaAuthority.UAA_USER.getUserType()).isEqualTo(user.getUserType());
        assertThat(created.getGroups()).isNull();
        assertThat(created.getOrigin()).isEqualTo(origin);
        assertThat(created.getExternalId()).isEqualTo(externalId);

        // update external ID
        final String externalId2 = "testId2";
        created.setExternalId(externalId2);
        final ScimUser updated = jdbcScimUserProvisioning.update(created.getId(), created, currentIdentityZoneId);
        assertThat(updated.getExternalId()).isEqualTo(externalId2);
    }

    @Test
    void canCreateUserWithoutGivenNameAndFamilyName() {
        ScimUser user = new ScimUser(null, "jonah@foo.com", null, null);
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertThat(created.getUserName()).isEqualTo("jonah@foo.com");
        assertThat(created.getId()).isNotNull();
        assertThat(user.getId()).isNotSameAs(created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertThat(map).containsEntry("userName", user.getUserName())
                .extractingByKey(UaaAuthority.UAA_USER.getUserType()).isEqualTo(user.getUserType());
        assertThat(created.getGroups()).isNull();
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
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> user.addEmail(""));
    }

    @Test
    void canReadScimUserWithMissingEmail() {
        // Create a user with no email address, reflecting previous behavior

        JdbcScimUserProvisioning noValidateProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder, new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate), new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(), true) {
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
        assertThat(joe.getUserName()).isEqualTo("josephine");
        assertThat(joe.getPrimaryEmail()).isEqualTo("jo@blah.com");
        assertThat(joe.getGivenName()).isEqualTo("Jo");
        assertThat(joe.getFamilyName()).isEqualTo("NewUser");
        assertThat(joe.getVersion()).isOne();
        assertThat(joe.getId()).isEqualTo(joeId);
        assertThat(joe.getGroups()).isNull();
        assertThat(joe.getSalt()).isEqualTo("salt");
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

        assertThat(joe.getId()).isEqualTo(joeId);
        assertThat(joe.getGroups()).isNull();
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

        assertThatThrownBy(() -> jdbcScimUserProvisioning.update(userId, scimUser, currentIdentityZoneId))
                .isInstanceOf(InvalidScimResourceException.class)
                .hasMessage("Cannot change user's origin in update operation.")
                .satisfies(e -> assertThat(((InvalidScimResourceException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void updateWithWrongVersionIsError() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setVersion(1);
        assertThatExceptionOfType(OptimisticLockingFailureException.class).isThrownBy(() -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
    }

    @Test
    void updateWithBadUsernameIsError() {
        ScimUser jo = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        jo.setUserName("jo$ephione");
        assertThatExceptionOfType(InvalidScimResourceException.class).isThrownBy(() -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
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
        assertThat(userAfterUpdate.getUserName()).isEqualTo("jo$ephine");
        assertThat(userAfterUpdate.getOrigin()).isEqualTo(OriginKeys.LDAP);
    }

    @Test
    void canChangePasswordWithoutOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, null, "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertThat(passwordEncoder.matches("koala123$marissa", storedPassword)).isTrue();
    }

    @Test
    void canChangePasswordWithCorrectOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, "joespassword", "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertThat(passwordEncoder.matches("koala123$marissa", storedPassword)).isTrue();
    }

    @Test
    void cannotChangePasswordNonexistentUser() {
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> jdbcScimUserProvisioning.changePassword(joeId, "notjoespassword", "newpassword", currentIdentityZoneId));
    }

    @Test
    void cannotChangePasswordIfOldPasswordDoesntMatch() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.changePassword("9999", null, "newpassword", currentIdentityZoneId));
    }

    @Test
    void canRetrieveExistingUser() {
        ScimUser joe = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertThat(joe).isNotNull();
        assertThat(joe.getId()).isEqualTo(joeId);
        assertThat(joe.getGivenName()).isEqualTo("Joe");
        assertThat(joe.getFamilyName()).isEqualTo("User");
        assertThat(joe.getPrimaryEmail()).isEqualTo("joe@joe.com");
        assertThat(joe.getUserName()).isEqualTo("joe");
        assertThat(joe.getPhoneNumbers().getFirst().getValue()).isEqualTo("+1-222-1234567");
        assertThat(joe.getGroups()).isNull();
    }

    @Test
    void cannotRetrieveNonexistentUser() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.retrieve("9999", currentIdentityZoneId));
    }

    @Test
    void canDeactivateExistingUser() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForList("select * from users where id=? and active=?", tmpUserId, false)).hasSize(1);
        assertThat(deletedUser.isActive()).isFalse();
        assertThat(jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\" and active eq false", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void cannotDeactivateExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        deletedUser.setActive(true);
        assertThatExceptionOfType(ScimResourceAlreadyExistsException.class).isThrownBy(() -> jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId));
    }

    @Test
    void cannotDeactivateNonexistentUser() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
    }

    @Test
    void deactivateWithWrongVersionIsError() {
        assertThatExceptionOfType(OptimisticLockingFailureException.class).isThrownBy(() -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
    }

    @Nested
    class DeactivateOnDeleteDisabled {
        @BeforeEach
        void setUp() {
            jdbcScimUserProvisioning = new JdbcScimUserProvisioning(
                    namedJdbcTemplate,
                    pagingListFactory,
                    passwordEncoder,
                    idzManager,
                    jdbcIdentityZoneProvisioning,
                    filterConverter,
                    joinConverter,
                    new TimeServiceImpl(),
                    false
            );
        }

        @Test
        void canDeleteExistingUserThroughEvent() {
            String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
            ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserId, currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(
                    new EntityDeletedEvent<Object>(user, mock(Authentication.class), currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForList("select * from users where id=?", tmpUserId)).isEmpty();
            assertThat(jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId)).isEmpty();
        }

        @Test
        void canDeleteExistingUser() {
            String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
            jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForList("select * from users where id=?", tmpUserId)).isEmpty();
            assertThat(jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId)).isEmpty();
        }

        @Test
        void canDeleteExistingUserAndThenCreateHimAgain() {
            String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
            ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForList("select * from users where id=?", tmpUserId)).isEmpty();

            deletedUser.setActive(true);
            ScimUser user = jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId);
            assertThat(user).isNotNull();
            assertThat(user.getId()).isNotNull();
            assertThat(tmpUserId).isNotSameAs(user.getId());
            assertThat(jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId)).hasSize(1);
        }

        @Test
        void cannotDeleteNonexistentUser() {
            assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
        }

        @Test
        void deleteWithWrongVersionIsError() {
            assertThatExceptionOfType(OptimisticLockingFailureException.class).isThrownBy(() -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
        }
    }

    @Test
    void createdUserNotVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertThat(verified).isFalse();
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
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

        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("origin", UAA);
        assertThatThrownBy(() -> jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId))
                .isInstanceOf(ScimResourceAlreadyExistsException.class)
                .hasMessage("Username already in use: user@example.com")
                .satisfies(e -> assertThat(((ScimResourceAlreadyExistsException) e).getStatus()).isEqualTo(HttpStatus.CONFLICT))
                .satisfies(e -> assertThat(((ScimResourceAlreadyExistsException) e).getExtraInfo()).isEqualTo(userDetails));
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
        assertThat(scimUser).isNotNull();
        assertThat(scimUser.getSalt()).isEqualTo("salt");
        scimUser.setSalt("newsalt");
        scimUser = jdbcScimUserProvisioning.update(scimUser.getId(), scimUser, currentIdentityZoneId);
        assertThat(scimUser).isNotNull();
        assertThat(scimUser.getSalt()).isEqualTo("newsalt");
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
        assertThat(scimUser).isNotNull();
        assertThat(scimUser.getSalt()).isEqualTo("salt");
        scimUser.setSalt("newsalt");

        String passwordHash = jdbcTemplate.queryForObject("select password from users where id=?", String.class, new Object[]{scimUser.getId()});
        assertThat(passwordHash).isNotNull();

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), null, "password", currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select password from users where id=?", String.class, new Object[]{scimUser.getId()})).isEqualTo(passwordHash);

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), "password", "password", currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select password from users where id=?", String.class, new Object[]{scimUser.getId()})).isEqualTo(passwordHash);

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
        assertThat(userId2).isNotNull()
                .isNotEqualTo("cba09242-aa43-4247-9aa0-b5c75c281f94");
    }

    @Test
    void updatedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertThat(verified).isFalse();
        jdbcScimUserProvisioning.verifyUser(tmpUserIdString, -1, currentIdentityZoneId);
        verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertThat(verified).isTrue();
    }

    @Test
    void createUserWithNoZoneDefaultsToUAAZone() {
        String id = UUID.randomUUID().toString();
        jdbcTemplate.execute(OLD_ADD_USER_SQL_FORMAT.formatted(id, "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890"));
        ScimUser user = jdbcScimUserProvisioning.retrieve(id, IdentityZone.getUaaZoneId());
        assertThat(user.getZoneId()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(user.getSalt()).isNull();
    }

    @Test
    void createUserWithNoZoneFailsIfUserAlreadyExistsInUaaZone() {
        addUser(jdbcTemplate, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890", IdentityZone.getUaaZoneId());
        assertThatExceptionOfType(DuplicateKeyException.class).isThrownBy(() -> jdbcTemplate.execute(OLD_ADD_USER_SQL_FORMAT.formatted(UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890")));
    }

    @Test
    void updatedVersionedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
        user = jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion(), currentIdentityZoneId);
        assertThat(user.isVerified()).isTrue();
    }

    @Test
    void userVerifiedThroughUpdate() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
        user.setVerified(true);
        user = jdbcScimUserProvisioning.update(tmpUserIdString, user, currentIdentityZoneId);
        assertThat(user.isVerified()).isTrue();
    }

    @Test
    void userVerifiedInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.verifyUser("-1-1-1", -1, currentIdentityZoneId));
    }

    @Test
    void userUpdateInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
        user.setVerified(true);
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimUserProvisioning.update("-1-1-1", user, currentIdentityZoneId));
    }

    @Test
    void updatedIncorrectVersionUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertThat(user.isVerified()).isFalse();
        assertThatExceptionOfType(OptimisticLockingFailureException.class).isThrownBy(() -> jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion() + 50, currentIdentityZoneId));
    }

    @Test
    void canRetrieveUsers() {
        assertThat(jdbcScimUserProvisioning.retrieveAll(currentIdentityZoneId)).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void canRetrieveUsersWithFilterExists() {
        assertThat(jdbcScimUserProvisioning.query("username pr", currentIdentityZoneId)).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void canRetrieveUsersWithFilterEquals() {
        assertThat(jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterEqualsDoubleQuote() {
        assertThat(jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterKeyCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertThat(jdbcScimUserProvisioning.query("USERNAME eq \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertThat(jdbcScimUserProvisioning.query("username EQ \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterValueCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertThat(jdbcScimUserProvisioning.query("username eq \"Joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterContains() {
        assertThat(jdbcScimUserProvisioning.query("username co \"e\"", currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithFilterStartsWith() {
        assertThat(jdbcScimUserProvisioning.query("username sw \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithFilterGreater() {
        assertThat(jdbcScimUserProvisioning.query("username gt \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithEmailFilter() {
        assertThat(jdbcScimUserProvisioning.query("emails.value sw \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithGroupsFilter() {
        List<ScimUser> users = jdbcScimUserProvisioning.query("groups.display co \"uaa.user\"", currentIdentityZoneId);
        assertThat(users).hasSize(2);
        for (ScimUser user : users) {
            assertThat(user).isNotNull();
        }
    }

    @Test
    void canRetrieveUsersWithPhoneNumberFilter() {
        assertThat(jdbcScimUserProvisioning.query("phoneNumbers.value sw \"+1-222\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithMetaVersionFilter() {
        assertThat(jdbcScimUserProvisioning.query("userName eq \"joe\" and meta.version eq 0", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void canRetrieveUsersWithMetaDateFilter() {
        assertThat(jdbcScimUserProvisioning.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithBooleanFilter() {
        assertThat(jdbcScimUserProvisioning.query("username pr and active eq true", currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithSortBy() {
        assertThat(jdbcScimUserProvisioning.query("username pr", "username", true, currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void throwsExceptionWhenSortByIncludesThePrivateFieldSalt() {
        assertThatThrownBy(() -> jdbcScimUserProvisioning.query("id pr", "ID,     salt     ", true, currentIdentityZoneId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid sort field: salt");
    }

    @Test
    void canRetrieveUsersWithSortByEmail() {
        assertThat(jdbcScimUserProvisioning.query("username pr", "emails.value", true, currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithFilterBooleanAnd() {
        assertThat(jdbcScimUserProvisioning.query("username pr and emails.value co \".com\"", currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOr() {
        assertThat(jdbcScimUserProvisioning.query("username eq \"joe\" or emails.value co \".com\"", currentIdentityZoneId)).hasSize(2);
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
        assertThat(jdbcScimUserProvisioning.query("username eq \"foo\" or username eq \"joe\"", currentIdentityZoneId)).hasSize(1);
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterField() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> assertThat(jdbcScimUserProvisioning.query("emails.type eq \"bar\"", currentIdentityZoneId)).hasSize(2));
    }

    @Test
    void cannotRetrieveUsersWithIllegalPhoneNumberFilterField() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> assertThat(jdbcScimUserProvisioning.query("phoneNumbers.type eq \"bar\"", currentIdentityZoneId)).hasSize(2));
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterQuotes() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> assertThat(jdbcScimUserProvisioning.query("username eq \"bar", currentIdentityZoneId)).hasSize(2));
    }

    @Test
    void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertThat(password).isNotNull();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username=\"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertThat(password).isNotNull();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username gt \"h\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertThat(password).isNotNull();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username eq \"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertThat(password).isNotNull();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username eq \"joe\"\"; select id from users where id='''; select "
                + SQL_INJECTION_FIELDS + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertThat(password).isNotNull();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username eq \"joe\"'; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe''", currentIdentityZoneId));
    }

    @Test
    void filterEqWithoutQuotesIsRejected() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jdbcScimUserProvisioning.query("username eq joe", currentIdentityZoneId));
    }

    @Test
    void checkPasswordMatches_returnsTrue_PasswordMatches() {
        assertThat(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "joespassword", currentIdentityZoneId)).isTrue();
    }

    @Test
    void checkPasswordMatches_ReturnsFalse_newPasswordSameAsOld() {
        assertThat(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "notjoepassword", currentIdentityZoneId)).isFalse();
    }

    @Test
    void updateLastLogonTime() {
        ScimUser user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        Long timeStampBeforeUpdate = user.getLastLogonTime();
        assertThat(timeStampBeforeUpdate).isNull();
        jdbcScimUserProvisioning.updateLastLogonTime(joeId, currentIdentityZoneId);
        user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertThat(user.getLastLogonTime()).isNotNull();
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
        assertThatThrownBy(() -> {
            for (int i = 1; i < 12; i++) {
                scimUser.setId("user-id-" + i);
                scimUser.setUserName("user" + i + "@example.com");
                scimUser.setPassword(randomString());
                jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
            }
        })
                .isInstanceOf(InvalidScimResourceException.class)
                .hasMessageContaining("The maximum allowed numbers of users: 10 is reached already in Identity Zone");
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setMaxUsers(-1);
    }

    @Test
    void canCreateUserWithValidOrigin() {
        String validOrigin = "validOrigin-" + randomString();
        addIdentityProvider(jdbcTemplate, currentIdentityZoneId, validOrigin);
        String userId = "user-" + randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId + "@example.com");
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
        String invalidOrigin = "invalidOrigin-" + randomString();
        String userId = "user-" + randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId + "@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setOrigin(invalidOrigin);
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(true);
        assertThatThrownBy(() -> jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId))
                .isInstanceOf(InvalidScimResourceException.class)
                .hasMessageContaining("Invalid origin");
        idzManager.getCurrentIdentityZone().getConfig().getUserConfig().setCheckOriginEnabled(false);
    }

    @Test
    void cannotCreateUserWithInvalidIdentityZone() {
        String userId = "user-" + randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId + "@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());

        // arrange zone does not exist
        final String invalidZoneId = "invalidZone-" + randomString();
        when(jdbcIdentityZoneProvisioning.retrieve(invalidZoneId))
                .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));

        assertThatThrownBy(() -> jdbcScimUserProvisioning.create(scimUser, invalidZoneId))
                .isInstanceOf(InvalidScimResourceException.class)
                .hasMessageContaining("Invalid identity zone id");
    }

    @Test
    void cannotUpdateUserWithWrongIdentityZone() {
        String userId = "user-" + randomString();
        ScimUser scimUser = new ScimUser(userId, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(userId + "@example.com");
        scimUser.setEmails(singletonList(email));
        scimUser.setPassword(randomString());
        scimUser.setZoneId("wrongZone-" + randomString());
        assertThatNoException().isThrownBy(() -> {
            jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
        });
        assertThatThrownBy(() -> jdbcScimUserProvisioning.update(userId, scimUser, currentIdentityZoneId))
                .isInstanceOf(ScimResourceNotFoundException.class)
                .hasMessageContaining("does not exist");
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
        String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id, alias_id, alias_zid) values ('%s','%s','%s','%s','%s','%s','%s','%s', %s, %s)".formatted(
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
        String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id, origin) values ('%s','%s','%s','%s','%s','%s','%s','%s', '%s')".formatted(
                scimUser.getId(),
                scimUser.getUserName(),
                scimUser.getPassword(),
                scimUser.getPrimaryEmail(),
                scimUser.getName().getGivenName(),
                scimUser.getName().getFamilyName(),
                scimUser.getPhoneNumbers().getFirst(),
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
