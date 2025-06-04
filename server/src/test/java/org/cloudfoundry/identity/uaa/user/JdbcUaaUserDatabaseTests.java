package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class JdbcUaaUserDatabaseTests {

    private JdbcUaaUserDatabase jdbcUaaUserDatabase;

    private static final String JOE_ID = UUID.randomUUID().toString();
    private static final String MABEL_ID = UUID.randomUUID().toString();
    private static final String ALICE_ID = UUID.randomUUID().toString();
    private static final String BOB_ID = UUID.randomUUID().toString();

    private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, origin, identity_zone_id, created, lastmodified, passwd_lastmodified, passwd_change_required) values (?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private static final String addSaltSql = "update users set salt=? where id=?";

    private String addGroupSql;
    private static final String ADD_MEMBER_SQL = "insert into group_membership (group_id, member_id, member_type, authorities) values (?,?,?,?)";
    private TimeService timeService;
    private IdentityZoneManager mockIdentityZoneManager;
    private Set<SimpleGrantedAuthority> defaultAuthorities;
    private DbUtils dbUtils;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Environment environment;

    @Autowired
    private DatabaseProperties databaseProperties;

    @BeforeEach
    void setUp() throws SQLException {
        defaultAuthorities = UserConfig.DEFAULT_ZONE_GROUPS
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        timeService = mock(TimeService.class);

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        setUpIdentityZone(mockIdentityZoneManager);

        dbUtils = new DbUtils();
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(
                jdbcTemplate,
                timeService,
                databaseProperties,
                mockIdentityZoneManager,
                dbUtils);

        // TODO: Don't need these checks
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", JOE_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", MABEL_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", ALICE_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", BOB_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "userName", "jo@foo.com");

        addUser(JOE_ID, "Joe", "joespassword", true, jdbcTemplate, "zone-the-first");
        addUser(MABEL_ID, "mabel", "mabelspassword", false, jdbcTemplate, "zone-the-first");
        addUser(ALICE_ID, "alice", "alicespassword", false, jdbcTemplate, "zone-the-second");
        addUser(BOB_ID, "bob", "bobspassword", false, jdbcTemplate, "zone-the-bob");

        addGroupSql = "insert into " + dbUtils.getQuotedIdentifier("groups", jdbcTemplate) +
                " (id, displayName, identity_zone_id) values (?,?,?)";
    }

    private static void setUpIdentityZone(IdentityZoneManager mockIdentityZoneManager) {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-first");

        final IdentityZone mockIdentityZone = mock(IdentityZone.class);
        final IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        final UserConfig mockUserConfig = mock(UserConfig.class);

        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        when(mockIdentityZoneConfiguration.getUserConfig()).thenReturn(mockUserConfig);
        when(mockUserConfig.getDefaultGroups()).thenReturn(UserConfig.DEFAULT_ZONE_GROUPS);
        when(mockUserConfig.resultingAllowedGroups()).thenReturn(null); // allow all groups
    }

    @AfterEach
    void tearDown() {
        TestUtils.deleteFrom(jdbcTemplate, "users");
    }

    @Test
    void storeUserInfoWithoutId() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> jdbcUaaUserDatabase.storeUserInfo(null, new UserInfo()));
    }

    @Test
    void storeNullUserInfo() {
        String id = "id";
        jdbcUaaUserDatabase.storeUserInfo(id, null);
        UserInfo info2 = jdbcUaaUserDatabase.getUserInfo(id);
        assertThat(info2.getRoles()).isNull();
        assertThat(info2.getUserAttributes()).isNull();
    }

    @Test
    void storeUserInfo() {
        UserInfo info = new UserInfo();
        String id = "id";
        LinkedMultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add("single", "1");
        userAttributes.add("multi", "2");
        userAttributes.add("multi", "3");
        info.setUserAttributes(userAttributes);
        List<String> roles = new LinkedList<>(Arrays.asList("role1", "role2", "role3"));
        info.setRoles(roles);

        jdbcUaaUserDatabase.storeUserInfo(id, info);
        UserInfo info2 = jdbcUaaUserDatabase.getUserInfo(id);
        assertThat(info2).isEqualTo(info);
        assertThat(info2.getUserAttributes()).isEqualTo(userAttributes);
        assertThat(info2.getRoles()).isEqualTo(roles);

        roles.add("role4");
        userAttributes.add("multi", "4");
        jdbcUaaUserDatabase.storeUserInfo(id, info);
        UserInfo info3 = jdbcUaaUserDatabase.getUserInfo(id);
        assertThat(info3).isEqualTo(info);
        assertThat(info3.getUserAttributes()).isEqualTo(userAttributes);
        assertThat(info3.getRoles()).isEqualTo(roles);
    }

    @Test
    void addedUserHasNoLegacyVerificationBehavior() {
        assertThat(jdbcUaaUserDatabase.retrieveUserById(JOE_ID).isLegacyVerificationBehavior()).isFalse();
        assertThat(jdbcUaaUserDatabase.retrieveUserById(MABEL_ID).isLegacyVerificationBehavior()).isFalse();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        assertThat(jdbcUaaUserDatabase.retrieveUserById(ALICE_ID).isLegacyVerificationBehavior()).isFalse();
    }

    @Test
    void getValidUserSucceeds() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        validateJoe(joe);
        assertThat(joe.getSalt()).isNull();
        assertThat(joe.getPasswordLastModified()).isNotNull()
                .isEqualTo(joe.getCreated());
    }

    @Test
    void getSaltValueWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertThat(joe).isNotNull();
        assertThat(joe.getSalt()).isNull();
        jdbcTemplate.update(addSaltSql, "salt", JOE_ID);
        joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertThat(joe).isNotNull();
        assertThat(joe.getSalt()).isEqualTo("salt");
    }

    @Test
    @DisabledIfProfile("mysql")
    void hsqlPostgresqlCaseSensitive() throws SQLException {
        JdbcTemplate mockJdbcTemplate = mock(JdbcTemplate.class);
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(mockJdbcTemplate, timeService, databaseProperties, mockIdentityZoneManager,
                dbUtils);

        String username = new RandomValueStringGenerator().generate() + "@test.org";

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).queryForObject(eq(DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).query(eq(DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
    }

    @Test
    @EnabledIfProfile("mysql")
    void mysqlCaseInsensitive() throws SQLException {
        JdbcTemplate mockJdbcTemplate = mock(JdbcTemplate.class);
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(mockJdbcTemplate, timeService, databaseProperties, mockIdentityZoneManager,
                dbUtils);
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(mockJdbcTemplate, timeService, databaseProperties, mockIdentityZoneManager,
                dbUtils);

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).queryForObject(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).query(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
    }

    @Test
        // TODO: this should be parameterized
    void getValidUserCaseInsensitive() throws SQLException {
        for (boolean caseInsensitive : Arrays.asList(true, false)) {
            try {
                var dbProps = new DatabaseProperties();
                dbProps.setEnvironment(environment);
                dbProps.setCaseinsensitive(caseInsensitive);
                jdbcUaaUserDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService, dbProps, mockIdentityZoneManager,
                        dbUtils);
                UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("JOE", OriginKeys.UAA);
                validateJoe(joe);
                joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
                validateJoe(joe);
                joe = jdbcUaaUserDatabase.retrieveUserByName("Joe", OriginKeys.UAA);
                validateJoe(joe);
                joe = jdbcUaaUserDatabase.retrieveUserByEmail("joe@test.org", OriginKeys.UAA);
                validateJoe(joe);
                joe = jdbcUaaUserDatabase.retrieveUserByEmail("JOE@TEST.ORG", OriginKeys.UAA);
                validateJoe(joe);
                joe = jdbcUaaUserDatabase.retrieveUserByEmail("Joe@Test.Org", OriginKeys.UAA);
                validateJoe(joe);
            } catch (UsernameNotFoundException x) {
                if (!caseInsensitive) {
                    throw x;
                }
                if (isMySQL(environment)) {
                    throw x;
                }
            }
        }
    }

    private static void validateJoe(UaaUser joe) {
        assertThat(joe).isNotNull();
        assertThat(joe.getId()).isEqualTo(JOE_ID);
        assertThat(joe.getUsername()).isEqualTo("Joe");
        assertThat(joe.getEmail()).isEqualTo("joe@test.org");
        assertThat(joe.getPassword()).isEqualTo("joespassword");
        assertThat(joe.isPasswordChangeRequired()).isTrue();
        assertThat((List<GrantedAuthority>) joe.getAuthorities()).as("authorities does not contain uaa.user").contains(new SimpleGrantedAuthority("uaa.user"));
    }

    @Test
    void getNonExistentUserRaisedNotFoundException() {
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> jdbcUaaUserDatabase.retrieveUserByName("jo", OriginKeys.UAA));
    }

    @Test
    void getUserWithExtraAuthorities() {
        addAuthority("dash.admin", jdbcTemplate, "zone-the-first", JOE_ID);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertThat((List<GrantedAuthority>) joe.getAuthorities()).contains(new SimpleGrantedAuthority("uaa.user"), new SimpleGrantedAuthority("dash.admin"));
    }

    @Test
    void getUserWithMultipleExtraAuthorities() throws SQLException {
        addAuthority("additional", jdbcTemplate, "zone-the-first", JOE_ID);
        addAuthority("anotherOne", jdbcTemplate, "zone-the-first", JOE_ID);
        JdbcTemplate spiedJdbcTemplate = Mockito.spy(jdbcTemplate);
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(spiedJdbcTemplate, timeService, databaseProperties, mockIdentityZoneManager,
                dbUtils);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        verify(spiedJdbcTemplate, times(1)).queryForObject(matches("select .* from users where .*"), eq(jdbcUaaUserDatabase.getMapper()), eq("joe"), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
        List<GrantedAuthority> grantedAuthorities = (List<GrantedAuthority>) joe.getAuthorities();
        assertThat(grantedAuthorities).contains(new SimpleGrantedAuthority("uaa.user"), new SimpleGrantedAuthority("additional"), new SimpleGrantedAuthority("anotherOne"));
    }

    @Test
    void getUserWithNestedAuthoritiesWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);

        List<GrantedAuthority> grantedAuthorities = (List<GrantedAuthority>) joe.getAuthorities();
        defaultAuthorities.forEach(authority ->
                assertThat(grantedAuthorities).contains(authority));

        String directId = new RandomValueStringGenerator().generate();
        String indirectId = new RandomValueStringGenerator().generate();

        jdbcTemplate.update(addGroupSql, directId, "direct", "zone-the-first");
        jdbcTemplate.update(addGroupSql, indirectId, "indirect", "zone-the-first");
        jdbcTemplate.update(ADD_MEMBER_SQL, indirectId, directId, "GROUP", "MEMBER");
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, joe.getId(), "USER", "MEMBER");

        evaluateNestedJoe(jdbcUaaUserDatabase, defaultAuthorities);

        //add a circular group
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, indirectId, "GROUP", "MEMBER");

        evaluateNestedJoe(jdbcUaaUserDatabase, defaultAuthorities);
    }

    @Test
    void updatePreviousAndLastLogonTime() {
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        jdbcUaaUserDatabase.updateLastLogonTime(JOE_ID);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserById(JOE_ID);
        assertThat((long) joe.getLastLogonTime()).isEqualTo(1000L);
        assertThat(joe.getPreviousLogonTime()).isNull();

        when(timeService.getCurrentTimeMillis()).thenReturn(2000L);
        jdbcUaaUserDatabase.updateLastLogonTime(JOE_ID);
        joe = jdbcUaaUserDatabase.retrieveUserById(JOE_ID);
        assertThat((long) joe.getPreviousLogonTime()).isEqualTo(1000L);
        assertThat((long) joe.getLastLogonTime()).isEqualTo(2000L);
    }

    @Test
    void getValidUserInDefaultZoneFromOtherZoneFails() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        // TODO: One @Test should not call another @Test
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(this::getValidUserSucceeds);
    }

    @Test
    void getValidUserInOtherZoneFromOtherZone() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        assertThatNoException().isThrownBy(() -> jdbcUaaUserDatabase.retrieveUserByName("alice", OriginKeys.UAA));
    }

    @Test
    void getValidUserInOtherZoneFromDefaultZoneFails() {
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> jdbcUaaUserDatabase.retrieveUserByName("alice", OriginKeys.UAA));
    }

    @Test
    void retrieveUserByEmail_also_isCaseInsensitive() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByEmail("JOE@test.org", OriginKeys.UAA);
        validateJoe(joe);
        assertThat(joe.getSalt()).isNull();
        assertThat(joe.getPasswordLastModified()).isNotNull()
                .isEqualTo(joe.getCreated());
    }

    @Test
    void null_if_noUserWithEmail() {
        assertThat(jdbcUaaUserDatabase.retrieveUserByEmail("email@doesnot.exist", OriginKeys.UAA)).isNull();
    }

    @Test
    void null_if_userWithEmail_in_differentZone() {
        assertThat(jdbcUaaUserDatabase.retrieveUserByEmail("alice@test.org", OriginKeys.UAA)).isNull();
    }

    @Test
    void maxParameters() {
        int oldValue = jdbcUaaUserDatabase.getMaxSqlParameters();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-bob");

        for (int l : List.of(-1, 10)) {
            jdbcUaaUserDatabase.setMaxSqlParameters(l);
            for (int i = 0; i < 5; i++) {
                addAuthority("testAuth" + l + i, jdbcTemplate, "zone-the-bob", BOB_ID);
            }
            validateBob(5, jdbcUaaUserDatabase.retrieveUserByName("bob", OriginKeys.UAA), l);

            for (int i = 5; i < 10; i++) {
                System.out.println(i);
                addAuthority("testAuth" + l + i, jdbcTemplate, "zone-the-bob", BOB_ID);
            }
            validateBob(10, jdbcUaaUserDatabase.retrieveUserByName("bob", OriginKeys.UAA), l);

            for (int i = 10; i < 15; i++) {
                addAuthority("testAuth" + l + i, jdbcTemplate, "zone-the-bob", BOB_ID);
            }
            validateBob(15, jdbcUaaUserDatabase.retrieveUserByName("bob", OriginKeys.UAA), l);
        }

        jdbcUaaUserDatabase.setMaxSqlParameters(oldValue);
    }

    @Test
    void skipLockedQuery() {
        boolean oldValue = jdbcUaaUserDatabase.isUseSkipLocked();
        jdbcUaaUserDatabase.setUseSkipLocked(true);
        jdbcUaaUserDatabase.init();
        assertThat(DEFAULT_UPDATE_USER_LAST_LOGON).contains("skip locked");
        jdbcUaaUserDatabase.setUseSkipLocked(false);
        jdbcUaaUserDatabase.init();
        assertThat(DEFAULT_UPDATE_USER_LAST_LOGON).doesNotContain("skip locked");
        jdbcUaaUserDatabase.setUseSkipLocked(oldValue);
    }

    private void validateBob(int numberAuths, UaaUser bob, int prefix) {
        int count = 0;
        for (GrantedAuthority s : bob.getAuthorities()) {
            if (s.getAuthority().startsWith("testAuth" + prefix)) {
                count++;
            }
        }
        assertThat(numberAuths).isEqualTo(count);
    }

    private static boolean isMySQL(Environment environment) {
        for (String s : environment.getActiveProfiles()) {
            if (s.contains("mysql")) {
                return true;
            }
        }
        return false;
    }

    private static void evaluateNestedJoe(JdbcUaaUserDatabase db, Set<SimpleGrantedAuthority> defaultAuthorities) {
        UaaUser joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        Set<GrantedAuthority> compareTo = new HashSet<>(defaultAuthorities);
        compareTo.add(new SimpleGrantedAuthority("direct"));
        compareTo.add(new SimpleGrantedAuthority("uaa.user"));
        compareTo.add(new SimpleGrantedAuthority("indirect"));
        List<GrantedAuthority> grantedAuthorities = (List<GrantedAuthority>) joe.getAuthorities();
        compareTo.forEach(authority -> assertThat(grantedAuthorities).contains(authority));
    }

    private static void addUser(
            final String id,
            final String name,
            final String password,
            final boolean requiresPasswordChange,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        final Timestamp t = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(
                addUserSql,
                id,
                name,
                password,
                name.toLowerCase() + "@test.org",
                name,
                name,
                "",
                OriginKeys.UAA,
                zoneId,
                t,
                t,
                t,
                requiresPasswordChange);
    }

    private void addAuthority(
            final String authority,
            final JdbcTemplate jdbcTemplate,
            final String zoneId,
            final String userId) {
        final String id = new RandomValueStringGenerator().generate();
        jdbcTemplate.update(addGroupSql, id, authority, zoneId);
        jdbcTemplate.update(ADD_MEMBER_SQL, id, userId, "USER", "MEMBER");
    }

}
