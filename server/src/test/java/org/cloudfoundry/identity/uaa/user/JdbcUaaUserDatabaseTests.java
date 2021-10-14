package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;

import java.sql.Timestamp;
import java.util.*;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@WithDatabaseContext
class JdbcUaaUserDatabaseTests {

    private JdbcUaaUserDatabase jdbcUaaUserDatabase;

    private static final String JOE_ID = UUID.randomUUID().toString();
    private static final String MABEL_ID = UUID.randomUUID().toString();
    private static final String ALICE_ID = UUID.randomUUID().toString();
    private static final String BOB_ID = UUID.randomUUID().toString();

    private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, origin, identity_zone_id, created, lastmodified, passwd_lastmodified, passwd_change_required) values (?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private static final String addSaltSql = "update users set salt=? where id=?";

    private static final String ADD_GROUP_SQL = "insert into groups (id, displayName, identity_zone_id) values (?,?,?)";
    private static final String ADD_MEMBER_SQL = "insert into group_membership (group_id, member_id, member_type, authorities) values (?,?,?,?)";
    private TimeService timeService;
    private IdentityZoneManager mockIdentityZoneManager;
    private Set<SimpleGrantedAuthority> defaultAuthorities;
    private DatabaseUrlModifier databaseUrlModifier;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Environment environment;

    @BeforeEach
    void setUp() {
        defaultAuthorities = UserConfig.DEFAULT_ZONE_GROUPS
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        timeService = mock(TimeService.class);

        databaseUrlModifier = new DatabaseUrlModifier(Vendor.unknown, ""); //Do not mock, so it works for all databases in Unit tests

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        setUpIdentityZone(mockIdentityZoneManager);

        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(
                jdbcTemplate,
                timeService,
                false,
                mockIdentityZoneManager,
                databaseUrlModifier);

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
    }

    @AfterEach
    void tearDown() {
        TestUtils.deleteFrom(jdbcTemplate, "users");
    }

    @Test
    void storeUserInfoWithoutId() {
        assertThrows(NullPointerException.class, () -> jdbcUaaUserDatabase.storeUserInfo(null, new UserInfo()));
    }

    @Test
    void storeNullUserInfo() {
        String id = "id";
        jdbcUaaUserDatabase.storeUserInfo(id, null);
        UserInfo info2 = jdbcUaaUserDatabase.getUserInfo(id);
        assertNull(info2.getRoles());
        assertNull(info2.getUserAttributes());
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
        assertEquals(info, info2);
        assertEquals(userAttributes, info2.getUserAttributes());
        assertEquals(roles, info2.getRoles());

        roles.add("role4");
        userAttributes.add("multi", "4");
        jdbcUaaUserDatabase.storeUserInfo(id, info);
        UserInfo info3 = jdbcUaaUserDatabase.getUserInfo(id);
        assertEquals(info, info3);
        assertEquals(userAttributes, info3.getUserAttributes());
        assertEquals(roles, info3.getRoles());
    }

    @Test
    void addedUserHasNoLegacyVerificationBehavior() {
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(JOE_ID).isLegacyVerificationBehavior());
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(MABEL_ID).isLegacyVerificationBehavior());
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(ALICE_ID).isLegacyVerificationBehavior());
    }

    @Test
    void getValidUserSucceeds() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    void getSaltValueWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertNull(joe.getSalt());
        jdbcTemplate.update(addSaltSql, "salt", JOE_ID);
        joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertEquals("salt", joe.getSalt());
    }

    @Test
    void is_the_right_query_used() {
        JdbcTemplate mockJdbcTemplate = mock(JdbcTemplate.class);
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(mockJdbcTemplate, timeService, false, mockIdentityZoneManager,
                databaseUrlModifier);

        String username = new RandomValueStringGenerator().generate() + "@test.org";

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).queryForObject(eq(DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).query(eq(DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));

        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(mockJdbcTemplate, timeService, true, mockIdentityZoneManager,
                databaseUrlModifier);

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).queryForObject(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(mockJdbcTemplate).query(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq("zone-the-first"));
    }

    @Test
    // TODO: this should be parameterized
    void getValidUserCaseInsensitive() {
        for (boolean caseInsensitive : Arrays.asList(true, false)) {
            try {
                jdbcUaaUserDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService, caseInsensitive, mockIdentityZoneManager,
                        databaseUrlModifier);
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
        assertNotNull(joe);
        assertEquals(JOE_ID, joe.getId());
        assertEquals("Joe", joe.getUsername());
        assertEquals("joe@test.org", joe.getEmail());
        assertEquals("joespassword", joe.getPassword());
        assertTrue(joe.isPasswordChangeRequired());
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")),
                "authorities does not contain uaa.user");
    }

    @Test
    void getNonExistentUserRaisedNotFoundException() {
        assertThrows(UsernameNotFoundException.class, () -> jdbcUaaUserDatabase.retrieveUserByName("jo", OriginKeys.UAA));
    }

    @Test
    void getUserWithExtraAuthorities() {
        addAuthority("dash.admin", jdbcTemplate, "zone-the-first", JOE_ID);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")),
                "authorities does not contain uaa.user");
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")),
                "authorities does not contain dash.admin");
    }

    @Test
    void getUserWithMultipleExtraAuthorities() {
        addAuthority("additional", jdbcTemplate, "zone-the-first", JOE_ID);
        addAuthority("anotherOne", jdbcTemplate, "zone-the-first", JOE_ID);
        JdbcTemplate spiedJdbcTemplate = Mockito.spy(jdbcTemplate);
        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(spiedJdbcTemplate, timeService, false, mockIdentityZoneManager,
                databaseUrlModifier);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        verify(spiedJdbcTemplate, times(2)).queryForList(anyString(), ArgumentMatchers.<String>any());
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")),
                "authorities does not contain uaa.user");
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("additional")),
                "authorities does not contain additional");
        assertTrue(joe.getAuthorities().contains(new SimpleGrantedAuthority("anotherOne")),
                "authorities does not contain anotherOne");
    }

    @Test
    void getUserWithNestedAuthoritiesWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);

        defaultAuthorities.forEach(authority ->
                assertThat(joe.getAuthorities().contains(authority), is(true)));

        String directId = new RandomValueStringGenerator().generate();
        String indirectId = new RandomValueStringGenerator().generate();

        jdbcTemplate.update(ADD_GROUP_SQL, directId, "direct", "zone-the-first");
        jdbcTemplate.update(ADD_GROUP_SQL, indirectId, "indirect", "zone-the-first");
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
        assertEquals((long) joe.getLastLogonTime(), 1000L);
        assertNull(joe.getPreviousLogonTime());

        when(timeService.getCurrentTimeMillis()).thenReturn(2000L);
        jdbcUaaUserDatabase.updateLastLogonTime(JOE_ID);
        joe = jdbcUaaUserDatabase.retrieveUserById(JOE_ID);
        assertEquals((long) joe.getPreviousLogonTime(), 1000L);
        assertEquals((long) joe.getLastLogonTime(), 2000L);
    }

    @Test
    void getValidUserInDefaultZoneFromOtherZoneFails() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        // TODO: One @Test should not call another @Test
        assertThrows(UsernameNotFoundException.class, this::getValidUserSucceeds);
    }

    @Test
    void getValidUserInOtherZoneFromOtherZone() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-second");
        assertDoesNotThrow(() -> jdbcUaaUserDatabase.retrieveUserByName("alice", OriginKeys.UAA));
    }

    @Test
    void getValidUserInOtherZoneFromDefaultZoneFails() {
        assertThrows(UsernameNotFoundException.class, () -> jdbcUaaUserDatabase.retrieveUserByName("alice", OriginKeys.UAA));
    }

    @Test
    void retrieveUserByEmail_also_isCaseInsensitive() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByEmail("JOE@test.org", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    void null_if_noUserWithEmail() {
        assertNull(jdbcUaaUserDatabase.retrieveUserByEmail("email@doesnot.exist", OriginKeys.UAA));
    }

    @Test
    void null_if_userWithEmail_in_differentZone() {
        assertNull(jdbcUaaUserDatabase.retrieveUserByEmail("alice@test.org", OriginKeys.UAA));
    }

    @Test
    void testMaxParameters() {
        int oldValue = jdbcUaaUserDatabase.getMaxSqlParameters();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("zone-the-bob");

        for (int l: List.of(-1, 10)) {
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

    private void validateBob(int numberAuths, UaaUser bob, int prefix) {
        int count = 0;
        for (GrantedAuthority s: bob.getAuthorities()) {
            if (s.getAuthority().startsWith("testAuth" + prefix)) count++;
        }
        Assert.assertEquals(count, numberAuths);
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
        compareTo.forEach(authority ->
                assertThat(joe.getAuthorities().contains(authority), is(true)));
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

    private static void addAuthority(
            final String authority,
            final JdbcTemplate jdbcTemplate,
            final String zoneId,
            final String userId) {
        final String id = new RandomValueStringGenerator().generate();
        jdbcTemplate.update(ADD_GROUP_SQL, id, authority, zoneId);
        jdbcTemplate.update(ADD_MEMBER_SQL, id, userId, "USER", "MEMBER");
    }

}
