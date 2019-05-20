package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;

import java.sql.Timestamp;
import java.util.*;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.*;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class JdbcUaaUserDatabaseTests extends JdbcTestBase {

    private JdbcUaaUserDatabase jdbcUaaUserDatabase;

    private static final String JOE_ID = UUID.randomUUID().toString();
    private static final String MABEL_ID = UUID.randomUUID().toString();
    private static final String ALICE_ID = UUID.randomUUID().toString();

    private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, origin, identity_zone_id, created, lastmodified, passwd_lastmodified, passwd_change_required) values (?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private static final String addSaltSql = "update users set salt=? where id=?";

    private IdentityZone otherIdentityZone;

    private static final String ADD_GROUP_SQL = "insert into groups (id, displayName, identity_zone_id) values (?,?,?)";
    private static final String ADD_MEMBER_SQL = "insert into group_membership (group_id, member_id, member_type, authorities) values (?,?,?,?)";
    private TimeService timeService;
    private Set<SimpleGrantedAuthority> defaultAuthorities;

    @Before
    public void initializeDb() {
        defaultAuthorities = UserConfig.DEFAULT_ZONE_GROUPS
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        timeService = mock(TimeService.class);
        IdentityZoneHolder.clear();
        otherIdentityZone = new IdentityZone();
        otherIdentityZone.setId("some-other-zone-id");

        jdbcUaaUserDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService);

        TestUtils.assertNoSuchUser(jdbcTemplate, "id", JOE_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", MABEL_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", ALICE_ID);
        TestUtils.assertNoSuchUser(jdbcTemplate, "userName", "jo@foo.com");

        addUser(JOE_ID, "Joe", "joespassword", true, jdbcTemplate);
        addUser(MABEL_ID, "mabel", "mabelspassword", false, jdbcTemplate);
        IdentityZoneHolder.set(otherIdentityZone);
        addUser(ALICE_ID, "alice", "alicespassword", false, jdbcTemplate);
        IdentityZoneHolder.clear();
    }

    @After
    public void clearDb() {
        IdentityZoneHolder.clear();
        TestUtils.deleteFrom(jdbcTemplate, "users");
    }

    @Test(expected = NullPointerException.class)
    public void storeUserInfoWithoutId() {
        jdbcUaaUserDatabase.storeUserInfo(null, new UserInfo());
    }

    @Test
    public void storeNullUserInfo() {
        String id = "id";
        jdbcUaaUserDatabase.storeUserInfo(id, null);
        UserInfo info2 = jdbcUaaUserDatabase.getUserInfo(id);
        assertNull(info2.getRoles());
        assertNull(info2.getUserAttributes());
    }

    @Test
    public void storeUserInfo() {
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
    public void addedUserHasNoLegacyVerificationBehavior() {
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(JOE_ID).isLegacyVerificationBehavior());
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(MABEL_ID).isLegacyVerificationBehavior());
        IdentityZoneHolder.set(otherIdentityZone);
        assertFalse(jdbcUaaUserDatabase.retrieveUserById(ALICE_ID).isLegacyVerificationBehavior());
    }

    @Test
    public void getValidUserSucceeds() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    public void getSaltValueWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertNull(joe.getSalt());
        jdbcTemplate.update(addSaltSql, "salt", JOE_ID);
        joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertEquals("salt", joe.getSalt());
    }

    @Test
    public void is_the_right_query_used() {
        JdbcTemplate template = mock(JdbcTemplate.class);
        jdbcUaaUserDatabase.setJdbcTemplate(template);

        String username = new RandomValueStringGenerator().generate() + "@test.org";

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(template).queryForObject(eq(DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(template).query(eq(DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));

        jdbcUaaUserDatabase.setCaseInsensitive(true);

        jdbcUaaUserDatabase.retrieveUserByName(username, OriginKeys.UAA);
        verify(template).queryForObject(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
        jdbcUaaUserDatabase.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(template).query(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(jdbcUaaUserDatabase.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
    }

    @Test
    public void getValidUserCaseInsensitive() {
        for (boolean caseInsensitive : Arrays.asList(true, false)) {
            try {
                jdbcUaaUserDatabase.setCaseInsensitive(caseInsensitive);
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

    private void validateJoe(UaaUser joe) {
        assertNotNull(joe);
        assertEquals(JOE_ID, joe.getId());
        assertEquals("Joe", joe.getUsername());
        assertEquals("joe@test.org", joe.getEmail());
        assertEquals("joespassword", joe.getPassword());
        assertEquals(true, joe.isPasswordChangeRequired());
        assertTrue("authorities does not contain uaa.user",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void getNonExistentUserRaisedNotFoundException() {
        jdbcUaaUserDatabase.retrieveUserByName("jo", OriginKeys.UAA);
    }

    @Test
    public void getUserWithExtraAuthorities() {
        addAuthority("dash.admin", jdbcTemplate);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        assertTrue("authorities does not contain uaa.user",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
        assertTrue("authorities does not contain dash.admin",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")));
    }

    @Test
    public void getUserWithMultipleExtraAuthorities() {
        addAuthority("additional", jdbcTemplate);
        addAuthority("anotherOne", jdbcTemplate);
        JdbcTemplate spy = Mockito.spy(jdbcTemplate);
        jdbcUaaUserDatabase.setJdbcTemplate(spy);
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);
        verify(spy, times(2)).queryForList(anyString(), ArgumentMatchers.<String>any());
        assertTrue("authorities does not contain uaa.user",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
        assertTrue("authorities does not contain additional",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("additional")));
        assertTrue("authorities does not contain anotherOne",
                joe.getAuthorities().contains(new SimpleGrantedAuthority("anotherOne")));
    }

    @Test
    public void getUserWithNestedAuthoritiesWorks() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByName("joe", OriginKeys.UAA);

        assertThat(joe.getAuthorities(),
                containsInAnyOrder(
                        defaultAuthorities
                                .toArray(new SimpleGrantedAuthority[0])
                )
        );

        String directId = new RandomValueStringGenerator().generate();
        String indirectId = new RandomValueStringGenerator().generate();

        jdbcTemplate.update(ADD_GROUP_SQL, directId, "direct", IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_GROUP_SQL, indirectId, "indirect", IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_MEMBER_SQL, indirectId, directId, "GROUP", "MEMBER");
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, joe.getId(), "USER", "MEMBER");


        evaluateNestedJoe(jdbcUaaUserDatabase, defaultAuthorities);

        //add a circular group
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, indirectId, "GROUP", "MEMBER");

        evaluateNestedJoe(jdbcUaaUserDatabase, defaultAuthorities);
    }

    @Test
    public void updatePreviousAndLastLogonTime() {
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

    @Test(expected = UsernameNotFoundException.class)
    public void getValidUserInDefaultZoneFromOtherZoneFails() {
        IdentityZoneHolder.set(otherIdentityZone);
        getValidUserSucceeds();
        fail("Should have thrown an exception.");
    }

    @Test
    public void getValidUserInOtherZoneFromOtherZone() {
        IdentityZoneHolder.set(otherIdentityZone);
        getValidUserInOtherZoneFromDefaultZoneFails();
    }

    @Test(expected = UsernameNotFoundException.class)
    public void getValidUserInOtherZoneFromDefaultZoneFails() {
        jdbcUaaUserDatabase.retrieveUserByName("alice", OriginKeys.UAA);
    }

    @Test
    public void retrieveUserByEmail_also_isCaseInsensitive() {
        UaaUser joe = jdbcUaaUserDatabase.retrieveUserByEmail("JOE@test.org", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    public void null_if_noUserWithEmail() {
        assertNull(jdbcUaaUserDatabase.retrieveUserByEmail("email@doesnot.exist", OriginKeys.UAA));
    }

    @Test
    public void null_if_userWithEmail_in_differentZone() {
        assertNull(jdbcUaaUserDatabase.retrieveUserByEmail("alice@test.org", OriginKeys.UAA));
    }

    private static boolean isMySQL(MockEnvironment environment) {
        for (String s : environment.getActiveProfiles()) {
            if (s.contains("mysql")) {
                return true;
            }
        }
        return false;
    }

    private static void evaluateNestedJoe(JdbcUaaUserDatabase db, Set<SimpleGrantedAuthority> defaultAuthorities) {
        UaaUser joe;
        joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        Set<GrantedAuthority> compareTo = new HashSet<>(defaultAuthorities);
        compareTo.add(new SimpleGrantedAuthority("direct"));
        compareTo.add(new SimpleGrantedAuthority("uaa.user"));
        compareTo.add(new SimpleGrantedAuthority("indirect"));
        assertThat(joe.getAuthorities(), containsInAnyOrder(compareTo.toArray(new SimpleGrantedAuthority[0])));
    }

    private static void addUser(
            final String id,
            final String name,
            final String password,
            final boolean requiresPasswordChange,
            final JdbcTemplate jdbcTemplate) {
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
                IdentityZoneHolder.get().getId(),
                t,
                t,
                t,
                requiresPasswordChange);
    }

    private static void addAuthority(String authority, JdbcTemplate jdbcTemplate) {
        final String id = new RandomValueStringGenerator().generate();
        jdbcTemplate.update(ADD_GROUP_SQL, id, authority, IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_MEMBER_SQL, id, JdbcUaaUserDatabaseTests.JOE_ID, "USER", "MEMBER");
    }

}
