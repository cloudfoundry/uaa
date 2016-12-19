/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
import static org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase.DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JdbcUaaUserDatabaseTests extends JdbcTestBase {

    private JdbcUaaUserDatabase db;

    private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

    private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, origin, identity_zone_id, created, lastmodified, passwd_lastmodified, passwd_change_required) values (?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private static final String getAuthoritiesSql = "select authorities from users where id=?";

    private static final String addAuthoritySql = "update users set authorities=? where id=?";

    private static final String addSaltSql = "update users set salt=? where id=?";

    private static final String MABEL_ID = UUID.randomUUID().toString();

    private static final String ALICE_ID = UUID.randomUUID().toString();

    private IdentityZone otherIdentityZone;

    private JdbcTemplate template;
    public static final String ADD_GROUP_SQL = "insert into groups (id, displayName, identity_zone_id) values (?,?,?)";
    public static final String ADD_MEMBER_SQL = "insert into group_membership (group_id, member_id, member_type, authorities) values (?,?,?,?)";
    private TimeService timeService;

    private void addUser(String id, String name, String password, boolean requiresPasswordChange) {
        TestUtils.assertNoSuchUser(template, "id", id);
        Timestamp t = new Timestamp(System.currentTimeMillis());
        template.update(addUserSql, id, name, password, name.toLowerCase() + "@test.org", name, name, "", OriginKeys.UAA, IdentityZoneHolder.get().getId(),t,t,t,requiresPasswordChange);
    }

    private void addAuthority(String authority, String userId) {
        String id = new RandomValueStringGenerator().generate();
        jdbcTemplate.update(ADD_GROUP_SQL, id, authority, IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_MEMBER_SQL, id, userId, "USER", "MEMBER");
    }

    @Before
    public void initializeDb() throws Exception {
        timeService = mock(TimeService.class);
        IdentityZoneHolder.clear();
        otherIdentityZone = new IdentityZone();
        otherIdentityZone.setId("some-other-zone-id");

        template = new JdbcTemplate(dataSource);

        db = new JdbcUaaUserDatabase(template, timeService);
        db.setDefaultAuthorities(Collections.singleton("uaa.user"));

        TestUtils.assertNoSuchUser(template, "id", JOE_ID);
        TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
        TestUtils.assertNoSuchUser(template, "id", ALICE_ID);
        TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

        addUser(JOE_ID, "Joe", "joespassword", true);
        addUser(MABEL_ID, "mabel", "mabelspassword", false);
        IdentityZoneHolder.set(otherIdentityZone);
        addUser(ALICE_ID, "alice", "alicespassword", false);
        IdentityZoneHolder.clear();
    }

    @After
    public void clearDb() throws Exception {
        IdentityZoneHolder.clear();
        TestUtils.deleteFrom(dataSource, "users");
    }


    @Test(expected = NullPointerException.class)
    public void testStoreUserInfoWithoutId() {
        db.storeUserInfo(null, new UserInfo());
    }

    @Test
    public void testStoreNullUserInfo() {
        String id = "id";
        db.storeUserInfo(id, null);
        UserInfo info2 = db.getUserInfo(id);
        assertEquals(id, info2.getUserId());
        assertEquals(1, info2.size());
    }

    @Test
    public void testStoreUserInfoOverridesID() {
        UserInfo info = new UserInfo();
        String id = "id", id1 = id + "1";
        info.setUserId(id);
        info.put("family_name","Somelastname");
        info.put("given_name","Somefirstname");
        db.storeUserInfo(id1, info);
        UserInfo info2 = db.getUserInfo(id1);
        info.setUserId(id1);
        assertEquals(info, info2);
    }


    @Test
    public void testStoreUserInfo() {
        UserInfo info = new UserInfo();
        String id = "id";
        info.setUserId(id);
        info.put("family_name","Somelastname");
        info.put("given_name","Somefirstname");
        db.storeUserInfo(id, info);
        UserInfo info2 = db.getUserInfo(id);
        assertEquals(info, info2);

        info.put("new","value");
        db.storeUserInfo(id, info);
        UserInfo info3  = db.getUserInfo(id);
        assertEquals(info, info3);
    }

    @Test
    public void addedUserHasNoLegacyVerificationBehavior() {
        assertFalse(db.retrieveUserById(JOE_ID).isLegacyVerificationBehavior());
        assertFalse(db.retrieveUserById(MABEL_ID).isLegacyVerificationBehavior());
        IdentityZoneHolder.set(otherIdentityZone);
        assertFalse(db.retrieveUserById(ALICE_ID).isLegacyVerificationBehavior());
    }

    @Test
    public void getValidUserSucceeds() {
        UaaUser joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    public void getSaltValueWorks() {
        UaaUser joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertNull(joe.getSalt());
        template.update(addSaltSql, "salt", JOE_ID);
        joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        assertNotNull(joe);
        assertEquals("salt", joe.getSalt());
    }

    public boolean isMySQL() {
        for (String s : environment.getActiveProfiles()) {
            if (s.contains("mysql")) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void is_the_right_query_used() throws Exception {
        JdbcTemplate template = mock(JdbcTemplate.class);
        db.setJdbcTemplate(template);

        String username = new RandomValueStringGenerator().generate()+"@test.org";

        db.retrieveUserByName(username, OriginKeys.UAA);
        verify(template).queryForObject(eq(DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY), eq(db.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
        db.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(template).query(eq(DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(db.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));

        db.setCaseInsensitive(true);

        db.retrieveUserByName(username, OriginKeys.UAA);
        verify(template).queryForObject(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY), eq(db.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
        db.retrieveUserByEmail(username, OriginKeys.UAA);
        verify(template).query(eq(DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY), eq(db.getMapper()), eq(username.toLowerCase()), eq(true), eq(OriginKeys.UAA), eq(OriginKeys.UAA));
    }

    @Test
    public void getValidUserCaseInsensitive() {
        for (boolean caseInsensitive : Arrays.asList(true,false)) {
            try {
                db.setCaseInsensitive(caseInsensitive);
                UaaUser joe = db.retrieveUserByName("JOE", OriginKeys.UAA);
                validateJoe(joe);
                joe = db.retrieveUserByName("joe", OriginKeys.UAA);
                validateJoe(joe);
                joe = db.retrieveUserByName("Joe", OriginKeys.UAA);
                validateJoe(joe);
                joe = db.retrieveUserByEmail("joe@test.org", OriginKeys.UAA);
                validateJoe(joe);
                joe = db.retrieveUserByEmail("JOE@TEST.ORG", OriginKeys.UAA);
                validateJoe(joe);
                joe = db.retrieveUserByEmail("Joe@Test.Org", OriginKeys.UAA);
                validateJoe(joe);
            } catch (UsernameNotFoundException x) {
                if (!caseInsensitive) {
                    throw x;
                }
                if (isMySQL()) {
                    throw x;
                }
            }
        }
    }

    protected void validateJoe(UaaUser joe) {
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
        db.retrieveUserByName("jo", OriginKeys.UAA);
    }

    @Test
    public void getUserWithExtraAuthorities() {
        addAuthority("dash.admin", JOE_ID);
        UaaUser joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        assertTrue("authorities does not contain uaa.user",
                        joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
        assertTrue("authorities does not contain dash.admin",
                        joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")));
    }

    @Test
    public void getUserWithNestedAuthoritiesWorks() {
        UaaUser joe = db.retrieveUserByName("joe", OriginKeys.UAA);
        assertThat(joe.getAuthorities(),
                   containsInAnyOrder(
                       new SimpleGrantedAuthority("uaa.user")
                   )
        );

        String directId = new RandomValueStringGenerator().generate();
        String indirectId = new RandomValueStringGenerator().generate();

        jdbcTemplate.update(ADD_GROUP_SQL, directId, "direct", IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_GROUP_SQL, indirectId, "indirect", IdentityZoneHolder.get().getId());
        jdbcTemplate.update(ADD_MEMBER_SQL, indirectId, directId, "GROUP", "MEMBER");
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, joe.getId(), "USER", "MEMBER");


        evaluateNestedJoe();

        //add a circular group
        jdbcTemplate.update(ADD_MEMBER_SQL, directId, indirectId, "GROUP", "MEMBER");

        evaluateNestedJoe();
    }

    protected void evaluateNestedJoe() {
        UaaUser joe;
        joe = db.retrieveUserByName("joe", OriginKeys.UAA);

        assertThat(joe.getAuthorities(),
                   containsInAnyOrder(
                       new SimpleGrantedAuthority("direct"),
                       new SimpleGrantedAuthority("uaa.user"),
                       new SimpleGrantedAuthority("indirect")
                   )
        );
    }

    @Test
    public void testUpdateLastLogonTime() {
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        db.updateLastLogonTime(JOE_ID);
        UaaUser joe = db.retrieveUserById(JOE_ID);
        assertEquals(joe.getLastLogonTime(), 1000L);

        when(timeService.getCurrentTimeMillis()).thenReturn(2000L);
        db.updateLastLogonTime(JOE_ID);
        joe = db.retrieveUserById(JOE_ID);
        assertEquals(joe.getLastLogonTime(), 2000L);
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
        db.retrieveUserByName("alice", OriginKeys.UAA);
    }

    @Test
    public void retrieveUserByEmail_also_isCaseInsensitive() {
        UaaUser joe = db.retrieveUserByEmail("JOE@test.org", OriginKeys.UAA);
        validateJoe(joe);
        assertNull(joe.getSalt());
        assertNotNull(joe.getPasswordLastModified());
        assertEquals(joe.getCreated(), joe.getPasswordLastModified());
    }

    @Test
    public void null_if_noUserWithEmail() {
        assertNull(db.retrieveUserByEmail("email@doesnot.exist", OriginKeys.UAA));
    }

    @Test
    public void null_if_userWithEmail_in_differentZone(){
        assertNull(db.retrieveUserByEmail("alice@test.org", OriginKeys.UAA));
    }
}
