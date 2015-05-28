/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.UUID;

import static org.junit.Assert.*;

public class JdbcUaaUserDatabaseTests extends JdbcTestBase {

    private JdbcUaaUserDatabase db;

    private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

    private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, origin, identity_zone_id) values (?,?,?,?,?,?,?,?,?)";

    private static final String getAuthoritiesSql = "select authorities from users where id=?";

    private static final String addAuthoritySql = "update users set authorities=? where id=?";

    private static final String addSaltSql = "update users set salt=? where id=?";

    private static final String MABEL_ID = UUID.randomUUID().toString();

    private static final String ALICE_ID = UUID.randomUUID().toString();

    private IdentityZone otherIdentityZone;


    private JdbcTemplate template;

    private void addUser(String id, String name, String password) {
        TestUtils.assertNoSuchUser(template, "id", id);
        template.update(addUserSql, id, name, password, name.toLowerCase() + "@test.org", name, name, "", Origin.UAA, IdentityZoneHolder.get().getId());
    }

    private void addAuthority(String authority, String userId) {
        String authorities = template.queryForObject(getAuthoritiesSql, String.class, userId);
        authorities = authorities == null ? authority : authorities + "," + authority;
        template.update(addAuthoritySql, authorities, userId);
    }

    @Before
    public void initializeDb() throws Exception {

        otherIdentityZone = new IdentityZone();
        otherIdentityZone.setId("some-other-zone-id");

        template = new JdbcTemplate(dataSource);

        db = new JdbcUaaUserDatabase(template);
        db.setDefaultAuthorities(Collections.singleton("uaa.user"));

        TestUtils.assertNoSuchUser(template, "id", JOE_ID);
        TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
        TestUtils.assertNoSuchUser(template, "id", ALICE_ID);
        TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

        addUser(JOE_ID, "Joe", "joespassword");
        addUser(MABEL_ID, "mabel", "mabelspassword");
        IdentityZoneHolder.set(otherIdentityZone);
        addUser(ALICE_ID, "alice", "alicespassword");
        IdentityZoneHolder.clear();
    }

    @After
    public void clearDb() throws Exception {
        IdentityZoneHolder.clear();
        TestUtils.deleteFrom(dataSource, "users");
    }

    @Test
    public void getValidUserSucceeds() {
        UaaUser joe = db.retrieveUserByName("joe",Origin.UAA);
        assertNotNull(joe);
        assertEquals(JOE_ID, joe.getId());
        assertEquals("Joe", joe.getUsername());
        assertEquals("joe@test.org", joe.getEmail());
        assertEquals("joespassword", joe.getPassword());
        assertTrue("authorities does not contain uaa.user",
            joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
        assertNull(joe.getSalt());
    }

    @Test
    public void getSaltValueWorks() {
        UaaUser joe = db.retrieveUserByName("joe",Origin.UAA);
        assertNotNull(joe);
        assertNull(joe.getSalt());
        template.update(addSaltSql, "salt", JOE_ID);
        joe = db.retrieveUserByName("joe",Origin.UAA);
        assertNotNull(joe);
        assertEquals("salt", joe.getSalt());
    }

    @Test
    public void getValidUserCaseInsensitive() {
        UaaUser joe = db.retrieveUserByName("JOE", Origin.UAA);
        assertNotNull(joe);
        assertEquals(JOE_ID, joe.getId());
        assertEquals("Joe", joe.getUsername());
        assertEquals("joe@test.org", joe.getEmail());
        assertEquals("joespassword", joe.getPassword());
        assertTrue("authorities does not contain uaa.user",
                        joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void getNonExistentUserRaisedNotFoundException() {
        db.retrieveUserByName("jo", Origin.UAA);
    }

    @Test
    public void getUserWithExtraAuthorities() {
        addAuthority("dash.admin", JOE_ID);
        UaaUser joe = db.retrieveUserByName("joe", Origin.UAA);
        assertTrue("authorities does not contain uaa.user",
                        joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
        assertTrue("authorities does not contain dash.admin",
                        joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")));
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
        UaaUser alice = db.retrieveUserByName("alice",Origin.UAA);
        assertNotNull(alice);
        assertEquals(ALICE_ID, alice.getId());
        assertEquals("alice", alice.getUsername());
        assertEquals("alice@test.org", alice.getEmail());
        assertEquals("alicespassword", alice.getPassword());
        assertTrue("authorities does not contain uaa.user",
                        alice.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
    }

}
