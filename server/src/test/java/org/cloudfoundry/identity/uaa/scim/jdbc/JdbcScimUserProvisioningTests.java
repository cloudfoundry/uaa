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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrapTests;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class JdbcScimUserProvisioningTests extends JdbcTestBase {

    private JdbcScimUserProvisioning db;
    private JdbcIdentityProviderProvisioning providerDb;
    private JdbcIdentityZoneProvisioning zoneDb;

    private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

    private static final String MABEL_ID = UUID.randomUUID().toString();

    private static final String SQL_INJECTION_FIELDS = "password,version,created,lastModified,username,email,givenName,familyName";

    private static final String ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id) values ('%s','%s','%s','%s','%s', '%s', '%s', '%s')";

    private static final String OLD_ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values ('%s','%s','%s','%s','%s', '%s', '%s')";

    private static final String DELETE_USER_SQL_FORMAT = "delete from users where id='%s'";

    private static final String VERIFY_USER_SQL_FORMAT = "select verified from users where id=?";

    private static final String INSERT_MEMBERSHIP = "insert into group_membership (group_id, member_id, member_type,authorities,added, origin, identity_zone_id) values (?,?,?,?,?,?,?)";

    private int existingUserCount = 0;

    private String defaultIdentityProviderId;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private JdbcPagingListFactory pagingListFactory;

    @Before
    public void initJdbcScimUserProvisioningTests() throws Exception {
        pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        db = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory);
        zoneDb = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        providerDb = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        SimpleSearchQueryConverter filterConverter = new SimpleSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<String, String>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
        db.setQueryConverter(filterConverter);
        BCryptPasswordEncoder pe = new BCryptPasswordEncoder(4);

        existingUserCount = jdbcTemplate.queryForObject("select count(id) from users", Integer.class);

        defaultIdentityProviderId = jdbcTemplate.queryForObject("select id from identity_provider where origin_key = ? and identity_zone_id = ?", String.class, OriginKeys.UAA, "uaa");

        addUser(JOE_ID, "joe", pe.encode("joespassword"), "joe@joe.com", "Joe", "User", "+1-222-1234567", defaultIdentityProviderId, "uaa");
        addUser(MABEL_ID, "mabel", pe.encode("mabelspassword"), "mabel@mabel.com", "Mabel", "User", "", defaultIdentityProviderId, "uaa");
    }

    private String createUserForDelete() {
        String tmpUserId = UUID.randomUUID().toString();
        addUser(tmpUserId, tmpUserId, "password", tmpUserId + "@delete.com", "ToDelete", "User", "+1-234-5678910", defaultIdentityProviderId, "uaa");
        return tmpUserId;
    }

    private void addUser(String id, String username, String password, String email, String givenName,
                         String familyName, String phoneNumber, String identityProviderId, String identityZoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        jdbcTemplate.execute(String.format(ADD_USER_SQL_FORMAT, id, username, password, email, givenName, familyName,
            phoneNumber, identityZoneId));
    }

    private void removeUser(String id) {
        jdbcTemplate.execute(String.format(DELETE_USER_SQL_FORMAT, id));
    }

    @After
    public void clear() throws Exception {
        jdbcTemplate.execute("delete from users where id = '" + JOE_ID + "'");
        jdbcTemplate.execute("delete from users where id = '" + MABEL_ID + "'");
        jdbcTemplate.execute("delete from users where upper(userName) = 'JO@FOO.COM'");
        jdbcTemplate.execute("delete from users where upper(userName) = 'JONAH@FOO.COM'");
        jdbcTemplate.execute("delete from users where upper(userName) = 'RO''GALLAGHER@EXAMPLE.COM'");
        jdbcTemplate.execute("delete from users where upper(userName) = 'USER@EXAMPLE.COM'");
        jdbcTemplate.execute("delete from identity_provider where identity_zone_id = 'my-zone-id'");
        jdbcTemplate.execute("delete from identity_zone where id = 'my-zone-id'");
        IdentityZoneHolder.clear();
    }

    @Test
    public void canCreateUserWithExclamationMarkInUsername() {
        String userName = "jo!!@foo.com";
        ScimUser user = new ScimUser(null, userName, "Jo", "User");
        user.addEmail(userName);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals(userName, created.getUserName());
    }

    protected void addMembership(String userId, String origin) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        String zoneId = IdentityZoneHolder.get().getId();
        jdbcTemplate.update(INSERT_MEMBERSHIP, userId, userId, "USER", "authorities", timestamp, origin, zoneId);
    }

    @Test
    public void test_can_delete_provider_users_in_default_zone() throws Exception {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject(
                         "select count(*) from users where origin=? and identity_zone_id=?",
                         new Object[] {LOGIN_SERVER,IdentityZone.getUaa().getId()},
                         Integer.class
                     ), is(1)
        );
        addMembership(created.getId(), created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(LOGIN_SERVER)
                .setIdentityZoneId(IdentityZone.getUaa().getId());
        db.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {LOGIN_SERVER, IdentityZone.getUaa().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(0));
    }

    @Test
    public void test_can_delete_provider_users_in_other_zone() throws Exception {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, id);
        IdentityZoneHolder.set(zone);
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertEquals(zone.getId(), created.getZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {LOGIN_SERVER, zone.getId()}, Integer.class), is(1));
        addMembership(created.getId(), created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(LOGIN_SERVER)
                .setIdentityZoneId(zone.getId());
        db.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {LOGIN_SERVER, zone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(0));
    }

    @Test
    public void test_can_delete_zone_users() throws Exception {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, id);
        IdentityZoneHolder.set(zone);
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(UAA);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(UAA, created.getOrigin());
        assertEquals(zone.getId(), created.getZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, zone.getId()}, Integer.class), is(1));
        addMembership(created.getId(), created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(1));

        db.onApplicationEvent(new EntityDeletedEvent<>(zone, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, zone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[] {created.getId()}, Integer.class), is(0));
    }

    @Test
    public void test_cannot_delete_uaa_zone_users() throws Exception {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(UAA);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(UAA, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, IdentityZone.getUaa().getId()}, Integer.class), is(3));
        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(UAA)
                .setIdentityZoneId(IdentityZone.getUaa().getId());
        db.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, IdentityZone.getUaa().getId()}, Integer.class), is(3));
    }

    @Test
    public void test_cannot_delete_uaa_provider_users_in_other_zone() throws Exception {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, id);
        IdentityZoneHolder.set(zone);
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(UAA);
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(UAA, created.getOrigin());
        assertEquals(zone.getId(), created.getZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, zone.getId()}, Integer.class), is(1));
        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(UAA)
                .setIdentityZoneId(zone.getId());
        db.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[] {UAA, zone.getId()}, Integer.class), is(1));
    }



    @Test
    public void canCreateUserInDefaultIdentityZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals("uaa", map.get("identity_zone_id"));
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001); //1 second at most given MySQL fractionless timestamp
    }

    @Test
    public void canModifyPassword() throws Exception {
        ScimUser user = new ScimUser(null, generator.generate()+ "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001);
        Thread.sleep(10);
        db.changePassword(created.getId(), "j7hyqpassX", "j7hyqpassXXX", IdentityZoneHolder.get().getId());

        user = db.retrieve(created.getId(), IdentityZoneHolder.get().getId());
        assertNotNull(user.getPasswordLastModified());
        assertTrue(Math.abs(user.getMeta().getLastModified().getTime() - user.getPasswordLastModified().getTime()) < 1001);
    }

    @Test
    public void testSetPasswordChangeRequired() {
        ScimUser user = new ScimUser(null, generator.generate()+ "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertFalse(db.checkPasswordChangeIndividuallyRequired(created.getId(), IdentityZoneHolder.get().getId()));
        db.updatePasswordChangeRequired(created.getId(), true, IdentityZoneHolder.get().getId());
        assertTrue(db.checkPasswordChangeIndividuallyRequired(created.getId(), IdentityZoneHolder.get().getId()));
        db.updatePasswordChangeRequired(created.getId(), false, IdentityZoneHolder.get().getId());
        assertFalse(db.checkPasswordChangeIndividuallyRequired(created.getId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    public void canCreateUserInOtherIdentityZone() {
        String otherZoneId = "my-zone-id";
        createOtherIdentityZone(otherZoneId);
        String idpId = createOtherIdentityProvider(OriginKeys.UAA, otherZoneId);
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals("my-zone-id", map.get("identity_zone_id"));
    }

    @Test
    public void countUsersAcrossAllZones() {
        IdentityZoneHolder.clear();
        int beginningCount = db.getTotalCount();
        canCreateUserInDefaultIdentityZone();
        IdentityZoneHolder.clear();
        assertEquals(beginningCount+1, db.getTotalCount());
        canCreateUserInOtherIdentityZone();
        IdentityZoneHolder.clear();
        assertEquals(beginningCount+2, db.getTotalCount());

    }

    private void createOtherIdentityZone(String zoneId) {
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, "myzone");
        zoneDb.create(identityZone);
        IdentityZoneHolder.set(identityZone);
    }

    private String createOtherIdentityProvider(String origin, String zoneId) {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(origin, zoneId);
        return providerDb.create(identityProvider, IdentityZoneHolder.get().getId()).getId();
    }

    @Test
    public void validateOriginAndExternalIDDuringCreateAndUpdate() {
        String origin = "test";
        ScimUserBootstrapTests.addIdentityProvider(jdbcTemplate, origin);
        String externalId = "testId";
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.setOrigin(origin);
        user.setExternalId(externalId);
        user.addEmail("jo@blah.com");
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(origin, created.getOrigin());
        assertEquals(externalId, created.getExternalId());
        String origin2 = "test2";
        ScimUserBootstrapTests.addIdentityProvider(jdbcTemplate,origin2);
        String externalId2 = "testId2";
        created.setOrigin(origin2);
        created.setExternalId(externalId2);
        ScimUser updated = db.update(created.getId(), created, IdentityZoneHolder.get().getId());
        assertEquals(origin2, updated.getOrigin());
        assertEquals(externalId2, updated.getExternalId());
    }


    @Test
    public void canCreateUserWithoutGivenNameAndFamilyName() {
        ScimUser user = new ScimUser(null, "jonah@foo.com", null, null);
        user.addEmail("jo@blah.com");
        ScimUser created = db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
        assertEquals("jonah@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
    }

    @Test
    public void canCreateUserWithSingleQuoteInEmailAndUsername() {
        ScimUser user = new ScimUser(null, "ro'gallagher@example.com", "Rob", "O'Gallagher");
        user.addEmail("ro'gallagher@example.com");
        db.createUser(user, "j7hyqpassX", IdentityZoneHolder.get().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotCreateScimUserWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "joeyjoejoe", "joe", "young");
        user.addEmail("");
    }



    @Test
    public void canReadScimUserWithMissingEmail() {
        // Create a user with no email address, reflecting previous behavior

        JdbcScimUserProvisioning noValidateProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory) {
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
        when(nohbdy.getEmails()).thenReturn(Collections.singletonList(emptyEmail));
        when(nohbdy.getPrimaryEmail()).thenReturn("");
        nohbdy.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        nohbdy.setSalt("salt");
        nohbdy.setPassword(generator.generate());
        nohbdy.setOrigin(OriginKeys.UAA);
        String createdUserId = noValidateProvisioning.create(nohbdy, IdentityZoneHolder.get().getId()).getId();

        db.retrieve(createdUserId, IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateModifiesExpectedData() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        jo.setSalt("salt");

        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());

        // Can change username
        assertEquals("josephine", joe.getUserName());
        assertEquals("jo@blah.com", joe.getPrimaryEmail());
        assertEquals("Jo", joe.getGivenName());
        assertEquals("NewUser", joe.getFamilyName());
        assertEquals(1, joe.getVersion());
        assertEquals(JOE_ID, joe.getId());
        assertNull(joe.getGroups());
        assertEquals("salt", joe.getSalt());
    }

    @Test
    public void updateWithEmptyPhoneListWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(new ArrayList<PhoneNumber>());
        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateWithEmptyPhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(Arrays.asList(emptyNumber));
        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateWithWhiteSpacePhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        emptyNumber.setValue(" ");
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(Arrays.asList(emptyNumber));
        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateCannotModifyGroups() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setGroups(Collections.singleton(new Group(null, "dash/user")));

        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());

        assertEquals(JOE_ID, joe.getId());
        assertNull(joe.getGroups());
    }

    @Test(expected = OptimisticLockingFailureException.class)
    public void updateWithWrongVersionIsError() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setVersion(1);
        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
        assertEquals("joe", joe.getUserName());
    }

    @Test(expected = InvalidScimResourceException.class)
    public void updateWithBadUsernameIsError() {
        ScimUser jo = db.retrieve(JOE_ID, IdentityZoneHolder.get().getId());
        jo.setUserName("jo$ephione");
        db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateWithBadUsernameIsOk_For_Non_UAA() {
        ScimUser jo = new ScimUser(null, "jo$ephine", "Jo", "NewUser");
        jo.setOrigin(OriginKeys.LDAP);
        jo.addEmail("jo@blah.com");
        ScimUser joe = db.update(JOE_ID, jo, IdentityZoneHolder.get().getId());
        assertEquals("jo$ephine", joe.getUserName());
        assertEquals(OriginKeys.LDAP, joe.getOrigin());
    }

    /*
     * @Test(expected = InvalidScimResourceException.class)
     * public void updateWithCapitalLetterInUsernameIsError() throws Exception {
     * ScimUser jo = new ScimUser(null, "joSephine", "Jo", "NewUser");
     * jo.addEmail("jo@blah.com");
     * jo.setVersion(1);
     * ScimUser joe = db.update(JOE_ID, jo);
     * assertEquals("joe", joe.getUserId());
     * }
     */
    @Test
    public void canChangePasswordWithoutOldPassword() throws Exception {
        db.changePassword(JOE_ID, null, "koala123$marissa", IdentityZoneHolder.get().getId());
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, JOE_ID);
        assertTrue(BCrypt.checkpw("koala123$marissa", storedPassword));
    }

    @Test
    public void canChangePasswordWithCorrectOldPassword() throws Exception {
        db.changePassword(JOE_ID, "joespassword", "koala123$marissa", IdentityZoneHolder.get().getId());
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, JOE_ID);
        assertTrue(BCrypt.checkpw("koala123$marissa", storedPassword));
    }

    @Test(expected = BadCredentialsException.class)
    public void cannotChangePasswordNonexistentUser() {
        db.changePassword(JOE_ID, "notjoespassword", "newpassword", IdentityZoneHolder.get().getId());
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotChangePasswordIfOldPasswordDoesntMatch() {
        db.changePassword("9999", null, "newpassword", IdentityZoneHolder.get().getId());
    }

    @Test
    public void canRetrieveExistingUser() {
        ScimUser joe = db.retrieve(JOE_ID, IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotRetrieveNonexistentUser() {
        ScimUser joe = db.retrieve("9999", IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test
    public void canDeactivateExistingUser() {
        String tmpUserId = createUserForDelete();
        ScimUser deletedUser = db.delete(tmpUserId, 0, IdentityZoneHolder.get().getId());
        assertEquals(1, jdbcTemplate.queryForList("select * from users where id=? and active=?", tmpUserId, false).size());
        assertFalse(deletedUser.isActive());
        assertEquals(1, db.query("username eq \"" + tmpUserId + "\" and active eq false", IdentityZoneHolder.get().getId()).size());
        removeUser(tmpUserId);
    }

    @Test(expected = ScimResourceAlreadyExistsException.class)
    public void cannotDeactivateExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete();
        ScimUser deletedUser = db.delete(tmpUserId, 0, IdentityZoneHolder.get().getId());
        deletedUser.setActive(true);
        try {
            db.createUser(deletedUser, "foobarspam1234", IdentityZoneHolder.get().getId());
        } catch (ScimResourceAlreadyExistsException e) {
            removeUser(tmpUserId);
            throw e;
        }
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotDeactivateNonexistentUser() {
        ScimUser joe = db.delete("9999", 0, IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test(expected = OptimisticLockingFailureException.class)
    public void deactivateWithWrongVersionIsError() {
        ScimUser joe = db.delete(JOE_ID, 1, IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test
    public void canDeleteExistingUserThroughEvent() {
        String tmpUserId = createUserForDelete();
        ScimUser user = db.retrieve(tmpUserId, IdentityZoneHolder.get().getId());
        db.setDeactivateOnDelete(false);
        db.onApplicationEvent(new EntityDeletedEvent<Object>(user, mock(Authentication.class)));
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, db.query("username eq \"" + tmpUserId + "\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canDeleteExistingUser() {
        String tmpUserId = createUserForDelete();
        db.setDeactivateOnDelete(false);
        db.delete(tmpUserId, 0, IdentityZoneHolder.get().getId());
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, db.query("username eq \"" + tmpUserId + "\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    // (expected = ScimResourceAlreadyExistsException.class)
    public void canDeleteExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete();
        db.setDeactivateOnDelete(false);
        ScimUser deletedUser = db.delete(tmpUserId, 0, IdentityZoneHolder.get().getId());
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());

        deletedUser.setActive(true);
        ScimUser user = db.createUser(deletedUser, "foobarspam1234", IdentityZoneHolder.get().getId());
        assertNotNull(user);
        assertNotNull(user.getId());
        assertNotSame(tmpUserId, user.getId());
        assertEquals(1, db.query("username eq \"" + tmpUserId + "\"", IdentityZoneHolder.get().getId()).size());
        removeUser(user.getId());
    }

    @Test
    public void testCreatedUserNotVerified() {
        String tmpUserIdString = createUserForDelete();
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
        assertFalse(user.isVerified());
        removeUser(tmpUserIdString);
    }

    @Test
    public void testCreateUserWithDuplicateUsername() throws Exception {
        addUser("cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", defaultIdentityProviderId, "uaa");
        ScimUser scimUser = new ScimUser("user-id-2", "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setPassword("password");

        try {
            db.create(scimUser, IdentityZoneHolder.get().getId());
            fail("Should have thrown an exception");
        } catch (ScimResourceAlreadyExistsException e) {
            Map<String,Object> userDetails = new HashMap<>();
            userDetails.put("active", true);
            userDetails.put("verified", false);
            userDetails.put("user_id", "cba09242-aa43-4247-9aa0-b5c75c281f94");
            assertEquals(HttpStatus.CONFLICT, e.getStatus());
            assertEquals("Username already in use: user@example.com", e.getMessage());
            assertEquals(userDetails, e.getExtraInfo());
        }
    }


    @Test
    public void testCreateUserCheckSalt() throws Exception {
        ScimUser scimUser = new ScimUser("user-id-3", "user3@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setPassword("password");
        scimUser.setSalt("salt");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser = db.create(scimUser, IdentityZoneHolder.get().getId());
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");
        scimUser = db.update(scimUser.getId(), scimUser, IdentityZoneHolder.get().getId());
        assertNotNull(scimUser);
        assertEquals("newsalt", scimUser.getSalt());
    }

    @Test
    public void testUpdateUserPasswordDoesntChange() throws Exception {
        String username = "user-"+new RandomValueStringGenerator().generate()+"@test.org";
        ScimUser scimUser = new ScimUser(null, username, "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setSalt("salt");
        scimUser = db.createUser(scimUser, "password", IdentityZoneHolder.get().getId());
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");

        String passwordHash = jdbcTemplate.queryForObject("select password from users where id=?",new Object[] {scimUser.getId()}, String.class);
        assertNotNull(passwordHash);

        db.changePassword(scimUser.getId(), null, "password", IdentityZoneHolder.get().getId());
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class));

        db.changePassword(scimUser.getId(), "password", "password", IdentityZoneHolder.get().getId());
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?",new Object[] {scimUser.getId()}, String.class));

    }


    @Test
    public void testCreateUserWithDuplicateUsernameInOtherIdp() throws Exception {
        addUser("cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", defaultIdentityProviderId, "uaa");

        String origin = "test-origin";
        createOtherIdentityProvider(origin, IdentityZone.getUaa().getId());

        ScimUser scimUser = new ScimUser(null, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setPassword("password");
        scimUser.setOrigin(origin);
        String userId2 = db.create(scimUser, IdentityZoneHolder.get().getId()).getId();
        assertNotNull(userId2);
        assertNotEquals("cba09242-aa43-4247-9aa0-b5c75c281f94", userId2);
    }

    @Test
    public void testUpdatedUserVerified() {
        String tmpUserIdString = createUserForDelete();
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        db.verifyUser(tmpUserIdString, -1, IdentityZoneHolder.get().getId());
        verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertTrue(verified);
        removeUser(tmpUserIdString);
    }

    @Test
    public void createUserWithNoZoneDefaultsToUAAZone() {
        String id = UUID.randomUUID().toString();
        jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, id, "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890"));
        ScimUser user = db.retrieve(id, IdentityZoneHolder.get().getId());
        assertEquals("uaa", user.getZoneId());
        assertNull(user.getSalt());
    }

    @Test(expected=DuplicateKeyException.class)
    public void createUserWithNoZoneFailsIfUserAlreadyExistsInUaaZone() {
        addUser(UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890", defaultIdentityProviderId, "uaa");
        jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890"));
    }

    @Test
    public void testUpdatedVersionedUserVerified() {
        String tmpUserIdString = createUserForDelete();
        ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
        assertFalse(user.isVerified());
        user = db.verifyUser(tmpUserIdString, user.getVersion(), IdentityZoneHolder.get().getId());
        assertTrue(user.isVerified());
        removeUser(tmpUserIdString);
    }

    @Test
    public void testUserVerifiedThroughUpdate() {
        String tmpUserIdString = createUserForDelete();
        ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
        assertFalse(user.isVerified());
        user.setVerified(true);
        user = db.update(tmpUserIdString, user, IdentityZoneHolder.get().getId());
        assertTrue(user.isVerified());
        removeUser(tmpUserIdString);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void testUserVerifiedInvalidUserId() {
        String tmpUserIdString = createUserForDelete();
        try {
            ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
            assertFalse(user.isVerified());
            user = db.verifyUser("-1-1-1", -1, IdentityZoneHolder.get().getId());
            assertTrue(user.isVerified());
        } finally {
            removeUser(tmpUserIdString);
        }
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void testUserUpdateInvalidUserId() {
        String tmpUserIdString = createUserForDelete();
        try {
            ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
            assertFalse(user.isVerified());
            user.setVerified(true);
            user = db.update("-1-1-1", user, IdentityZoneHolder.get().getId());
            assertTrue(user.isVerified());
        } finally {
            removeUser(tmpUserIdString);
        }
    }

    @Test(expected = OptimisticLockingFailureException.class)
    public void testUpdatedIncorrectVersionUserVerified() {
        String tmpUserIdString = createUserForDelete();
        try {
            ScimUser user = db.retrieve(tmpUserIdString, IdentityZoneHolder.get().getId());
            assertFalse(user.isVerified());
            user = db.verifyUser(tmpUserIdString, user.getVersion() + 50, IdentityZoneHolder.get().getId());
            assertTrue(user.isVerified());
        } finally {
            removeUser(tmpUserIdString);
        }
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotDeleteNonexistentUser() {
        db.setDeactivateOnDelete(false);
        ScimUser joe = db.delete("9999", 0, IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test(expected = OptimisticLockingFailureException.class)
    public void deleteWithWrongVersionIsError() {
        db.setDeactivateOnDelete(false);
        ScimUser joe = db.delete(JOE_ID, 1, IdentityZoneHolder.get().getId());
        assertJoe(joe);
    }

    @Test
    public void canRetrieveUsers() {
        assertTrue(2 <= db.retrieveAll(IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterExists() {
        assertTrue(2 <= db.query("username pr", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterEquals() {
        assertEquals(1, db.query("username eq \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterEqualsDoubleQuote() {
        assertEquals(1, db.query("username eq \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterKeyCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, db.query("USERNAME eq \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, db.query("username EQ \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterValueCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, db.query("username eq \"Joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterContains() {
        assertEquals(2, db.query("username co \"e\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterStartsWith() {
        assertEquals(1, db.query("username sw \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterGreater() {
        assertEquals(1 + existingUserCount, db.query("username gt \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithEmailFilter() {
        assertEquals(1, db.query("emails.value sw \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithGroupsFilter() {
        List<ScimUser> users = db.query("groups.display co \"uaa.user\"", IdentityZoneHolder.get().getId());
        assertEquals(2 + existingUserCount, users.size());
        for (int i=0; i<users.size(); i++) {
            assertNotNull(users.get(i));
        }
    }

    @Test
    public void canRetrieveUsersWithPhoneNumberFilter() {
        assertEquals(1, db.query("phoneNumbers.value sw \"+1-222\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithMetaVersionFilter() {
        assertEquals(1, db.query("userName eq \"joe\" and meta.version eq 0", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithMetaDateFilter() {
        assertEquals(2 + existingUserCount, db.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithBooleanFilter() {
        assertEquals(2 + existingUserCount, db.query("username pr and active eq true", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithSortBy() {
        assertEquals(2 + existingUserCount, db.query("username pr", "username", true, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithSortByEmail() {
        assertEquals(2 + existingUserCount, db.query("username pr", "emails.value", true, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterBooleanAnd() {
        assertEquals(2, db.query("username pr and emails.value co \".com\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterBooleanOr() {
        assertEquals(2, db.query("username eq \"joe\" or emails.value co \".com\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
        assertEquals(1, db.query("username eq \"foo\" or username eq \"joe\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithIllegalFilterField() {
        assertEquals(2, db.query("emails.type eq \"bar\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithIllegalPhoneNumberFilterField() {
        assertEquals(2, db.query("phoneNumbers.type eq \"bar\"", IdentityZoneHolder.get().getId()).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithIllegalFilterQuotes() {
        assertEquals(2, db.query("username eq \"bar", IdentityZoneHolder.get().getId()).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        Collection<ScimUser> users = db.query("username=\"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", IdentityZoneHolder.get().getId());
        assertEquals(password, users.iterator().next().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        Collection<ScimUser> users = db.query("username gt \"h\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", IdentityZoneHolder.get().getId());
        assertEquals(password, users.iterator().next().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        Collection<ScimUser> users = db.query("username eq \"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", IdentityZoneHolder.get().getId());
        assertEquals(password, users.iterator().next().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        Collection<ScimUser> users = db.query("username eq \"joe\"\"; select id from users where id='''; select "
                + SQL_INJECTION_FIELDS + " from users where username='joe'", IdentityZoneHolder.get().getId());
        assertEquals(password, users.iterator().next().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        Collection<ScimUser> users = db.query("username eq \"joe\"'; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe''", IdentityZoneHolder.get().getId());
        assertEquals(password, users.iterator().next().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void filterEqWithoutQuotesIsRejected() {
        db.query("username eq joe", IdentityZoneHolder.get().getId());
    }

    @Test
    public void checkPasswordMatches_returnsTrue_PasswordMatches() {
        assertTrue(db.checkPasswordMatches(JOE_ID, "joespassword", IdentityZoneHolder.get().getId()));
    }

    @Test
    public void checkPasswordMatches_ReturnsFalse_newPasswordSameAsOld() {
        assertFalse(db.checkPasswordMatches(JOE_ID, "notjoepassword", IdentityZoneHolder.get().getId()));
    }

    @Test
    public void updateLastLogonTime() {
        ScimUser user = db.retrieve(JOE_ID, IdentityZoneHolder.get().getId());
        Long timeStampBeforeUpdate = user.getLastLogonTime();
        assertNull(timeStampBeforeUpdate);
        db.updateLastLogonTime(JOE_ID, IdentityZoneHolder.get().getId());
        user = db.retrieve(JOE_ID, IdentityZoneHolder.get().getId());
        assertNotNull(user.getLastLogonTime());
    }

    private void assertJoe(ScimUser joe) {
        assertNotNull(joe);
        assertEquals(JOE_ID, joe.getId());
        assertEquals("Joe", joe.getGivenName());
        assertEquals("User", joe.getFamilyName());
        assertEquals("joe@joe.com", joe.getPrimaryEmail());
        assertEquals("joe", joe.getUserName());
        assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
        assertNull(joe.getGroups());
    }
}
