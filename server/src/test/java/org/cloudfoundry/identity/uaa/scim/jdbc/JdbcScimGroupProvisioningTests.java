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

import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_FIELDS;
import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_TABLE;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.util.StringUtils.hasText;

public class JdbcScimGroupProvisioningTests extends JdbcTestBase {
    private JdbcScimGroupProvisioning dao;
    private JdbcScimGroupMembershipManager memberships;
    private ScimUserProvisioning users;

    private static final String SQL_INJECTION_FIELDS = "displayName,version,created,lastModified";

    private int existingGroupCount = -1;
    private ScimGroup g1;
    private ScimGroup g2;
    private ScimGroup g3;
    private String g1Id;
    private String g2Id;
    private String g3Id;
    private RandomValueStringGenerator generator;
    private String zoneId;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private String group1Description;
    private String group2Description;
    private String group3Description;

    @Before
    public void initJdbcScimGroupProvisioningTests() {
        generator = new RandomValueStringGenerator();
        SecureRandom random = new SecureRandom();
        random.setSeed(System.nanoTime());
        generator.setRandom(random);

        zoneId = generator.generate();

        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        IdentityZoneHolder.set(zone);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(new ArrayList<>());

        validateGroupCount(0);

        memberships = new JdbcScimGroupMembershipManager(jdbcTemplate);
        dao = spy(new JdbcScimGroupProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter)));
        memberships.setScimGroupProvisioning(dao);
        users = mock(ScimUserProvisioning.class);
        memberships.setScimUserProvisioning(users);

        g1Id = "g1";
        g2Id = "g2";
        g3Id = "g3";

        group1Description = "u" + generator.generate();
        g1 = addGroup(g1Id, group1Description);
        group2Description = "u" + generator.generate();
        g2 = addGroup(g2Id, group2Description);
        group3Description = "op" + generator.generate();
        g3 = addGroup(g3Id, group3Description);

        validateGroupCount(3);
    }

    @After
    public void cleanSpy() {
        dao.deleteByIdentityZone(zoneId);
        validateGroupCount(0);

        reset(dao);
    }

    @Test
    public void create_or_get_tries_get_first() {
        reset(dao);
        dao.createOrGet(new ScimGroup(group3Description), zoneId);
        verify(dao, times(1)).getByName(group3Description, zoneId);
        verify(dao, never()).createAndIgnoreDuplicate(anyString(), anyString());
    }

    @Test
    public void create_or_get_tries_get_first_but_creates_it() {
        reset(dao);
        String name = generator.generate().toLowerCase() + System.nanoTime();
        dao.createOrGet(new ScimGroup(name), zoneId);
        verify(dao, times(2)).getByName(name, zoneId);
        verify(dao, times(1)).createAndIgnoreDuplicate(name, zoneId);
    }

    @Test
    public void get_by_name() {
        assertNotNull(dao.getByName(group3Description, zoneId));
        assertNotNull(dao.getByName(group1Description, zoneId));
        assertNotNull(dao.getByName(group2Description, zoneId));
    }

    @Test
    public void get_by_invalid_name() {
        exception.expect(IncorrectResultSizeDataAccessException.class);
        exception.expectMessage("Invalid result size found for");
        assertNotNull(dao.getByName("invalid-group-name", zoneId));
    }

    @Test
    public void get_by_empty_name() {
        exception.expect(IncorrectResultSizeDataAccessException.class);
        exception.expectMessage("group name must contain text");
        assertNotNull(dao.getByName("", zoneId));
    }

    @Test
    public void get_by_null_name() {
        exception.expect(IncorrectResultSizeDataAccessException.class);
        exception.expectMessage("group name must contain text");
        assertNotNull(dao.getByName("", zoneId));
    }

    @Test
    public void canRetrieveGroups() {
        List<ScimGroup> groups = dao.retrieveAll(zoneId);
        assertEquals(3, groups.size());
        for (ScimGroup g : groups) {
            validateGroup(g, null, zoneId);
        }
    }

    @Test
    public void canRetrieveGroupsWithFilter() {
        assertEquals(1, dao.query("displayName eq " + "\"" + group1Description+ "\"" , zoneId).size());
        assertEquals(3, dao.query("displayName pr", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"" + group3Description + "\"", zoneId).size());
        assertEquals(1, dao.query("DISPLAYNAMe eq " + "\"" + group2Description + "\"", zoneId).size());
        assertEquals(1, dao.query("displayName EQ \"" + group3Description + "\"", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"" + group3Description.toUpperCase() + "\"", zoneId).size());
        assertEquals(1, dao.query("displayName co \"" + group1Description.substring(1, group1Description.length() - 1) + "\"", zoneId).size());
        assertEquals(3, dao.query("id sw \"g\"", zoneId).size());
        assertEquals(3, dao.query("displayName gt \"oauth\"", zoneId).size());
        assertEquals(0, dao.query("displayName lt \"oauth\"", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"" + group3Description + "\" and meta.version eq 0", zoneId).size());
        assertEquals(3, dao.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", zoneId).size());
        assertEquals(3, dao.query("displayName pr and id co \"g\"", zoneId).size());
        assertEquals(2, dao.query("displayName eq \"" + group3Description + "\" or displayName co \"" + group1Description.substring(1, group1Description.length() - 1) + "\"", zoneId).size());
        assertEquals(3, dao.query("displayName eq \"foo\" or id sw \"g\"", zoneId).size());
    }

    @Test
    public void canRetrieveGroupsWithFilterAndSortBy() {
        assertEquals(3, dao.query("displayName pr", "id", true, zoneId).size());
        assertEquals(1, dao.query("id co \"2\"", "displayName", false, zoneId).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithIllegalQuotesFilter() {
        assertEquals(1, dao.query("displayName eq \"bar", zoneId).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithMissingQuotesFilter() {
        assertEquals(0, dao.query("displayName eq bar", zoneId).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithInvalidFieldsFilter() {
        assertEquals(1, dao.query("name eq \"openid\"", zoneId).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithWrongFilter() {
        assertEquals(0, dao.query("displayName pr \"r\"", zoneId).size());
    }

    @Test
    public void canRetrieveGroup() {
        ScimGroup group = dao.retrieve(g1Id, zoneId);
        validateGroup(group, group1Description, zoneId);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotRetrieveNonExistentGroup() {
        dao.retrieve("invalidgroup", zoneId);
    }

    @Test
    public void canCreateGroup() {
        internalCreateGroup(generator.generate().toLowerCase());
    }

    @Test
    public void canCreateOrGetGroup() {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        String id = g.getId();
        g.setId(null);
        ScimGroup same = dao.createOrGet(g, zoneId);
        assertNotNull(same);
        assertEquals(id, same.getId());
    }

    @Test
    public void canGetByName() {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        ScimGroup same = dao.getByName(g.getDisplayName(), zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    public void canCreateAndGetGroupWithQuotes() {
        String nameWithQuotes = generator.generate() + "\"" + generator.generate() + "\"";
        ScimGroup g = internalCreateGroup(nameWithQuotes);
        assertNotNull(g);
        assertEquals(nameWithQuotes, g.getDisplayName());
        ScimGroup same = dao.getByName(nameWithQuotes, zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    public void canUpdateGroup() {
        ScimGroup g = dao.retrieve(g1Id, zoneId);
        assertEquals(group1Description, g.getDisplayName());

        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = new ScimGroupMember(g2Id, ScimGroupMember.Type.USER);
        g.setMembers(Arrays.asList(m1, m2));
        g.setDisplayName("uaa.none");
        g.setDescription("description-update");

        dao.update(g1Id, g, zoneId);

        g = dao.retrieve(g1Id, zoneId);
        validateGroup(g, "uaa.none", zoneId, "description-update");
    }

    @Test
    public void canRemoveGroup() {
        validateGroupCount(3);
        addUserToGroup(g1.getId(), "joe@example.com");
        validateGroupCount(3);
        addUserToGroup(g1.getId(), "mary@example.com");
        ScimGroupMember bill = addUserToGroup(g2.getId(), "bill@example.com");

        dao.delete(g1Id, 0, zoneId);
        validateGroupCount(2);
        List<ScimGroupMember> remainingMemberships = jdbcTemplate.query("select "+MEMBERSHIP_FIELDS+" from "+MEMBERSHIP_TABLE,
                                                                        new JdbcScimGroupMembershipManager.ScimGroupMemberRowMapper());
        assertEquals(1, remainingMemberships.size());
        ScimGroupMember survivor = remainingMemberships.get(0);
        assertThat(survivor.getType(), is(ScimGroupMember.Type.USER));
        assertEquals(bill.getMemberId(), survivor.getMemberId());
    }

    @Test
    public void deleteGroupWithNestedMembers() {
        ScimGroup appUsers = addGroup("appuser", "app.user");
        addGroupToGroup(appUsers.getId(), g1.getId());
        dao.delete(appUsers.getId(), 0, zoneId);

        List<ScimGroupMember> remainingMemberships = jdbcTemplate.query("select "+MEMBERSHIP_FIELDS+" from "+MEMBERSHIP_TABLE,
                                                                        new JdbcScimGroupMembershipManager.ScimGroupMemberRowMapper());
        assertEquals(0, remainingMemberships.size());
    }

    @Test
    public void test_that_uaa_scopes_are_bootstrapped_when_zone_is_created() {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, "subdomain-" + id);
        IdentityZoneModifiedEvent event = IdentityZoneModifiedEvent.identityZoneCreated(zone);
        dao.onApplicationEvent(event);
        List<String> groups = dao.retrieveAll(id).stream().map(g -> g.getDisplayName()).collect(Collectors.toList());
        ZoneManagementScopes.getSystemScopes()
            .stream()
            .forEach(
                scope ->
                    assertTrue("Scope:" + scope + " should have been bootstrapped into the new zone", groups.contains(scope))
            );

    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack1Fails() {
        dao.query("displayName='something'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'", zoneId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack2Fails() {
        dao.query("displayName gt 'a'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'", zoneId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack3Fails() {
        dao.query("displayName eq \"something\"; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'", zoneId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack4Fails() {
        dao.query("displayName eq \"something\"; select id from groups where id='''; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'", zoneId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack5Fails() {
        dao.query("displayName eq \"something\"'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something''", zoneId);
    }

    private void validateGroupCount(int expected) {
        existingGroupCount = jdbcTemplate.queryForObject("select count(id) from groups where identity_zone_id='" + zoneId + "'", Integer.class);
        assertEquals(expected, existingGroupCount);
    }

    private void validateGroup(ScimGroup group, String name, String zoneId) {
        assertNotNull(group);
        assertNotNull(group.getId());
        assertNotNull(group.getDisplayName());
        if (hasText(name)) {
            assertEquals(name, group.getDisplayName());
        }
        if (hasText(zoneId)) {
            assertEquals(zoneId, group.getZoneId());
        }
    }

    private void validateGroup(ScimGroup group, String name, String zoneId, String description) {
        validateGroup(group, name, zoneId);
        if (hasText(description)) {
            assertEquals(description, group.getDescription());
        }
    }

    private ScimGroup addGroup(String id, String name) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        jdbcTemplate.update(dao.ADD_GROUP_SQL,
                id,
                name,
                name + "-description",
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                0,
                zoneId);

        return dao.retrieve(id, zoneId);
    }

    private ScimGroupMember<ScimUser> addUserToGroup(String groupId, String username) {
        String userId = UUID.randomUUID().toString();
        ScimUser scimUser = new ScimUser(userId, username, username, username);
        scimUser.setZoneId(zoneId);
        when(users.retrieve(userId, zoneId)).thenReturn(scimUser);
        ScimGroupMember<ScimUser> member = new ScimGroupMember<>(scimUser);
        memberships.addMember(groupId, member, zoneId);
        return member;
    }

    private ScimGroupMember addGroupToGroup(String parentGroupId, String childGroupId) {
        ScimGroupMember<ScimGroup> member = new ScimGroupMember<>(dao.retrieve(childGroupId, zoneId));
        memberships.addMember(parentGroupId, member, zoneId);
        return member;
    }

    private ScimGroup internalCreateGroup(String groupName) {
        ScimGroup g = new ScimGroup(null, groupName, zoneId);
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER);
        g.setMembers(Arrays.asList(m1, m2));
        g = dao.create(g, zoneId);
        validateGroupCount(4);
        validateGroup(g, groupName, zoneId, "description-create");
        return g;
    }
}
