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

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_FIELDS;
import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_TABLE;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
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
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String zoneId;

    @Before
    public void initJdbcScimGroupProvisioningTests() {
        zoneId = IdentityZoneHolder.get().getId();
        memberships = new JdbcScimGroupMembershipManager(jdbcTemplate);
        dao = new JdbcScimGroupProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        memberships.setScimGroupProvisioning(dao);
        users = mock(ScimUserProvisioning.class);
        memberships.setScimUserProvisioning(users);

        g1 = addGroup("g1", "uaa.user");
        g2 = addGroup("g2", "uaa.admin");
        g3 = addGroup("g3", "openid");

        validateGroupCount(3);
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

    @Test
    public void canRetrieveGroups() throws Exception {
        List<ScimGroup> groups = dao.retrieveAll(zoneId);
        assertEquals(3, groups.size());
        for (ScimGroup g : groups) {
            validateGroup(g, null, zoneId);
        }
    }

    @Test
    public void canRetrieveGroupsWithFilter() throws Exception {
        assertEquals(1, dao.query("displayName eq \"uaa.user\"", zoneId).size());
        assertEquals(3, dao.query("displayName pr", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"openid\"", zoneId).size());
        assertEquals(1, dao.query("DISPLAYNAMe eq \"uaa.admin\"", zoneId).size());
        assertEquals(1, dao.query("displayName EQ \"openid\"", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"Openid\"", zoneId).size());
        assertEquals(1, dao.query("displayName co \"user\"", zoneId).size());
        assertEquals(3, dao.query("id sw \"g\"", zoneId).size());
        assertEquals(3, dao.query("displayName gt \"oauth\"", zoneId).size());
        assertEquals(0, dao.query("displayName lt \"oauth\"", zoneId).size());
        assertEquals(1, dao.query("displayName eq \"openid\" and meta.version eq 0", zoneId).size());
        assertEquals(3, dao.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", zoneId).size());
        assertEquals(3, dao.query("displayName pr and id co \"g\"", zoneId).size());
        assertEquals(2, dao.query("displayName eq \"openid\" or displayName co \".user\"", zoneId).size());
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
    public void canRetrieveGroup() throws Exception {
        ScimGroup group = dao.retrieve("g1", zoneId);
        validateGroup(group, "uaa.user", zoneId);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotRetrieveNonExistentGroup() {
        dao.retrieve("invalidgroup", zoneId);
    }

    @Test
    public void canCreateGroup() throws Exception {
        internalCreateGroup(generator.generate().toLowerCase());
    }
    public ScimGroup internalCreateGroup(String groupName) throws Exception {
        ScimGroup g = new ScimGroup(null, groupName, zoneId);
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
        g.setMembers(Arrays.asList(m1, m2));
        g = dao.create(g, zoneId);
        validateGroupCount(4);
        validateGroup(g, groupName, zoneId, "description-create");
        return g;
    }

    @Test
    public void canCreateOrGetGroup() throws Exception {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        String id = g.getId();
        g.setId(null);
        ScimGroup same = dao.createOrGet(g, zoneId);
        assertNotNull(same);
        assertEquals(id, same.getId());
    }

    @Test
    public void canGetByName() throws Exception {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        ScimGroup same = dao.getByName(g.getDisplayName(), zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    public void canCreateAndGetGroupWithQuotes() throws Exception {
        String nameWithQuotes = generator.generate() + "\"" + generator.generate() + "\"";
        ScimGroup g = internalCreateGroup(nameWithQuotes);
        assertNotNull(g);
        assertEquals(nameWithQuotes, g.getDisplayName());
        ScimGroup same = dao.getByName(nameWithQuotes, zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    public void canUpdateGroup() throws Exception {
        ScimGroup g = dao.retrieve("g1", zoneId);
        assertEquals("uaa.user", g.getDisplayName());

        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
        ScimGroupMember m2 = new ScimGroupMember("g2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
        g.setMembers(Arrays.asList(m1, m2));
        g.setDisplayName("uaa.none");
        g.setDescription("description-update");

        dao.update("g1", g, zoneId);

        g = dao.retrieve("g1", zoneId);
        validateGroup(g, "uaa.none", zoneId, "description-update");
    }

    @Test
    public void canRemoveGroup() throws Exception {
        addUserToGroup(g1.getId(), "joe@example.com");
        addUserToGroup(g1.getId(), "mary@example.com");
        ScimGroupMember bill = addUserToGroup(g2.getId(), "bill@example.com");

        dao.delete("g1", 0, zoneId);
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

    private ScimGroup addGroup(String id, String name) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        //"id,displayName,created,lastModified,version,identity_zone_id"
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
        scimUser.setZoneId(OriginKeys.UAA);
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
}
