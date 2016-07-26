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
import org.cloudfoundry.identity.uaa.resources.jdbc.DefaultLimitSqlAdapter;
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

    @Before
    public void initJdbcScimGroupProvisioningTests() {
        memberships = new JdbcScimGroupMembershipManager(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, new DefaultLimitSqlAdapter()));
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
        existingGroupCount = jdbcTemplate.queryForObject("select count(id) from groups where identity_zone_id='" + IdentityZoneHolder.get().getId() + "'", Integer.class);
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
        List<ScimGroup> groups = dao.retrieveAll();
        assertEquals(3, groups.size());
        for (ScimGroup g : groups) {
            validateGroup(g, null, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    public void canRetrieveGroupsWithFilter() throws Exception {
        assertEquals(1, dao.query("displayName eq \"uaa.user\"").size());
        assertEquals(3, dao.query("displayName pr").size());
        assertEquals(1, dao.query("displayName eq \"openid\"").size());
        assertEquals(1, dao.query("DISPLAYNAMe eq \"uaa.admin\"").size());
        assertEquals(1, dao.query("displayName EQ \"openid\"").size());
        assertEquals(1, dao.query("displayName eq \"Openid\"").size());
        assertEquals(1, dao.query("displayName co \"user\"").size());
        assertEquals(3, dao.query("id sw \"g\"").size());
        assertEquals(3, dao.query("displayName gt \"oauth\"").size());
        assertEquals(0, dao.query("displayName lt \"oauth\"").size());
        assertEquals(1, dao.query("displayName eq \"openid\" and meta.version eq 0").size());
        assertEquals(3, dao.query("meta.created gt \"1970-01-01T00:00:00.000Z\"").size());
        assertEquals(3, dao.query("displayName pr and id co \"g\"").size());
        assertEquals(2, dao.query("displayName eq \"openid\" or displayName co \".user\"").size());
        assertEquals(3, dao.query("displayName eq \"foo\" or id sw \"g\"").size());
    }

    @Test
    public void canRetrieveGroupsWithFilterAndSortBy() {
        assertEquals(3, dao.query("displayName pr", "id", true).size());
        assertEquals(1, dao.query("id co \"2\"", "displayName", false).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithIllegalQuotesFilter() {
        assertEquals(1, dao.query("displayName eq \"bar").size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithMissingQuotesFilter() {
        assertEquals(0, dao.query("displayName eq bar").size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithInvalidFieldsFilter() {
        assertEquals(1, dao.query("name eq \"openid\"").size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotRetrieveGroupsWithWrongFilter() {
        assertEquals(0, dao.query("displayName pr \"r\"").size());
    }

    @Test
    public void canRetrieveGroup() throws Exception {
        ScimGroup group = dao.retrieve("g1");
        validateGroup(group, "uaa.user", IdentityZoneHolder.get().getId());
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotRetrieveNonExistentGroup() {
        dao.retrieve("invalidgroup");
    }

    @Test
    public void canCreateGroup() throws Exception {
        ScimGroup g = new ScimGroup(null, "test.1", IdentityZoneHolder.get().getId());
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
        g.setMembers(Arrays.asList(m1, m2));
        g = dao.create(g);
        validateGroupCount(4);
        validateGroup(g, "test.1", IdentityZoneHolder.get().getId(), "description-create");
    }

    @Test
    public void canDeleteGroupsUsingFilter1() throws Exception {
        dao.delete("displayName eq \"uaa.user\"");
        validateGroupCount(2);
    }

    @Test
    public void canDeleteGroupsUsingFilter2() throws Exception {
        dao.delete("displayName sw \"uaa\"");
        validateGroupCount(1);
    }

    @Test
    public void canDeleteGroupsUsingFilter3() throws Exception {
        dao.delete("id eq \"g1\"");
        validateGroupCount(2);
    }

    @Test
    public void canUpdateGroup() throws Exception {
        ScimGroup g = dao.retrieve("g1");
        assertEquals("uaa.user", g.getDisplayName());

        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
        ScimGroupMember m2 = new ScimGroupMember("g2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
        g.setMembers(Arrays.asList(m1, m2));
        g.setDisplayName("uaa.none");
        g.setDescription("description-update");

        dao.update("g1", g);

        g = dao.retrieve("g1");
        validateGroup(g, "uaa.none", IdentityZoneHolder.get().getId(), "description-update");
    }

    @Test
    public void canRemoveGroup() throws Exception {
        addUserToGroup(g1.getId(), "joe@example.com");
        addUserToGroup(g1.getId(), "mary@example.com");
        ScimGroupMember bill = addUserToGroup(g2.getId(), "bill@example.com");

        dao.delete("g1", 0);
        validateGroupCount(2);
        List<ScimGroupMember> remainingMemberships = memberships.query("");
        assertEquals(1, remainingMemberships.size());
        ScimGroupMember survivor = remainingMemberships.get(0);
        assertThat(survivor.getType(), is(ScimGroupMember.Type.USER));
        assertEquals(bill.getMemberId(), survivor.getMemberId());
    }

    @Test
    public void deleteGroupWithNestedMembers() {
        ScimGroup appUsers = addGroup("appuser", "app.user");
        addGroupToGroup(appUsers.getId(), g1.getId());
        dao.delete(appUsers.getId(), 0);

        List<ScimGroupMember> remainingMemberships = memberships.query("");
        assertEquals(0, remainingMemberships.size());
    }

    @Test
    public void test_that_uaa_scopes_are_bootstrapped_when_zone_is_created() {
        String id = new RandomValueStringGenerator().generate();
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
                            IdentityZoneHolder.get().getId());

        return dao.retrieve(id);
    }

    private ScimGroupMember<ScimUser> addUserToGroup(String groupId, String username) {
        String userId = UUID.randomUUID().toString();
        ScimUser scimUser = new ScimUser(userId, username, username, username);
        scimUser.setZoneId(OriginKeys.UAA);
        when(users.retrieve(userId)).thenReturn(scimUser);
        ScimGroupMember<ScimUser> member = new ScimGroupMember<>(scimUser);
        memberships.addMember(groupId, member);
        return member;
    }

    private ScimGroupMember addGroupToGroup(String parentGroupId, String childGroupId) {
        ScimGroupMember<ScimGroup> member = new ScimGroupMember<>(dao.retrieve(childGroupId));
        memberships.addMember(parentGroupId, member);
        return member;
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack1Fails() {
        dao.query("displayName='something'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'");
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack2Fails() {
        dao.query("displayName gt 'a'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'");
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack3Fails() {
        dao.query("displayName eq \"something\"; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'");
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack4Fails() {
        dao.query("displayName eq \"something\"; select id from groups where id='''; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something'");
    }

    @Test(expected = IllegalArgumentException.class)
    public void sqlInjectionAttack5Fails() {
        dao.query("displayName eq \"something\"'; select " + SQL_INJECTION_FIELDS
                      + " from groups where displayName='something''");
    }
}
