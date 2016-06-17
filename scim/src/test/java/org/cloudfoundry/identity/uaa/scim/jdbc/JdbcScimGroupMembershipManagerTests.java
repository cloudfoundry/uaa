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
package org.cloudfoundry.identity.uaa.scim.jdbc;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class JdbcScimGroupMembershipManagerTests extends JdbcTestBase {

    private JdbcScimGroupProvisioning gdao;

    private JdbcScimUserProvisioning udao;

    private JdbcScimGroupMembershipManager dao;

    private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";

    private static final String addGroupSqlFormat = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";

    private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities, origin) values ('%s', '%s', '%s', '%s', '%s')";

    @Before
    public void initJdbcScimGroupMembershipManagerTests() {

        JdbcTemplate template = new JdbcTemplate(dataSource);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        udao = new JdbcScimUserProvisioning(template, pagingListFactory);
        gdao = new JdbcScimGroupProvisioning(template, pagingListFactory);

        dao = new JdbcScimGroupMembershipManager(template, pagingListFactory);
        dao.setScimGroupProvisioning(gdao);
        dao.setScimUserProvisioning(udao);
        dao.setDefaultUserGroups(Collections.singleton("uaa.user"));

        addGroup("g1", "test1", IdentityZone.getUaa().getId());
        addGroup("g2", "test2", IdentityZone.getUaa().getId());
        addGroup("g3", "test3", IdentityZone.getUaa().getId());
        addUser("m1", "test", IdentityZone.getUaa().getId());
        addUser("m2", "test", IdentityZone.getUaa().getId());
        addUser("m3", "test", IdentityZone.getUaa().getId());

        validateCount(0);
    }

    private void addMember(String gId, String mId, String mType, String authorities) {
        addMember(gId,mId,mType,authorities, Origin.UAA);
    }
    private void addMember(String gId, String mId, String mType, String authorities, String origin) {
        jdbcTemplate.execute(String.format(addMemberSqlFormat, gId, mId, mType, authorities, origin));
    }

    private void addGroup(String id, String name, String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        jdbcTemplate.execute(String.format(addGroupSqlFormat, id, name, zoneId));
    }

    private void addUser(String id, String password, String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, "id", id);
        jdbcTemplate.execute(String.format(addUserSqlFormat, id, id, password, id, id, id, id, "", zoneId));
    }

    private void validateCount(int expected) {
        int existingMemberCount = jdbcTemplate.queryForInt("select count(*) from groups g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id", IdentityZoneHolder.get().getId());
        assertEquals(expected, existingMemberCount);
    }

    private void validateUserGroups(String id, String... gNm) {
        Set<ScimGroup> directGroups = dao.getGroupsWithMember(id, false);
        assertNotNull(directGroups);
        Set<ScimGroup> indirectGroups = dao.getGroupsWithMember(id, true);
        indirectGroups.removeAll(directGroups);
        assertNotNull(indirectGroups);

        Set<String> expectedAuthorities = Collections.<String> emptySet();
        if (gNm != null) {
            expectedAuthorities = new HashSet<>(Arrays.asList(gNm));
        }
        expectedAuthorities.add("uaa.user");

        assertEquals(expectedAuthorities.size(), directGroups.size() + indirectGroups.size());
        for (ScimGroup group : directGroups) {
            assertTrue(expectedAuthorities.contains(group.getDisplayName()));
        }
        for (ScimGroup group : indirectGroups) {
            assertTrue(expectedAuthorities.contains(group.getDisplayName() + ".i"));
        }
    }

    @After
    public void cleanupDataSource() throws Exception {
        IdentityZoneHolder.clear();
        TestUtils.deleteFrom(dataSource, "group_membership");
        TestUtils.deleteFrom(dataSource, "groups");
        TestUtils.deleteFrom(dataSource, "users");
        validateCount(0);
    }

    @Test
    public void canQuery_Filter_Has_ZoneIn_Effect() throws Exception {
        addMembers();
        validateCount(4);
        String id = new RandomValueStringGenerator().generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id,id);
        IdentityZoneHolder.set(zone);
        assertEquals(0,dao.query("origin eq \"" + Origin.UAA + "\"").size());
        assertEquals(0,dao.query("origin eq \"" + Origin.UAA + "\"").size());
        IdentityZoneHolder.clear();
        assertEquals(4,dao.query("origin eq \"" + Origin.UAA + "\"").size());
        assertEquals(4,dao.query("origin eq \"" + Origin.UAA + "\"", "member_id", true).size());
        assertEquals(4,dao.query("origin eq \"" + Origin.UAA + "\"", "1,2", true).size());
        assertEquals(4,dao.query("origin eq \"" + Origin.UAA + "\"", "origin", true).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotQuery_Filter_Has_Unknown_Sort() throws Exception {
        dao.query("origin eq \"" + Origin.UAA + "\"", "unknown,origin", true);
    }


    @Test
    public void canDeleteWithFilter1() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("origin eq \"" + Origin.UAA + "\"");
        validateCount(0);
    }

    @Test
    public void canDeleteWithFilter2() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("origin eq \""+ Origin.ORIGIN +"\"");
        validateCount(4);
    }

    @Test
    public void canDeleteWithFilter3() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id eq \"m3\" and origin eq \""+ Origin.UAA +"\"");
        validateCount(2);
    }

    @Test
    public void canDeleteWithFilter4() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id sw \"m\" and origin eq \""+ Origin.UAA +"\"");
        validateCount(1);
    }

    @Test
    public void canDeleteWithFilter5() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id sw \"m\" and origin eq \""+ Origin.LDAP +"\"");
        validateCount(4);
    }

    @Test
    public void cannot_Delete_With_Filter_Outside_Zone() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        addMembers();
        validateCount(4);
        IdentityZone zone = MultitenancyFixture.identityZone(id,id);
        IdentityZoneHolder.set(zone);
        dao.delete("member_id eq \"m3\" and origin eq \"" + Origin.UAA + "\"");
        IdentityZoneHolder.clear();
        validateCount(4);
    }


    @Test
    public void canGetGroupsForMember() {
        addMembers();

        Set<ScimGroup> groups = dao.getGroupsWithMember("g2", false);
        assertNotNull(groups);
        assertEquals(1, groups.size());

        groups = dao.getGroupsWithMember("m3", true);
        assertNotNull(groups);
        assertEquals(3, groups.size());
    }

    private void addMembers() {
        addMember("g1", "m3", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");
        addMember("g2", "m3", "USER", "READER");
    }

    @Test
    public void canGetGroupsForMemberEvenWhenCycleExistsInGroupHierarchy() {
        addMember("g1", "m3", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g2", "g3", "GROUP", "READER");
        addMember("g3", "g1", "GROUP", "READER");

        Set<ScimGroup> groups = dao.getGroupsWithMember("m3", true);
        assertNotNull(groups);
        assertEquals(4, groups.size());
    }

    @Test
    public void canAddMember() throws Exception {
        validateCount(0);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
        ScimGroupMember m2 = dao.addMember("g2", m1);
        validateCount(1);
        assertEquals(ScimGroupMember.Type.USER, m2.getType());
        assertEquals(ScimGroupMember.GROUP_MEMBER, m2.getRoles());
        assertEquals("m1", m2.getMemberId());
        validateUserGroups("m1", "test2");
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void addMember_In_Different_Zone_Causes_Issues() throws Exception {
        String subdomain = new RandomValueStringGenerator().generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneHolder.set(otherZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
        m1.setOrigin(Origin.UAA);
        dao.addMember("g2", m1);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void canAddMember_Validate_Origin_and_ZoneId() throws Exception {
        String subdomain = new RandomValueStringGenerator().generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneHolder.set(otherZone);
        validateCount(0);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
        m1.setOrigin(Origin.UAA);
        dao.addMember("g2", m1);
    }

    @Test
    public void canAddNestedGroupMember() {
        addMember("g2", "m1", "USER", "READER");

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
        g2 = dao.addMember("g1", g2);
        assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
        assertEquals(ScimGroupMember.GROUP_ADMIN, g2.getRoles());
        assertEquals("g2", g2.getMemberId());
        validateUserGroups("m1", "test1.i", "test2");
    }

    @Test(expected = InvalidScimResourceException.class)
    public void cannotNestGroupWithinItself() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
        dao.addMember("g2", g2);
    }

    @Test
    public void canGetMembers() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");

        List<ScimGroupMember> members = dao.getMembers("g1");
        assertNotNull(members);
        assertEquals(2, members.size());

        members = dao.getMembers("g2");
        assertNotNull(members);
        assertEquals(0, members.size());

    }

    @Test
    public void canGetMembers_Fails_In_Other_Zone() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");
        IdentityZoneHolder.set(MultitenancyFixture.identityZone(new RandomValueStringGenerator().generate(), new RandomValueStringGenerator().generate()));
        assertEquals(0, dao.getMembers("g1").size());
    }

    @Test
    public void testBackwardsCompatibilityToMemberAuthorities() {
        addMember("g1", "m1", "USER", "READ");
        addMember("g1", "g2", "GROUP", "member");
        addMember("g1", "m2", "USER", "READER,write");

        List<ScimGroupMember> members = dao.getMembers("g1");
        assertNotNull(members);
        assertEquals(3, members.size());
        List<ScimGroupMember> readers = new ArrayList<ScimGroupMember>(), writers = new ArrayList<ScimGroupMember>();
        for (ScimGroupMember member : members) {
            if (member.getRoles().contains(ScimGroupMember.Role.READER)) {
                readers.add(member);
            }
            if (member.getRoles().contains(ScimGroupMember.Role.WRITER)) {
                writers.add(member);
            }
        }
        assertEquals(2, readers.size());
        assertEquals(1, writers.size());
    }

    @Test
    public void canGetDefaultGroupsUsingGetGroupsForMember() {
        Set<ScimGroup> groups = dao.getGroupsWithMember("m1", false);
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    public void canGetAdminMembers() {
        addMember("g1", "m3", "USER", "READER,WRITER");
        addMember("g1", "g2", "GROUP", "READER");

        assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.WRITER).size());
        assertTrue(dao.getMembers("g1", ScimGroupMember.Role.WRITER).contains(new ScimGroupMember("m3")));

        assertEquals(0, dao.getMembers("g2", ScimGroupMember.Role.WRITER).size());
    }

    @Test
    public void canGetMembersByAuthority() {
        addMember("g1", "m3", "USER", "READER,WRITER");
        addMember("g1", "g2", "GROUP", "READER,MEMBER");
        addMember("g2", "g3", "GROUP", "MEMBER");

        assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.MEMBER).size());
        assertEquals(2, dao.getMembers("g1", ScimGroupMember.Role.READER).size());
        assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.WRITER).size());

        assertEquals(1, dao.getMembers("g2", ScimGroupMember.Role.MEMBER).size());
        assertEquals(0, dao.getMembers("g2", ScimGroupMember.Role.WRITER).size());
    }

    @Test
    public void canGetMemberById() throws Exception {
        addMember("g3", "m2", "USER", "READER,WRITER");

        ScimGroupMember m = dao.getMemberById("g3", "m2");
        assertEquals(ScimGroupMember.Type.USER, m.getType());
        assertEquals(ScimGroupMember.GROUP_ADMIN, m.getRoles());
    }

    @Test
    public void canUpdateMember() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        validateCount(1);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
        ScimGroupMember m2 = dao.updateMember("g1", m1);
        assertEquals(ScimGroupMember.GROUP_ADMIN, m2.getRoles());
        assertNotSame(m1, m2);

        validateCount(1);
        validateUserGroups("m1", "test1");
    }

    @Test
    public void canUpdateOrAddMembers() {
        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
        validateCount(3);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
        ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
        List<ScimGroupMember> members = dao.updateOrAddMembers("g1", Arrays.asList(g2, m3));

        validateCount(3);
        assertEquals(2, members.size());
        assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, null)));
        assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER, null)));
        assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER, null)));
        validateUserGroups("m3", "test1");
        validateUserGroups("m2", "test2", "test1.i");
        validateUserGroups("m1");
    }

    @Test
    public void canRemoveMemberById() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        validateCount(1);

        dao.removeMemberById("g1", "m1");
        validateCount(0);
        try {
            dao.getMemberById("g1", "m1");
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {

        }
    }

    @Test
    public void canRemoveNestedGroupMember() {
        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
        validateCount(3);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        dao.removeMemberById("g1", "g2");
        try {
            dao.getMemberById("g1", "g2");
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateCount(2);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2");

    }

    @Test
    public void canRemoveAllMembers() {
        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
        validateCount(3);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        dao.removeMembersByGroupId("g1");
        validateCount(1);
        try {
            dao.getMemberById("g1", "m1");
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateUserGroups("m1");
        validateUserGroups("m2", "test2");

    }
}
