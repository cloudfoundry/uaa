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

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
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

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class JdbcScimGroupMembershipManagerTests extends JdbcTestBase {

    private JdbcScimGroupProvisioning gdao;

    private JdbcScimUserProvisioning udao;

    private JdbcScimGroupMembershipManager dao;

    private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";

    private static final String addGroupSqlFormat = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";

    private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities, origin) values ('%s', '%s', '%s', '%s', '%s')";

    private static final String addExternalMapSql = "insert into external_group_mapping (group_id, external_group, added, origin) values (?, ?, ?, ?)";

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private IdentityZone zone = MultitenancyFixture.identityZone(generator.generate(), generator.generate());

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

        for (String id : Arrays.asList(zone.getId(), IdentityZone.getUaa().getId())) {
            String g1 = id.equals(zone.getId()) ? zone.getId()+"-"+"g1" : "g1";
            String g2 = id.equals(zone.getId()) ? zone.getId()+"-"+"g2" : "g2";
            String g3 = id.equals(zone.getId()) ? zone.getId()+"-"+"g3" : "g3";
            String m1 = id.equals(zone.getId()) ? zone.getId()+"-"+"m1" : "m1";
            String m2 = id.equals(zone.getId()) ? zone.getId()+"-"+"m2" : "m2";
            String m3 = id.equals(zone.getId()) ? zone.getId()+"-"+"m3" : "m3";
            addGroup(g1, "test1", id);
            addGroup(g2, "test2", id);
            addGroup(g3, "test3", id);
            addUser(m1, "test", id);
            addUser(m2, "test", id);
            addUser(m3, "test", id);
            mapExternalGroup(g1, g1+"-external", UAA);
            mapExternalGroup(g2, g2+"-external", LOGIN_SERVER);
            mapExternalGroup(g3, g3+"-external", UAA);
        }
        validateCount(0);
    }

    private void mapExternalGroup(String gId, String external, String origin) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(addExternalMapSql, gId, external, now, origin);
    }

    private void addMember(String gId, String mId, String mType, String authorities) {
        addMember(gId,mId,mType,authorities, OriginKeys.UAA);
    }
    private void addMember(String gId, String mId, String mType, String authorities, String origin) {
        gId = IdentityZoneHolder.isUaa() ? gId : IdentityZoneHolder.get().getId()+"-"+gId;
        mId = IdentityZoneHolder.isUaa() ? mId : IdentityZoneHolder.get().getId()+"-"+mId;
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
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from groups g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class);
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
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id,id);
        IdentityZoneHolder.set(zone);
        assertEquals(0,dao.query("origin eq \"" + OriginKeys.UAA + "\"").size());
        IdentityZoneHolder.clear();
        assertEquals(4,dao.query("origin eq \"" + OriginKeys.UAA + "\"").size());
        assertEquals(4,dao.query("origin eq \"" + OriginKeys.UAA + "\"", "member_id", true).size());
        assertEquals(4,dao.query("origin eq \"" + OriginKeys.UAA + "\"", "1,2", true).size());
        assertEquals(4,dao.query("origin eq \"" + OriginKeys.UAA + "\"", "origin", true).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void cannotQuery_Filter_Has_Unknown_Sort() throws Exception {
        dao.query("origin eq \"" + OriginKeys.UAA + "\"", "unknown,origin", true);
    }


    @Test
    public void canDeleteWithFilter1() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("origin eq \"" + OriginKeys.UAA + "\"");
        validateCount(0);
    }

    @Test
    public void canDeleteWithFilter2() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("origin eq \""+ OriginKeys.ORIGIN +"\"");
        validateCount(4);
    }

    @Test
    public void canDeleteWithFilter3() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id eq \"m3\" and origin eq \""+ OriginKeys.UAA +"\"");
        validateCount(2);
    }

    @Test
    public void canDeleteWithFilter4() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id sw \"m\" and origin eq \""+ OriginKeys.UAA +"\"");
        validateCount(1);
    }

    @Test
    public void canDeleteWithFilter5() throws Exception {
        addMembers();
        validateCount(4);
        dao.delete("member_id sw \"m\" and origin eq \""+ OriginKeys.LDAP +"\"");
        validateCount(4);
    }

    @Test
    public void cannot_Delete_With_Filter_Outside_Zone() throws Exception {
        String id = generator.generate();
        addMembers();
        validateCount(4);
        IdentityZone zone = MultitenancyFixture.identityZone(id,id);
        IdentityZoneHolder.set(zone);
        dao.delete("member_id eq \"m3\" and origin eq \"" + OriginKeys.UAA + "\"");
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

    private void addMembers(String origin) {
        addMember("g1", "m3", "USER", "READER", origin);
        addMember("g1", "g2", "GROUP", "READER", origin);
        addMember("g3", "m2", "USER", "READER,WRITER", origin);
        addMember("g2", "m3", "USER", "READER", origin);
    }
    private void addMembers() {
        addMembers(OriginKeys.UAA);
    }

    @Test
    public void test_zone_deleted() {
        String zoneAdminId = generator.generate();
        addGroup(zoneAdminId, "zones." + zone.getId() + ".admin", IdentityZone.getUaa().getId());
        addMember(zoneAdminId, "m1", "USER", "MEMBER", OriginKeys.UAA);

        IdentityZoneHolder.set(zone);
        addMembers();
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaa().getId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaa().getId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(1));
        gdao.onApplicationEvent(new EntityDeletedEvent<>(zone, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaa().getId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaa().getId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(0));
    }

    @Test
    public void test_provider_deleted() {
        IdentityZoneHolder.set(zone);
        addMembers(LOGIN_SERVER);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and group_id in (select id from groups where identity_zone_id=?)", new Object[] {LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(LOGIN_SERVER)
                .setIdentityZoneId(zone.getId());
        gdao.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and group_id in (select id from groups where identity_zone_id=?)", new Object[] {LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(0));
    }

    @Test
    public void test_cannot_delete_uaa_zone() {
        addMembers();
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        gdao.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
    }

    @Test
    public void test_cannot_delete_uaa_provider() {
        IdentityZoneHolder.set(zone);
        addMembers(LOGIN_SERVER);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(UAA)
                .setIdentityZoneId(zone.getId());
        gdao.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));

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
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneHolder.set(otherZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
        m1.setOrigin(OriginKeys.UAA);
        dao.addMember("g2", m1);
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void canAddMember_Validate_Origin_and_ZoneId() throws Exception {
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneHolder.set(otherZone);
        validateCount(0);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
        m1.setOrigin(OriginKeys.UAA);
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

        List<ScimGroupMember> members = dao.getMembers("g1", null, false);
        assertNotNull(members);
        assertEquals(2, members.size());

        members = dao.getMembers("g2", null, false);
        assertNotNull(members);
        assertEquals(0, members.size());

    }

    @Test
    public void canGetMembers_Fails_In_Other_Zone() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");
        IdentityZoneHolder.set(MultitenancyFixture.identityZone(generator.generate(), generator.generate()));
        assertEquals(0, dao.getMembers("g1", null, false).size());
    }

    @Test
    public void testBackwardsCompatibilityToMemberAuthorities() {
        addMember("g1", "m1", "USER", "READ");
        addMember("g1", "g2", "GROUP", "member");
        addMember("g1", "m2", "USER", "READER,write");

        List<ScimGroupMember> members = dao.getMembers("g1", null, false);
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
