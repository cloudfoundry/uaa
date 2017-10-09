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
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

public class JdbcScimGroupMembershipManagerTests extends JdbcTestBase {

    private JdbcScimGroupProvisioning gdao;

    private JdbcScimUserProvisioning udao;

    private JdbcScimGroupMembershipManager dao;

    private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";

    private static final String addGroupSqlFormat = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";

    private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s')";

    private static final String addExternalMapSql = "insert into external_group_mapping (group_id, external_group, added, origin, identity_zone_id) values (?, ?, ?, ?, ?)";

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private IdentityZone zone = MultitenancyFixture.identityZone(generator.generate(), generator.generate());

    @Before
    public void initJdbcScimGroupMembershipManagerTests() {
        JdbcTemplate template = new JdbcTemplate(dataSource);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        udao = new JdbcScimUserProvisioning(template, pagingListFactory);
        gdao = new JdbcScimGroupProvisioning(template, pagingListFactory);

        dao = new JdbcScimGroupMembershipManager(template);
        dao.setScimGroupProvisioning(gdao);
        dao.setScimUserProvisioning(udao);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(asList("uaa.user"));
        gdao.createOrGet(new ScimGroup(null, "uaa.user", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        for (String id : Arrays.asList(zone.getId(), IdentityZone.getUaa().getId())) {
            String g1 = id.equals(zone.getId()) ? zone.getId() + "-g1" : "g1";
            String g2 = id.equals(zone.getId()) ? zone.getId() + "-g2" : "g2";
            String g3 = id.equals(zone.getId()) ? zone.getId() + "-g3" : "g3";
            String m1 = id.equals(zone.getId()) ? zone.getId() + "-m1" : "m1";
            String m2 = id.equals(zone.getId()) ? zone.getId() + "-m2" : "m2";
            String m3 = id.equals(zone.getId()) ? zone.getId() + "-m3" : "m3";
            String m4 = id.equals(zone.getId()) ? zone.getId() + "-m4" : "m4";
            addGroup(g1, "test1", id);
            addGroup(g2, "test2", id);
            addGroup(g3, "test3", id);
            addUser(m1, "test", id);
            addUser(m2, "test", id);
            addUser(m3, "test", id);
            addUser(m4, "test", id);
            mapExternalGroup(g1, g1 + "-external", UAA);
            mapExternalGroup(g2, g2 + "-external", LOGIN_SERVER);
            mapExternalGroup(g3, g3 + "-external", UAA);
        }
        validateCount(0);
    }

    private void mapExternalGroup(String gId, String external, String origin) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(addExternalMapSql, gId, external, now, origin, IdentityZoneHolder.get().getId());
    }

    private void addMember(String gId, String mId, String mType, String origin) {
        gId = IdentityZoneHolder.isUaa() ? gId : IdentityZoneHolder.get().getId()+"-"+gId;
        mId = IdentityZoneHolder.isUaa() ? mId : IdentityZoneHolder.get().getId()+"-"+mId;
        jdbcTemplate.execute(String.format(addMemberSqlFormat, gId, mId, mType, origin, IdentityZoneHolder.get().getId()));
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
        validateCount(expected, "No message given.");
    }

    private void validateCount(int expected, String msg) {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from groups g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class);
        assertEquals(msg, expected, existingMemberCount);
    }

    private void validateUserGroups(String id, String... gNm) {
        Set<ScimGroup> directGroups = dao.getGroupsWithMember(id, false, IdentityZoneHolder.get().getId());
        assertNotNull(directGroups);
        Set<ScimGroup> indirectGroups = dao.getGroupsWithMember(id, true, IdentityZoneHolder.get().getId());
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
    }

    @Test
    public void default_groups_are_cached() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        List<String> defaultGroups = Arrays.asList("g1", "g2", "g3");
        zone.getConfig().getUserConfig().setDefaultGroups(defaultGroups);
        IdentityZoneHolder.set(zone);
        JdbcScimGroupProvisioning spy = spy(gdao);
        dao.setScimGroupProvisioning(spy);
        defaultGroups.stream().forEach(g -> dao.createOrGetGroup(g, zone.getId()));
        defaultGroups.stream().forEach(g -> verify(spy, times(1)).createAndIgnoreDuplicate(eq(g), eq(zone.getId())));
        reset(spy);
        defaultGroups.stream().forEach(g -> dao.createOrGetGroup(g, zone.getId()));
        verifyZeroInteractions(spy);
    }

    @Test
    public void delete_by_member() throws Exception {
        addMember("g1", "m3", "USER", LDAP);
        addMember("g1", "g2", "GROUP",LDAP);
        addMember("g3", "m2", "USER", UAA);
        addMember("g2", "m3", "USER", UAA);
        validateCount(4);
        dao.removeMembersByMemberId("m3", IdentityZoneHolder.get().getId());
        validateCount(2);
    }

    @Test
    public void delete_by_member_and_origin() throws Exception {
        addMember("g1", "m3", "USER", LDAP);
        addMember("g1", "g2", "GROUP",LDAP);
        addMember("g3", "m2", "USER", UAA);
        addMember("g2", "m3", "USER", UAA);
        validateCount(4);
        dao.removeMembersByMemberId("m3", "non-existent-origin", IdentityZoneHolder.get().getId());
        validateCount(4);
        dao.removeMembersByMemberId("m3", LDAP, IdentityZoneHolder.get().getId());
        validateCount(3);
    }


    @Test
    public void canDeleteWithOrigin() throws Exception {
        addMembers();
        validateCount(4);
        dao.deleteMembersByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        validateCount(0);
    }

    @Test
    public void canDeleteWithOrigin2() throws Exception {
        addMembers();
        validateCount(4);
        dao.deleteMembersByOrigin(OriginKeys.ORIGIN, IdentityZoneHolder.get().getId());
        validateCount(4);
    }

    @Test
    public void canDeleteWithOrigin3() throws Exception {
        addMembers();
        validateCount(4);
        dao.removeMembersByMemberId("m3",  OriginKeys.UAA);
        validateCount(2);
    }

    @Test
    public void cannot_Delete_With_Filter_Outside_Zone() throws Exception {
        String id = generator.generate();
        addMembers();
        validateCount(4);
        IdentityZone zone = MultitenancyFixture.identityZone(id,id);
        IdentityZoneHolder.set(zone);
        dao.removeMembersByMemberId("m3", OriginKeys.UAA);
        IdentityZoneHolder.clear();
        validateCount(4);
    }


    @Test
    public void canGetGroupsForMember() {
        addMembers();

        Set<ScimGroup> groups = dao.getGroupsWithMember("g2", false, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());

        groups = dao.getGroupsWithMember("m3", true, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(3, groups.size());
    }

    private void addMembers(String origin) {
        addMember("g1", "m3", "USER", origin);
        addMember("g1", "g2", "GROUP",origin);
        addMember("g3", "m2", "USER", origin);
        addMember("g2", "m3", "USER", origin);
    }
    private void addMembers() {
        addMembers(OriginKeys.UAA);
    }

    @Test
    public void user_delete_clears_memberships() throws Exception {
        UaaUserPrototype prototype = new UaaUserPrototype()
            .withUsername("username")
            .withEmail("test@test.com");

        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            String userId = this.zone.getId().equals(zone.getId()) ? zone.getId()+"-"+"m3" : "m3";
            UaaUser user = new UaaUser(prototype.withId(userId).withZoneId(zone.getId()));
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP);
            validateCount(4);
            IdentityZoneHolder.clear();
            gdao.onApplicationEvent(new EntityDeletedEvent<>(user, mock(Authentication.class)));
            IdentityZoneHolder.set(zone);
            validateCount(2, "ZoneID: "+zone.getId());
        }
    }

    @Test
    public void zone_delete_clears_memberships() throws Exception {
        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP);
            validateCount(4);
            IdentityZoneHolder.clear();
            gdao.onApplicationEvent(new EntityDeletedEvent<>(zone, mock(Authentication.class)));
            validateCount(Objects.equals(zone, IdentityZone.getUaa()) ? 4 : 0, "ZoneID: "+zone.getId());
        }
    }

    @Test
    public void provider_delete_clears_memberships() throws Exception {
        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP);
            validateCount(4, "ZoneID: "+zone.getId());
            IdentityZoneHolder.clear();
            IdentityProvider provider = new IdentityProvider()
                .setId("ldap-id")
                .setOriginKey(LDAP)
                .setIdentityZoneId(zone.getId());
            gdao.onApplicationEvent(new EntityDeletedEvent<>(provider, mock(Authentication.class)));
            IdentityZoneHolder.set(zone);
            validateCount(0, "ZoneID: "+zone.getId());
        }
    }

    @Test
    public void test_zone_deleted() {
        String zoneAdminId = generator.generate();
        addGroup(zoneAdminId, "zones." + zone.getId() + ".admin", IdentityZone.getUaa().getId());
        addMember(zoneAdminId, "m1", "USER", OriginKeys.UAA);

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
        mapExternalGroup("g1", "some-external-group", LOGIN_SERVER);
        mapExternalGroup("g1", "some-external-group", UAA);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[] {IdentityZoneHolder.get().getId(), LOGIN_SERVER}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[] {LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
            new IdentityProvider()
                .setOriginKey(LOGIN_SERVER)
                .setIdentityZoneId(zone.getId());
        EntityDeletedEvent<IdentityProvider> event = new EntityDeletedEvent<>(loginServer, null);
        gdao.onApplicationEvent(event);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[] {IdentityZoneHolder.get().getId(), LOGIN_SERVER}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[] {LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(0));
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

        Set<ScimGroup> groups = dao.getGroupsWithMember("m3", true, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(4, groups.size());
    }

    @Test
    public void canAddMember() throws Exception {
        validateCount(0);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = dao.addMember("g2", m1, IdentityZoneHolder.get().getId());
        validateCount(1);
        assertEquals(ScimGroupMember.Type.USER, m2.getType());
        assertEquals("m1", m2.getMemberId());
        validateUserGroups("m1", "test2");
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void addMember_In_Different_Zone_Causes_Issues() throws Exception {
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        otherZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        dao.addMember("g2", m1, IdentityZoneHolder.get().getId());
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void canAddMember_Validate_Origin_and_ZoneId() throws Exception {
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        otherZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherZone);
        validateCount(0);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        dao.addMember("g2", m1, IdentityZoneHolder.get().getId());
    }

    @Test
    public void canAddNestedGroupMember() {
        addMember("g2", "m1", "USER", "READER");

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        g2 = dao.addMember("g1", g2, IdentityZoneHolder.get().getId());
        assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
        assertEquals("g2", g2.getMemberId());
        validateUserGroups("m1", "test1.i", "test2");
    }

    @Test(expected = InvalidScimResourceException.class)
    public void cannotNestGroupWithinItself() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        dao.addMember("g2", g2, IdentityZoneHolder.get().getId());
    }

    @Test
    public void canGetMembers() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");

        List<ScimGroupMember> members = dao.getMembers("g1", false, IdentityZoneHolder.get().getId());
        assertNotNull(members);
        assertEquals(2, members.size());

        members = dao.getMembers("g2", false, IdentityZoneHolder.get().getId());
        assertNotNull(members);
        assertEquals(0, members.size());

    }

    @Test
    public void canGetMembers_Fails_In_Other_Zone() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        addMember("g1", "g2", "GROUP", "READER");
        addMember("g3", "m2", "USER", "READER,WRITER");
        IdentityZoneHolder.set(MultitenancyFixture.identityZone(generator.generate(), generator.generate()));
        assertEquals(0, dao.getMembers("g1", false, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canReadNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
            "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', NULL, '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "uaa", IdentityZoneHolder.get().getId()));

        ScimGroupMember member = dao.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    public void canReadNonNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
            "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "ANYTHING", "uaa", IdentityZoneHolder.get().getId()));

        ScimGroupMember member = dao.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    public void canGetDefaultGroupsUsingGetGroupsForMember() {
        Set<ScimGroup> groups = dao.getGroupsWithMember("m1", false, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    public void canGetMemberById() throws Exception {
        addMember("g3", "m2", "USER", "READER,WRITER");

        ScimGroupMember m = dao.getMemberById("g3", "m2", IdentityZoneHolder.get().getId());
        assertEquals(ScimGroupMember.Type.USER, m.getType());
    }

    @Test
    public void canUpdateOrAddMembers() {
        String zoneId = IdentityZoneHolder.get().getId();

        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), zoneId);
        dao.addMember("g1", new ScimGroupMember("m4", ScimGroupMember.Type.USER), zoneId);
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), zoneId);

        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), zoneId);

        validateCount(4);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        JdbcScimGroupMembershipManager spy = spy(dao);

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP); // update role member->admin
        ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER); // new member
        ScimGroupMember m4 = new ScimGroupMember("m4", ScimGroupMember.Type.USER); // does not change

        List<ScimGroupMember> members = spy.updateOrAddMembers("g1", Arrays.asList(g2, m3, m4), zoneId);

        validateCount(4);
        verify(spy).addMember("g1", m3, zoneId);
        verify(spy, times(0)).addMember("g1", m4, zoneId);
        verify(spy).removeMemberById("g1", "m1", zoneId);
        assertEquals(3, members.size());
        assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP)));
        assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER)));
        assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER)));
        validateUserGroups("m3", "test1");
        validateUserGroups("m2", "test2", "test1.i");
        validateUserGroups("m1");
    }

    @Test
    public void canRemoveMemberById() throws Exception {
        addMember("g1", "m1", "USER", "READER");
        validateCount(1);

        dao.removeMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        validateCount(0);
        try {
            dao.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {

        }
    }

    @Test
    public void canRemoveNestedGroupMember() {
        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), IdentityZoneHolder.get().getId());
        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        validateCount(3);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        dao.removeMemberById("g1", "g2", IdentityZoneHolder.get().getId());
        try {
            dao.getMemberById("g1", "g2", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateCount(2);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2");

    }

    @Test
    public void canRemoveAllMembers() {
        dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), IdentityZoneHolder.get().getId());
        dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        validateCount(3);
        validateUserGroups("m1", "test1");
        validateUserGroups("m2", "test2", "test1.i");

        dao.removeMembersByGroupId("g1", IdentityZoneHolder.get().getId());
        validateCount(1);
        try {
            dao.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateUserGroups("m1");
        validateUserGroups("m2", "test2");

    }

    @Test
    public void canGetGroupsWithExternalMember() {
        addMember("g1", "m1", "MEMBER", zone.getId());
        addMember("g2", "m1", "MEMBER", zone.getId());

        Set<ScimGroup> groups = dao.getGroupsWithExternalMember("m1", zone.getId());

        assertThat(groups.size(), equalTo(2));

        List<String> groupIds = groups.stream().map(ScimGroup::getId).collect(Collectors.toList());
        assertThat(groupIds, hasItem("g1"));
        assertThat(groupIds, hasItem("g2"));
    }

}
