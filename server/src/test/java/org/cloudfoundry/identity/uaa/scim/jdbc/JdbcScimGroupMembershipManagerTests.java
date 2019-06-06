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
import org.cloudfoundry.identity.uaa.util.FakePasswordEncoder;
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
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.*;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class JdbcScimGroupMembershipManagerTests extends JdbcTestBase {

    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;

    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    private static final String ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";
    private static final String ADD_GROUP_SQL_FORMAT = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";
    private static final String ADD_MEMBER_SQL_FORMAT = "insert into group_membership (group_id, member_id, member_type, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s')";
    private static final String ADD_EXTERNAL_MAP_SQL = "insert into external_group_mapping (group_id, external_group, added, origin, identity_zone_id) values (?, ?, ?, ?, ?)";

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private IdentityZone zone = MultitenancyFixture.identityZone(generator.generate(), generator.generate());

    @Before
    public void initJdbcScimGroupMembershipManagerTests() {
        JdbcTemplate template = new JdbcTemplate(dataSource);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        JdbcScimUserProvisioning jdbcScimUserProvisioning = new JdbcScimUserProvisioning(template, pagingListFactory, new FakePasswordEncoder());
        jdbcScimGroupProvisioning = new JdbcScimGroupProvisioning(template, pagingListFactory);

        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(template);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(jdbcScimGroupProvisioning);
        jdbcScimGroupMembershipManager.setScimUserProvisioning(jdbcScimUserProvisioning);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        jdbcScimGroupProvisioning.createOrGet(new ScimGroup(null, "uaa.user", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        for (String id : Arrays.asList(zone.getId(), IdentityZone.getUaaZoneId())) {
            String g1 = id.equals(zone.getId()) ? zone.getId() + "-g1" : "g1";
            String g2 = id.equals(zone.getId()) ? zone.getId() + "-g2" : "g2";
            String g3 = id.equals(zone.getId()) ? zone.getId() + "-g3" : "g3";
            String m1 = id.equals(zone.getId()) ? zone.getId() + "-m1" : "m1";
            String m2 = id.equals(zone.getId()) ? zone.getId() + "-m2" : "m2";
            String m3 = id.equals(zone.getId()) ? zone.getId() + "-m3" : "m3";
            String m4 = id.equals(zone.getId()) ? zone.getId() + "-m4" : "m4";
            addGroup(g1, "test1", id, jdbcTemplate);
            addGroup(g2, "test2", id, jdbcTemplate);
            addGroup(g3, "test3", id, jdbcTemplate);
            addUser(m1, "test", id, jdbcTemplate);
            addUser(m2, "test", id, jdbcTemplate);
            addUser(m3, "test", id, jdbcTemplate);
            addUser(m4, "test", id, jdbcTemplate);
            mapExternalGroup(g1, g1 + "-external", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
            mapExternalGroup(g2, g2 + "-external", LOGIN_SERVER, jdbcTemplate, IdentityZoneHolder.get().getId());
            mapExternalGroup(g3, g3 + "-external", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        }
        validateCount(0, jdbcTemplate);
    }

    @After
    public void cleanupDataSource() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void defaultGroupsAreCached() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        List<String> defaultGroups = Arrays.asList("g1", "g2", "g3");
        zone.getConfig().getUserConfig().setDefaultGroups(defaultGroups);
        IdentityZoneHolder.set(zone);
        JdbcScimGroupProvisioning spy = spy(jdbcScimGroupProvisioning);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(spy);
        defaultGroups.forEach(g -> jdbcScimGroupMembershipManager.createOrGetGroup(g, zone.getId()));
        defaultGroups.forEach(g -> verify(spy, times(1)).createAndIgnoreDuplicate(eq(g), eq(zone.getId())));
        reset(spy);
        defaultGroups.forEach(g -> jdbcScimGroupMembershipManager.createOrGetGroup(g, zone.getId()));
        verifyZeroInteractions(spy);
    }

    @Test
    public void deleteByMember() {
        addMember("g1", "m3", "USER", LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g1", "g2", "GROUP", LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g3", "m2", "USER", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g2", "m3", "USER", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", IdentityZoneHolder.get().getId());
        validateCount(2, jdbcTemplate);
    }

    @Test
    public void deleteByMemberAndOrigin() {
        addMember("g1", "m3", "USER", LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g1", "g2", "GROUP", LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g3", "m2", "USER", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g2", "m3", "USER", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", "non-existent-origin", IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", LDAP, IdentityZoneHolder.get().getId());
        validateCount(3, jdbcTemplate);
    }

    @Test
    public void canDeleteWithOrigin() {
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        validateCount(0, jdbcTemplate);
    }

    @Test
    public void canDeleteWithOrigin2() {
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.ORIGIN, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
    }

    @Test
    public void canDeleteWithOrigin3() {
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", OriginKeys.UAA);
        validateCount(2, jdbcTemplate);
    }

    @Test
    public void cannotDeleteWithFilterOutsideZone() {
        String id = generator.generate();
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(4, jdbcTemplate);
        IdentityZone zone = MultitenancyFixture.identityZone(id, id);
        IdentityZoneHolder.set(zone);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", OriginKeys.UAA);
        IdentityZoneHolder.clear();
        validateCount(4, jdbcTemplate);
    }

    @Test
    public void canGetGroupsForMember() {
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("g2", false, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());

        groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(3, groups.size());
    }

    @Test
    public void userDeleteClearsMemberships() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withUsername("username")
                .withEmail("test@test.com");

        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            String userId = this.zone.getId().equals(zone.getId()) ? zone.getId() + "-" + "m3" : "m3";
            UaaUser user = new UaaUser(prototype.withId(userId).withZoneId(zone.getId()));
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
            validateCount(4, jdbcTemplate);
            IdentityZoneHolder.clear();
            jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(user, mock(Authentication.class), IdentityZoneHolder.getCurrentZoneId()));
            IdentityZoneHolder.set(zone);
            validateCount(2, "ZoneID: " + zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    public void zoneDeleteClearsMemberships() {
        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
            validateCount(4, jdbcTemplate);
            IdentityZoneHolder.clear();
            jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(zone, mock(Authentication.class), IdentityZoneHolder.getCurrentZoneId()));
            validateCount(Objects.equals(zone, IdentityZone.getUaa()) ? 4 : 0, "ZoneID: " + zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    public void providerDeleteClearsMemberships() {
        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            IdentityZoneHolder.set(zone);
            addMembers(OriginKeys.LDAP, jdbcTemplate, IdentityZoneHolder.get().getId());
            validateCount(4, "ZoneID: " + zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());
            IdentityZoneHolder.clear();
            IdentityProvider provider = new IdentityProvider()
                    .setId("ldap-id")
                    .setOriginKey(LDAP)
                    .setIdentityZoneId(zone.getId());
            jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(provider, mock(Authentication.class), IdentityZoneHolder.getCurrentZoneId()));
            IdentityZoneHolder.set(zone);
            validateCount(0, "ZoneID: " + zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());
        }
    }

    @Test
    public void zoneDeleted() {
        String zoneAdminId = generator.generate();
        addGroup(zoneAdminId, "zones." + zone.getId() + ".admin", IdentityZone.getUaaZoneId(), jdbcTemplate);
        addMember(zoneAdminId, "m1", "USER", OriginKeys.UAA, jdbcTemplate, IdentityZoneHolder.get().getId());

        IdentityZoneHolder.set(zone);
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaaZoneId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaaZoneId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(1));
        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(zone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaaZoneId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaaZoneId(), "zones." + IdentityZoneHolder.get().getId() + ".%"}, Integer.class), is(0));
    }

    @Test
    public void providerDeleted() {
        IdentityZoneHolder.set(zone);
        addMembers(LOGIN_SERVER, jdbcTemplate, IdentityZoneHolder.get().getId());
        mapExternalGroup("g1", "some-external-group", LOGIN_SERVER, jdbcTemplate, IdentityZoneHolder.get().getId());
        mapExternalGroup("g1", "some-external-group", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[]{IdentityZoneHolder.get().getId(), LOGIN_SERVER}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[]{LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(zone.getId());
        EntityDeletedEvent<IdentityProvider> event = new EntityDeletedEvent<>(loginServer, null, IdentityZoneHolder.getCurrentZoneId());
        jdbcScimGroupProvisioning.onApplicationEvent(event);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[]{IdentityZoneHolder.get().getId(), LOGIN_SERVER}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[]{LOGIN_SERVER, IdentityZoneHolder.get().getId()}, Integer.class), is(0));
    }

    @Test
    public void cannotDeleteUaaZone() {
        addMembers(jdbcTemplate, IdentityZoneHolder.get().getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
    }

    @Test
    public void cannotDeleteUaaProvider() {
        IdentityZoneHolder.set(zone);
        addMembers(LOGIN_SERVER, jdbcTemplate, IdentityZoneHolder.get().getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(zone.getId());
        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(3));

    }

    @Test
    public void canGetGroupsForMemberEvenWhenCycleExistsInGroupHierarchy() {
        addMember("g1", "m3", "USER", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g2", "g3", "GROUP", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g3", "g1", "GROUP", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(4, groups.size());
    }

    @Test
    public void canAddMember() {
        validateCount(0, jdbcTemplate);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = jdbcScimGroupMembershipManager.addMember("g2", m1, IdentityZoneHolder.get().getId());
        validateCount(1, jdbcTemplate);
        assertEquals(ScimGroupMember.Type.USER, m2.getType());
        assertEquals("m1", m2.getMemberId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2");
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void addMemberInDifferentZoneCausesIssues() {
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        otherZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        jdbcScimGroupMembershipManager.addMember("g2", m1, IdentityZoneHolder.get().getId());
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void canAddMemberValidateOriginAndZoneId() {
        String subdomain = generator.generate();
        IdentityZone otherZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        otherZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherZone);
        validateCount(0, jdbcTemplate);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        jdbcScimGroupMembershipManager.addMember("g2", m1, IdentityZoneHolder.get().getId());
    }

    @Test
    public void canAddNestedGroupMember() {
        addMember("g2", "m1", "USER", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        g2 = jdbcScimGroupMembershipManager.addMember("g1", g2, IdentityZoneHolder.get().getId());
        assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
        assertEquals("g2", g2.getMemberId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1.i", "test2");
    }

    @Test(expected = InvalidScimResourceException.class)
    public void cannotNestGroupWithinItself() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        jdbcScimGroupMembershipManager.addMember("g2", g2, IdentityZoneHolder.get().getId());
    }

    @Test
    public void canGetMembers() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, IdentityZoneHolder.get().getId());

        List<ScimGroupMember> members = jdbcScimGroupMembershipManager.getMembers("g1", false, IdentityZoneHolder.get().getId());
        assertNotNull(members);
        assertEquals(2, members.size());

        members = jdbcScimGroupMembershipManager.getMembers("g2", false, IdentityZoneHolder.get().getId());
        assertNotNull(members);
        assertEquals(0, members.size());

    }

    @Test
    public void canGetMembers_Fails_In_Other_Zone() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, IdentityZoneHolder.get().getId());
        IdentityZoneHolder.set(MultitenancyFixture.identityZone(generator.generate(), generator.generate()));
        assertEquals(0, jdbcScimGroupMembershipManager.getMembers("g1", false, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canReadNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', NULL, '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "uaa", IdentityZoneHolder.get().getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    public void canReadNonNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "ANYTHING", "uaa", IdentityZoneHolder.get().getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    public void canGetDefaultGroupsUsingGetGroupsForMember() {
        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m1", false, IdentityZoneHolder.get().getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    public void canGetMemberById() {
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, IdentityZoneHolder.get().getId());

        ScimGroupMember m = jdbcScimGroupMembershipManager.getMemberById("g3", "m2", IdentityZoneHolder.get().getId());
        assertEquals(ScimGroupMember.Type.USER, m.getType());
    }

    @Test
    public void canUpdateOrAddMembers() {
        String zoneId = IdentityZoneHolder.get().getId();

        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), zoneId);
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m4", ScimGroupMember.Type.USER), zoneId);
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), zoneId);

        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), zoneId);

        validateCount(4, jdbcTemplate);
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2", "test1.i");

        JdbcScimGroupMembershipManager spy = spy(jdbcScimGroupMembershipManager);

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP); // update role member->admin
        ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER); // new member
        ScimGroupMember m4 = new ScimGroupMember("m4", ScimGroupMember.Type.USER); // does not change

        List<ScimGroupMember> members = spy.updateOrAddMembers("g1", Arrays.asList(g2, m3, m4), zoneId);

        validateCount(4, jdbcTemplate);
        verify(spy).addMember("g1", m3, zoneId);
        verify(spy, times(0)).addMember("g1", m4, zoneId);
        verify(spy).removeMemberById("g1", "m1", zoneId);
        assertEquals(3, members.size());
        assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP)));
        assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER)));
        assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER)));
        validateUserGroups("m3", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2", "test1.i");
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId());
    }

    @Test
    public void canRemoveMemberById() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, IdentityZoneHolder.get().getId());
        validateCount(1, jdbcTemplate);

        jdbcScimGroupMembershipManager.removeMemberById("g1", "m1", IdentityZoneHolder.get().getId());
        validateCount(0, jdbcTemplate);
        try {
            jdbcScimGroupMembershipManager.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {

        }
    }

    @Test
    public void canRemoveNestedGroupMember() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), IdentityZoneHolder.get().getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        validateCount(3, jdbcTemplate);
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMemberById("g1", "g2", IdentityZoneHolder.get().getId());
        try {
            jdbcScimGroupMembershipManager.getMemberById("g1", "g2", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateCount(2, jdbcTemplate);
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2");

    }

    @Test
    public void canRemoveAllMembers() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), IdentityZoneHolder.get().getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        validateCount(3, jdbcTemplate);
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMembersByGroupId("g1", IdentityZoneHolder.get().getId());
        validateCount(1, jdbcTemplate);
        try {
            jdbcScimGroupMembershipManager.getMemberById("g1", "m1", IdentityZoneHolder.get().getId());
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {
        }
        validateUserGroups("m1", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId());
        validateUserGroups("m2", jdbcScimGroupMembershipManager, IdentityZoneHolder.get().getId(), "test2");

    }

    @Test
    public void canGetGroupsWithExternalMember() {
        addMember("g1", "m1", "MEMBER", zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());
        addMember("g2", "m1", "MEMBER", zone.getId(), jdbcTemplate, IdentityZoneHolder.get().getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithExternalMember("m1", zone.getId());

        assertThat(groups.size(), equalTo(2));

        List<String> groupIds = groups.stream().map(ScimGroup::getId).collect(Collectors.toList());
        assertThat(groupIds, hasItem("g1"));
        assertThat(groupIds, hasItem("g2"));
    }

    private static void mapExternalGroup(
            final String gId,
            final String external,
            final String origin,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(ADD_EXTERNAL_MAP_SQL, gId, external, now, origin, zoneId);
    }

    private static void addMember(
            final String gId,
            final String mId, final String mType,
            final String origin,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        final String gId_withZone = IdentityZone.getUaaZoneId().equals(zoneId) ? gId : zoneId + "-" + gId;
        final String mId_WithZone = IdentityZone.getUaaZoneId().equals(zoneId) ? mId : zoneId + "-" + mId;
        jdbcTemplate.execute(String.format(ADD_MEMBER_SQL_FORMAT, gId_withZone, mId_WithZone, mType, origin, zoneId));
    }

    private static void addGroup(
            final String id,
            final String name,
            final String zoneId,
            final JdbcTemplate jdbcTemplate) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.execute(String.format(ADD_GROUP_SQL_FORMAT, id, name, zoneId));
    }

    private static void addUser(
            final String id,
            final String password,
            final String zoneId,
            final JdbcTemplate jdbcTemplate) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.execute(String.format(ADD_USER_SQL_FORMAT, id, id, password, id, id, id, id, "", zoneId));
    }

    private static void validateCount(
            final int expected,
            final JdbcTemplate jdbcTemplate) {
        validateCount(expected, "No message given.", jdbcTemplate, IdentityZoneHolder.get().getId());
    }

    private static void validateCount(
            final int expected,
            final String msg,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from groups g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id", new Object[]{zoneId}, Integer.class);
        assertEquals(msg, expected, existingMemberCount);
    }

    private static void validateUserGroups(
            final String memberId,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            final String zoneId,
            final String... gNm) {
        Set<ScimGroup> directGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(memberId, false, zoneId);
        assertNotNull(directGroups);
        Set<ScimGroup> indirectGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(memberId, true, zoneId);
        indirectGroups.removeAll(directGroups);
        assertNotNull(indirectGroups);

        Set<String> expectedAuthorities = Collections.emptySet();
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

    private static void addMembers(final String origin, JdbcTemplate jdbcTemplate, final String zoneId) {
        addMember("g1", "m3", "USER", origin, jdbcTemplate, zoneId);
        addMember("g1", "g2", "GROUP", origin, jdbcTemplate, zoneId);
        addMember("g3", "m2", "USER", origin, jdbcTemplate, zoneId);
        addMember("g2", "m3", "USER", origin, jdbcTemplate, zoneId);
    }

    private static void addMembers(final JdbcTemplate jdbcTemplate, final String zoneId) {
        addMembers(OriginKeys.UAA, jdbcTemplate, zoneId);
    }

}
