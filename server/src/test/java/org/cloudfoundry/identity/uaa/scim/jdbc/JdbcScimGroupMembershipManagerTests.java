package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

@WithDatabaseContext
class JdbcScimGroupMembershipManagerTests {

    private final String anyZoneId = "It appears that any zone ID can be used for Application Events";
    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;

    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    private static final String ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";
    private static final String ADD_GROUP_SQL_FORMAT = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";
    private static final String ADD_MEMBER_SQL_FORMAT = "insert into group_membership (group_id, member_id, member_type, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s')";
    private static final String ADD_EXTERNAL_MAP_SQL = "insert into external_group_mapping (group_id, external_group, added, origin, identity_zone_id) values (?, ?, ?, ?, ?)";

    private RandomValueStringGenerator generator;

    private IdentityZone otherIdentityZone;
    private IdentityZone uaaIdentityZone;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        generator = new RandomValueStringGenerator();
        otherIdentityZone = MultitenancyFixture.identityZone("otherIdentityZone-" + generator.generate(), "otherIdentityZone-" + generator.generate());
        uaaIdentityZone = IdentityZone.getUaa();

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        JdbcScimUserProvisioning jdbcScimUserProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, passwordEncoder);
        jdbcScimGroupProvisioning = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);

        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate, new TimeServiceImpl(), jdbcScimUserProvisioning, null);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(jdbcScimGroupProvisioning);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        jdbcScimGroupProvisioning.createOrGet(new ScimGroup(null, "uaa.user", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        addUsersAndGroups(jdbcTemplate, otherIdentityZone.getId(), otherIdentityZone.getId() + "-");
        addUsersAndGroups(jdbcTemplate, uaaIdentityZone.getId(), "");

        validateCount(0, jdbcTemplate, IdentityZoneHolder.get().getId());
    }

    private static void addUsersAndGroups(
            final JdbcTemplate jdbcTemplate,
            final String identityZoneId,
            final String namePrefix) {
        String g1 = namePrefix + "g1";
        String g2 = namePrefix + "g2";
        String g3 = namePrefix + "g3";
        String m1 = namePrefix + "m1";
        String m2 = namePrefix + "m2";
        String m3 = namePrefix + "m3";
        String m4 = namePrefix + "m4";
        String m5 = namePrefix + "m5";
        addGroup(g1, "test1", identityZoneId, jdbcTemplate);
        addGroup(g2, "test2", identityZoneId, jdbcTemplate);
        addGroup(g3, "test3", identityZoneId, jdbcTemplate);
        addUser(m1, "test", identityZoneId, jdbcTemplate);
        addUser(m2, "test", identityZoneId, jdbcTemplate);
        addUser(m3, "test", identityZoneId, jdbcTemplate);
        addUser(m4, "test", identityZoneId, jdbcTemplate);
        addUser(m5, "test", identityZoneId, jdbcTemplate);
        mapExternalGroup(g1, g1 + "-external", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
        mapExternalGroup(g2, g2 + "-external", LOGIN_SERVER, jdbcTemplate, IdentityZoneHolder.get().getId());
        mapExternalGroup(g3, g3 + "-external", UAA, jdbcTemplate, IdentityZoneHolder.get().getId());
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.execute("delete from groups");
        jdbcTemplate.execute("delete from users");
        jdbcTemplate.execute("delete from external_group_mapping");
        jdbcTemplate.execute("delete from group_membership");
        IdentityZoneHolder.clear();
    }

    @Test
    void defaultGroupsAreCached() {
        List<String> defaultGroups = Arrays.asList("g1", "g2", "g3");
        otherIdentityZone.getConfig().getUserConfig().setDefaultGroups(defaultGroups);
        IdentityZoneHolder.set(otherIdentityZone);
        JdbcScimGroupProvisioning spy = spy(jdbcScimGroupProvisioning);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(spy);
        defaultGroups.forEach(g -> jdbcScimGroupMembershipManager.createOrGetGroup(g, otherIdentityZone.getId()));
        defaultGroups.forEach(g -> verify(spy, times(1)).createAndIgnoreDuplicate(eq(g), eq(otherIdentityZone.getId())));
        reset(spy);
        defaultGroups.forEach(g -> jdbcScimGroupMembershipManager.createOrGetGroup(g, otherIdentityZone.getId()));
        verifyZeroInteractions(spy);
    }

    @Test
    void deleteByMember() {
        addMember("g1", "m3", "USER", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "m3", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", uaaIdentityZone.getId());
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void deleteByMemberAndOrigin() {
        addMember("g1", "m3", "USER", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "m3", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", "non-existent-origin", uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", LDAP, uaaIdentityZone.getId());
        validateCount(3, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canDeleteWithOrigin() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.UAA, uaaIdentityZone.getId());
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canDeleteWithOrigin2() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.ORIGIN, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canDeleteWithOrigin3() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", uaaIdentityZone.getId());
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void cannotDeleteWithFilterOutsideZone() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        IdentityZoneHolder.set(otherIdentityZone);
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canGetGroupsForMember() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("g2", false, uaaIdentityZone.getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());

        groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, uaaIdentityZone.getId());
        assertNotNull(groups);
        assertEquals(3, groups.size());
    }

    @Test
    void userDeleteClearsMemberships_InUaaZone() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withUsername("username")
                .withEmail("test@test.com");

        UaaUser user = new UaaUser(prototype.withId("m3").withZoneId(uaaIdentityZone.getId()));
        addMembers(OriginKeys.LDAP, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(user, mock(Authentication.class), anyZoneId));

        validateCount(2, "ZoneID: " + uaaIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void userDeleteClearsMemberships_InOtherZone() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withUsername("username")
                .withEmail("test@test.com");

        UaaUser user = new UaaUser(prototype.withId(otherIdentityZone.getId() + "-m3").withZoneId(otherIdentityZone.getId()));
        addMembers(OriginKeys.LDAP, jdbcTemplate, otherIdentityZone.getId());
        validateCount(4, jdbcTemplate, otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(user, mock(Authentication.class), anyZoneId));

        validateCount(2, "ZoneID: " + otherIdentityZone.getId(), jdbcTemplate, otherIdentityZone.getId());
    }

    @Test
    void zoneDeleteClearsMemberships_InUaaZone() {
        addMembers(OriginKeys.LDAP, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaaIdentityZone, mock(Authentication.class), anyZoneId));

        validateCount(4, "ZoneID: " + uaaIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void zoneDeleteClearsMemberships_InOtherZone() {
        addMembers(OriginKeys.LDAP, jdbcTemplate, otherIdentityZone.getId());
        validateCount(4, jdbcTemplate, otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, mock(Authentication.class), anyZoneId));

        validateCount(0, "ZoneID: " + otherIdentityZone.getId(), jdbcTemplate, otherIdentityZone.getId());
    }

    @Test
    void providerDeleteClearsMemberships_InUaaZone() {
        addMembers(OriginKeys.LDAP, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, "ZoneID: " + uaaIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
        IdentityProvider provider = new IdentityProvider()
                .setId("ldap-id")
                .setOriginKey(LDAP)
                .setIdentityZoneId(uaaIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(provider, mock(Authentication.class), anyZoneId));

        validateCount(0, "ZoneID: " + uaaIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void providerDeleteClearsMemberships_InOtherZone() {
        addMembers(OriginKeys.LDAP, jdbcTemplate, otherIdentityZone.getId());
        validateCount(4, "ZoneID: " + otherIdentityZone.getId(), jdbcTemplate, otherIdentityZone.getId());
        IdentityProvider provider = new IdentityProvider()
                .setId("ldap-id")
                .setOriginKey(LDAP)
                .setIdentityZoneId(otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(provider, mock(Authentication.class), anyZoneId));

        validateCount(0, "ZoneID: " + otherIdentityZone.getId(), jdbcTemplate, otherIdentityZone.getId());
    }

    @Test
    void zoneDeleted() {
        String zoneAdminId = generator.generate();
        addGroup(zoneAdminId, "zones." + otherIdentityZone.getId() + ".admin", uaaIdentityZone.getId(), jdbcTemplate);
        addMember(zoneAdminId, "m1", "USER", OriginKeys.UAA, jdbcTemplate, uaaIdentityZone.getId());

        addMembers(jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"}, Integer.class), is(1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"}, Integer.class), is(1));

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=? and displayName like ?)", new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=? and displayName like ?", new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"}, Integer.class), is(0));
    }

    @Test
    void providerDeleted() {
        addMembers(LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        mapExternalGroup("g1", "some-external-group", LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        mapExternalGroup("g1", "some-external-group", UAA, jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[]{otherIdentityZone.getId(), LOGIN_SERVER}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[]{LOGIN_SERVER, otherIdentityZone.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?) and origin=?", new Object[]{otherIdentityZone.getId(), LOGIN_SERVER}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", new Object[]{LOGIN_SERVER, otherIdentityZone.getId()}, Integer.class), is(0));
    }

    @Test
    void cannotDeleteUaaZone() {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{uaaIdentityZone.getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{uaaIdentityZone.getId()}, Integer.class), is(4));

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{uaaIdentityZone.getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{uaaIdentityZone.getId()}, Integer.class), is(4));
    }

    @Test
    void cannotDeleteUaaProvider() {
        addMembers(LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from groups where identity_zone_id=?)", new Object[]{otherIdentityZone.getId()}, Integer.class), is(4));
        assertThat(jdbcTemplate.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{otherIdentityZone.getId()}, Integer.class), is(3));
    }

    @Test
    void canGetGroupsForMemberEvenWhenCycleExistsInGroupHierarchy() {
        addMember("g1", "m3", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "g3", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "g1", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, uaaIdentityZone.getId());
        assertNotNull(groups);
        assertEquals(4, groups.size());
    }

    @Test
    void canAddMember() {
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = jdbcScimGroupMembershipManager.addMember("g2", m1, uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());
        assertEquals(ScimGroupMember.Type.USER, m2.getType());
        assertEquals("m1", m2.getMemberId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");
    }

    @Test
    void addMemberInDifferentZoneCausesIssues() {
        otherIdentityZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherIdentityZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimGroupMembershipManager.addMember("g2", m1, otherIdentityZone.getId()));
    }

    @Test
    void canAddMemberValidateOriginAndZoneId() {
        otherIdentityZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherIdentityZone);
        validateCount(0, jdbcTemplate, otherIdentityZone.getId());
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimGroupMembershipManager.addMember("g2", m1, otherIdentityZone.getId()));
    }

    @Test
    void canAddNestedGroupMember() {
        addMember("g2", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        g2 = jdbcScimGroupMembershipManager.addMember("g1", g2, uaaIdentityZone.getId());
        assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
        assertEquals("g2", g2.getMemberId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1.i", "test2");
    }

    @Test
    void cannotNestGroupWithinItself() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        assertThrows(InvalidScimResourceException.class,
                () -> jdbcScimGroupMembershipManager.addMember("g2", g2, uaaIdentityZone.getId()));
    }

    @Test
    void canGetMembers() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());

        List<ScimGroupMember> members = jdbcScimGroupMembershipManager.getMembers("g1", false, uaaIdentityZone.getId());
        assertNotNull(members);
        assertEquals(2, members.size());

        members = jdbcScimGroupMembershipManager.getMembers("g2", false, uaaIdentityZone.getId());
        assertNotNull(members);
        assertEquals(0, members.size());

    }

    @Test
    void canGetMembers_Fails_In_Other_Zone() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());
        IdentityZoneHolder.set(otherIdentityZone);
        assertEquals(0, jdbcScimGroupMembershipManager.getMembers("g1", false, otherIdentityZone.getId()).size());
    }

    @Test
    void canReadNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', NULL, '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "uaa", uaaIdentityZone.getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    void canReadNonNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s', '%s')";
        jdbcTemplate.execute(String.format(addNullAuthoritySQL, "g1", "m1", "USER", "ANYTHING", "uaa", uaaIdentityZone.getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId());
        assertNotNull(member);
        assertEquals("m1", member.getMemberId());
    }

    @Test
    void canGetDefaultGroupsUsingGetGroupsForMember() {
        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m1", false, uaaIdentityZone.getId());
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    void canGetMemberById() {
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());

        ScimGroupMember m = jdbcScimGroupMembershipManager.getMemberById("g3", "m2", uaaIdentityZone.getId());
        assertEquals(ScimGroupMember.Type.USER, m.getType());
    }

    @Test
    void canUpdateOrAddMembers() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m4", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), uaaIdentityZone.getId());

        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), uaaIdentityZone.getId());

        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");

        JdbcScimGroupMembershipManager spy = spy(jdbcScimGroupMembershipManager);

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP); // update role member->admin
        ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER); // new member
        ScimGroupMember m4 = new ScimGroupMember("m4", ScimGroupMember.Type.USER); // does not change

        List<ScimGroupMember> members = spy.updateOrAddMembers("g1", Arrays.asList(g2, m3, m4), uaaIdentityZone.getId());

        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        verify(spy).addMember("g1", m3, uaaIdentityZone.getId());
        verify(spy, times(0)).addMember("g1", m4, uaaIdentityZone.getId());
        verify(spy).removeMemberById("g1", "m1", uaaIdentityZone.getId());
        assertEquals(3, members.size());
        assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP)));
        assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER)));
        assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER)));
        validateUserGroups("m3", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId());
    }

    @Test
    void canRemoveMemberById() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());

        jdbcScimGroupMembershipManager.removeMemberById("g1", "m1", uaaIdentityZone.getId());
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
        assertThrows(MemberNotFoundException.class,
                () -> jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId()));
    }

    @Test
    void canRemoveNestedGroupMember() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        validateCount(3, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMemberById("g1", "g2", uaaIdentityZone.getId());
        assertThrows(MemberNotFoundException.class,
                () -> jdbcScimGroupMembershipManager.getMemberById("g1", "g2", uaaIdentityZone.getId()));
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");

    }

    @Test
    void canRemoveAllMembers() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        validateCount(3, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMembersByGroupId("g1", uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());
        assertThrows(MemberNotFoundException.class,
                () -> jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId()));
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId());
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");
    }

    @Test
    void canGetGroupsWithExternalMember() {
        addMember("g1", "m1", "MEMBER", otherIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "m1", "MEMBER", otherIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithExternalMember("m1", otherIdentityZone.getId(), uaaIdentityZone.getId());

        assertThat(groups.size(), equalTo(2));

        List<String> groupIds = groups.stream().map(ScimGroup::getId).collect(Collectors.toList());
        assertThat(groupIds, hasItem("g1"));
        assertThat(groupIds, hasItem("g2"));
    }

    @Test
    public void canAddMultipleMembers() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        try {
            jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
            Assertions.fail();
        } catch (MemberAlreadyExistsException e) {
            assertNotNull(e);
        }
    }

    @Test
    void testGroupsWithMemberAndMaxSqlParameter() {
        int oldValue = jdbcScimGroupMembershipManager.getMaxSqlParameters();
        for (int l: List.of(-1, 10)) {
            jdbcScimGroupMembershipManager.setMaxSqlParameters(l);

            for (int i = 0; i < 5; i++) {
                addGroup("testGroup" + l + i, "testGroupName" + l + i, uaaIdentityZone.getId(), jdbcTemplate);
                addMember("testGroup" + l + i, "m5", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
            }
            validateM5(5, jdbcScimGroupMembershipManager.getGroupsWithMember("m5", true, uaaIdentityZone.getId()), l);

            for (int i = 5; i < 10; i++) {
                addGroup("testGroup" + l + i, "testGroupName" + l + i, uaaIdentityZone.getId(), jdbcTemplate);
                addMember("testGroup" + l + i, "m5", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
            }
            validateM5(10, jdbcScimGroupMembershipManager.getGroupsWithMember("m5", true, uaaIdentityZone.getId()), l);

            for (int i = 10; i < 15; i++) {
                addGroup("testGroup" + l + i, "testGroupName" + l + i, uaaIdentityZone.getId(), jdbcTemplate);
                addMember("testGroup" + l + i, "m5", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
            }
            validateM5(15, jdbcScimGroupMembershipManager.getGroupsWithMember("m5", true, uaaIdentityZone.getId()), l);
        }

        jdbcScimGroupMembershipManager.setMaxSqlParameters(oldValue);
    }

    private void validateM5(int i, Set<ScimGroup> m5, int prefix) {
        int count = 0;
        for (ScimGroup g: m5) {
            if (g.getId().startsWith("testGroup" + prefix)) count++;
        }
        Assert.assertEquals(i, count);
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
            final String mId,
            final String mType,
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
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        validateCount(expected, "No message given.", jdbcTemplate, zoneId);
    }

    private static void validateCount(
            final int expected,
            final String msg,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from groups g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id", new Object[]{zoneId}, Integer.class);
        assertEquals(expected, existingMemberCount, msg);
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

    private static void addMembers(
            final String origin,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) {
        addMember("g1", "m3", "USER", origin, jdbcTemplate, zoneId);
        addMember("g1", "g2", "GROUP", origin, jdbcTemplate, zoneId);
        addMember("g3", "m2", "USER", origin, jdbcTemplate, zoneId);
        addMember("g2", "m3", "USER", origin, jdbcTemplate, zoneId);
    }

    private static void addMembers(final JdbcTemplate jdbcTemplate, final String zoneId) {
        addMembers(OriginKeys.UAA, jdbcTemplate, zoneId);
    }

}
