package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
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
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@WithDatabaseContext
class JdbcScimGroupMembershipManagerTests {

    private final String anyZoneId = "It appears that any zone ID can be used for Application Events";
    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;

    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    private DbUtils dbUtils;

    private static final String ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities ,identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s','%s')";
    private static final String ADD_GROUP_SQL_FORMAT = "insert into %s (id, displayName, identity_zone_id) values ('%s','%s','%s')";
    private static final String ADD_MEMBER_SQL_FORMAT = "insert into group_membership (group_id, member_id, member_type, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s')";
    private static final String ADD_EXTERNAL_MAP_SQL = "insert into external_group_mapping (group_id, external_group, added, origin, identity_zone_id) values (?, ?, ?, ?, ?)";

    private RandomValueStringGenerator generator;

    private IdentityZone otherIdentityZone;
    private IdentityZone uaaIdentityZone;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String groupName;

    @BeforeEach
    void setUp() throws SQLException {
        generator = new RandomValueStringGenerator();
        otherIdentityZone = MultitenancyFixture.identityZone("otherIdentityZone-" + generator.generate(), "otherIdentityZone-" + generator.generate());
        uaaIdentityZone = IdentityZone.getUaa();

        dbUtils = new DbUtils();
        groupName = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter);
        JdbcScimUserProvisioning jdbcScimUserProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate, pagingListFactory, passwordEncoder, new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate), new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(), true);
        jdbcScimGroupProvisioning = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);

        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(
                new IdentityZoneManagerImpl(), jdbcTemplate, new TimeServiceImpl(), jdbcScimUserProvisioning, null, dbUtils);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(jdbcScimGroupProvisioning);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        jdbcScimGroupProvisioning.createOrGet(new ScimGroup(null, "uaa.user", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        addUsersAndGroups(jdbcTemplate, otherIdentityZone.getId(), otherIdentityZone.getId() + "-");
        addUsersAndGroups(jdbcTemplate, uaaIdentityZone.getId(), "");

        validateCount(0, jdbcTemplate, IdentityZoneHolder.get().getId());
    }

    private void addUsersAndGroups(
            final JdbcTemplate jdbcTemplate,
            final String identityZoneId,
            final String namePrefix) throws SQLException {
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
    void tearDown() throws SQLException {
        jdbcTemplate.execute("delete from " + dbUtils.getQuotedIdentifier("groups", jdbcTemplate));
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
        verifyNoInteractions(spy);
    }

    @Test
    void deleteByMember() throws SQLException {
        addMember("g1", "m3", "USER", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", LDAP, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "m3", "USER", UAA, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", uaaIdentityZone.getId());
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void deleteByMemberAndOrigin() throws SQLException {
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
    void canDeleteWithOrigin() throws SQLException {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.UAA, uaaIdentityZone.getId());
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canDeleteWithOrigin2() throws SQLException {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.deleteMembersByOrigin(OriginKeys.ORIGIN, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void canDeleteWithOrigin3() throws SQLException {
        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.removeMembersByMemberId("m3", uaaIdentityZone.getId());
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void cannotDeleteWithFilterOutsideZone() throws SQLException {
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
        assertThat(groups).hasSize(1);

        groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, uaaIdentityZone.getId());
        assertThat(groups).hasSize(3);
    }

    @Test
    void userDeleteClearsMemberships_InUaaZone() throws SQLException {
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
    void userDeleteClearsMemberships_InOtherZone() throws SQLException {
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
    void zoneDeleteClearsMemberships_InUaaZone() throws SQLException {
        addMembers(OriginKeys.LDAP, jdbcTemplate, uaaIdentityZone.getId());
        validateCount(4, jdbcTemplate, uaaIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaaIdentityZone, mock(Authentication.class), anyZoneId));

        validateCount(4, "ZoneID: " + uaaIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
    }

    @Test
    void zoneDeleteClearsMemberships_InOtherZone() throws SQLException {
        addMembers(OriginKeys.LDAP, jdbcTemplate, otherIdentityZone.getId());
        validateCount(4, jdbcTemplate, otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, mock(Authentication.class), anyZoneId));

        validateCount(0, "ZoneID: " + otherIdentityZone.getId(), jdbcTemplate, otherIdentityZone.getId());
    }

    @Test
    void providerDeleteClearsMemberships_InUaaZone() throws SQLException {
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
    void providerDeleteClearsMemberships_InOtherZone() throws SQLException {
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
    void zoneDeleted() throws SQLException {
        String zoneAdminId = generator.generate();
        addGroup(zoneAdminId, "zones." + otherIdentityZone.getId() + ".admin", uaaIdentityZone.getId(), jdbcTemplate);
        addMember(zoneAdminId, "m1", "USER", OriginKeys.UAA, jdbcTemplate, uaaIdentityZone.getId());

        String groups = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);
        addMembers(jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups +
                " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=? and displayName like ?)", Integer.class, new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"})).isOne();
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups +
                " where identity_zone_id=? and displayName like ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"})).isOne();

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups +
                " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=? and displayName like ?)", Integer.class, new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from " +
                groups + " where identity_zone_id=? and displayName like ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId(), "zones." + otherIdentityZone.getId() + ".%"})).isZero();
    }

    @Test
    void providerDeleted() throws SQLException {
        String groups = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);

        addMembers(LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        mapExternalGroup("g1", "some-external-group", LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        mapExternalGroup("g1", "some-external-group", UAA, jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from "
                + groups + " where identity_zone_id=?) and origin=?", Integer.class, new Object[]{otherIdentityZone.getId(), LOGIN_SERVER})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups +
                " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", Integer.class, new Object[]{LOGIN_SERVER, otherIdentityZone.getId()})).isOne();

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " + groupName + " where identity_zone_id=?) and origin=?", Integer.class, new Object[]{otherIdentityZone.getId(), LOGIN_SERVER})).isZero();
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups + " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
        assertThat(jdbcTemplate.queryForObject("select count(*) from external_group_mapping where origin = ? and identity_zone_id=?", Integer.class, new Object[]{LOGIN_SERVER, otherIdentityZone.getId()})).isZero();
    }

    @Test
    void cannotDeleteUaaZone() throws SQLException {
        String groups = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);

        addMembers(jdbcTemplate, uaaIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " + groupName + " where identity_zone_id=?)", Integer.class, new Object[]{uaaIdentityZone.getId()})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups + " where identity_zone_id=?", Integer.class, new Object[]{uaaIdentityZone.getId()})).isEqualTo(4);

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " + groups + " where identity_zone_id=?)", Integer.class, new Object[]{uaaIdentityZone.getId()})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups + " where identity_zone_id=?", Integer.class, new Object[]{uaaIdentityZone.getId()})).isEqualTo(4);
    }

    @Test
    void cannotDeleteUaaProvider() throws SQLException {
        String groups = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);

        addMembers(LOGIN_SERVER, jdbcTemplate, otherIdentityZone.getId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " + groups +
                " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(otherIdentityZone.getId());

        jdbcScimGroupProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, anyZoneId));

        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where group_id in (select id from " +
                groups + " where identity_zone_id=?)", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(4);
        assertThat(jdbcTemplate.queryForObject("select count(*) from " +
                groups + " where identity_zone_id=?", Integer.class, new Object[]{otherIdentityZone.getId()})).isEqualTo(3);
    }

    @Test
    void canGetGroupsForMemberEvenWhenCycleExistsInGroupHierarchy() {
        addMember("g1", "m3", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "g3", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "g1", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m3", true, uaaIdentityZone.getId());
        assertThat(groups).hasSize(4);
    }

    @Test
    void canAddMember() throws SQLException {
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = jdbcScimGroupMembershipManager.addMember("g2", m1, uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());
        assertThat(m2.getType()).isEqualTo(ScimGroupMember.Type.USER);
        assertThat(m2.getMemberId()).isEqualTo("m1");
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");
    }

    @Test
    void addMemberInDifferentZoneCausesIssues() {
        otherIdentityZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherIdentityZone);
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.addMember("g2", m1, otherIdentityZone.getId()));
    }

    @Test
    void canAddMemberValidateOriginAndZoneId() throws SQLException {
        otherIdentityZone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        IdentityZoneHolder.set(otherIdentityZone);
        validateCount(0, jdbcTemplate, otherIdentityZone.getId());
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        m1.setOrigin(OriginKeys.UAA);
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.addMember("g2", m1, otherIdentityZone.getId()));
    }

    @Test
    void canAddNestedGroupMember() {
        addMember("g2", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());

        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        g2 = jdbcScimGroupMembershipManager.addMember("g1", g2, uaaIdentityZone.getId());
        assertThat(g2.getType()).isEqualTo(ScimGroupMember.Type.GROUP);
        assertThat(g2.getMemberId()).isEqualTo("g2");
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1.i", "test2");
    }

    @Test
    void cannotNestGroupWithinItself() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP);
        assertThatExceptionOfType(InvalidScimResourceException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.addMember("g2", g2, uaaIdentityZone.getId()));
    }

    @Test
    void canGetMembers() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());

        List<ScimGroupMember> members = jdbcScimGroupMembershipManager.getMembers("g1", false, uaaIdentityZone.getId());
        assertThat(members).hasSize(2);

        members = jdbcScimGroupMembershipManager.getMembers("g2", false, uaaIdentityZone.getId());
        assertThat(members).isEmpty();
    }

    @Test
    void canGetMembers_Fails_In_Other_Zone() {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g1", "g2", "GROUP", "READER", jdbcTemplate, uaaIdentityZone.getId());
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());
        IdentityZoneHolder.set(otherIdentityZone);
        assertThat(jdbcScimGroupMembershipManager.getMembers("g1", false, otherIdentityZone.getId())).isEmpty();
    }

    @Test
    void canReadNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', NULL, '%s', '%s')";
        jdbcTemplate.execute(addNullAuthoritySQL.formatted("g1", "m1", "USER", "uaa", uaaIdentityZone.getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId());
        assertThat(member).isNotNull();
        assertThat(member.getMemberId()).isEqualTo("m1");
    }

    @Test
    void canReadNonNullFromAuthoritiesColumn() {
        String addNullAuthoritySQL =
                "insert into group_membership (group_id, member_id, member_type, authorities, origin, identity_zone_id) values ('%s', '%s', '%s', '%s', '%s', '%s')";
        jdbcTemplate.execute(addNullAuthoritySQL.formatted("g1", "m1", "USER", "ANYTHING", "uaa", uaaIdentityZone.getId()));

        ScimGroupMember member = jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId());
        assertThat(member).isNotNull();
        assertThat(member.getMemberId()).isEqualTo("m1");
    }

    @Test
    void canGetDefaultGroupsUsingGetGroupsForMember() {
        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithMember("m1", false, uaaIdentityZone.getId());
        assertThat(groups).hasSize(1);
    }

    @Test
    void canGetMemberById() {
        addMember("g3", "m2", "USER", "READER,WRITER", jdbcTemplate, uaaIdentityZone.getId());

        ScimGroupMember m = jdbcScimGroupMembershipManager.getMemberById("g3", "m2", uaaIdentityZone.getId());
        assertThat(m.getType()).isEqualTo(ScimGroupMember.Type.USER);
    }

    @Test
    void canUpdateOrAddMembers() throws SQLException {
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
        assertThat(members)
                .hasSize(3)
                .contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP))
                .contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER))
                .doesNotContain(new ScimGroupMember("m1", ScimGroupMember.Type.USER));
        validateUserGroups("m3", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId());
    }

    @Test
    void canRemoveMemberById() throws SQLException {
        addMember("g1", "m1", "USER", "READER", jdbcTemplate, uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());

        jdbcScimGroupMembershipManager.removeMemberById("g1", "m1", uaaIdentityZone.getId());
        validateCount(0, jdbcTemplate, uaaIdentityZone.getId());
        assertThatExceptionOfType(MemberNotFoundException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId()));
    }

    @Test
    void canRemoveNestedGroupMember() throws SQLException {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        validateCount(3, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMemberById("g1", "g2", uaaIdentityZone.getId());
        assertThatExceptionOfType(MemberNotFoundException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.getMemberById("g1", "g2", uaaIdentityZone.getId()));
        validateCount(2, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");

    }

    @Test
    void canRemoveAllMembers() throws SQLException {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP), uaaIdentityZone.getId());
        jdbcScimGroupMembershipManager.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        validateCount(3, jdbcTemplate, uaaIdentityZone.getId());
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test1");
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2", "test1.i");

        jdbcScimGroupMembershipManager.removeMembersByGroupId("g1", uaaIdentityZone.getId());
        validateCount(1, jdbcTemplate, uaaIdentityZone.getId());
        assertThatExceptionOfType(MemberNotFoundException.class).isThrownBy(() -> jdbcScimGroupMembershipManager.getMemberById("g1", "m1", uaaIdentityZone.getId()));
        validateUserGroups("m1", jdbcScimGroupMembershipManager, uaaIdentityZone.getId());
        validateUserGroups("m2", jdbcScimGroupMembershipManager, uaaIdentityZone.getId(), "test2");
    }

    @Test
    void canGetGroupsWithExternalMember() {
        addMember("g1", "m1", "MEMBER", otherIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());
        addMember("g2", "m1", "MEMBER", otherIdentityZone.getId(), jdbcTemplate, uaaIdentityZone.getId());

        Set<ScimGroup> groups = jdbcScimGroupMembershipManager.getGroupsWithExternalMember("m1", otherIdentityZone.getId(), uaaIdentityZone.getId());

        assertThat(groups).hasSize(2);

        List<String> groupIds = groups.stream().map(ScimGroup::getId).toList();
        assertThat(groupIds).contains("g1", "g2");
    }

    @Test
    void canAddMultipleMembers() {
        jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
        try {
            jdbcScimGroupMembershipManager.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER), uaaIdentityZone.getId());
            fail("");
        } catch (MemberAlreadyExistsException e) {
            assertThat(e).isNotNull();
        }
    }

    @Test
    void groupsWithMemberAndMaxSqlParameter() throws SQLException {
        int oldValue = jdbcScimGroupMembershipManager.getMaxSqlParameters();
        for (int l : List.of(-1, 10)) {
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
        for (ScimGroup g : m5) {
            if (g.getId().startsWith("testGroup" + prefix)) {
                count++;
            }
        }
        assertThat(count).isEqualTo(i);
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
        final String gIdWithZone = IdentityZone.getUaaZoneId().equals(zoneId) ? gId : zoneId + "-" + gId;
        final String mIdWithZone = IdentityZone.getUaaZoneId().equals(zoneId) ? mId : zoneId + "-" + mId;
        jdbcTemplate.execute(ADD_MEMBER_SQL_FORMAT.formatted(gIdWithZone, mIdWithZone, mType, origin, zoneId));
    }

    private void addGroup(
            final String id,
            final String name,
            final String zoneId,
            final JdbcTemplate jdbcTemplate) throws SQLException {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.execute(ADD_GROUP_SQL_FORMAT.formatted(
                dbUtils.getQuotedIdentifier("groups", jdbcTemplate), id, name, zoneId));
    }

    private static void addUser(
            final String id,
            final String password,
            final String zoneId,
            final JdbcTemplate jdbcTemplate) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.execute(ADD_USER_SQL_FORMAT.formatted(id, id, password, id, id, id, id, "", zoneId));
    }

    private void validateCount(
            final int expected,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) throws SQLException {
        validateCount(expected, "No message given.", jdbcTemplate, zoneId);
    }

    private void validateCount(
            final int expected,
            final String msg,
            final JdbcTemplate jdbcTemplate,
            final String zoneId) throws SQLException {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from " +
                        dbUtils.getQuotedIdentifier("groups", jdbcTemplate) +
                        " g, group_membership gm where g.identity_zone_id=? and gm.group_id=g.id",
                Integer.class, new Object[]{zoneId});
        assertThat(existingMemberCount).as(msg).isEqualTo(expected);
    }

    private static void validateUserGroups(
            final String memberId,
            final JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
            final String zoneId,
            final String... gNm) {
        Set<ScimGroup> directGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(memberId, false, zoneId);
        assertThat(directGroups).isNotNull();
        Set<ScimGroup> indirectGroups = jdbcScimGroupMembershipManager.getGroupsWithMember(memberId, true, zoneId);
        indirectGroups.removeAll(directGroups);
        assertThat(indirectGroups).isNotNull();

        Set<String> expectedAuthorities = Collections.emptySet();
        if (gNm != null) {
            expectedAuthorities = new HashSet<>(Arrays.asList(gNm));
        }
        expectedAuthorities.add("uaa.user");

        assertThat(directGroups.size() + indirectGroups.size()).isEqualTo(expectedAuthorities.size());
        for (ScimGroup group : directGroups) {
            assertThat(expectedAuthorities).contains(group.getDisplayName());
        }
        for (ScimGroup group : indirectGroups) {
            assertThat(expectedAuthorities).contains(group.getDisplayName() + ".i");
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
