package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.security.SecureRandom;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_FIELDS;
import static org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager.MEMBERSHIP_TABLE;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.util.StringUtils.hasText;

@WithDatabaseContext
class JdbcScimGroupProvisioningTests {

    private static final String SQL_INJECTION_FIELDS = "displayName,version,created,lastModified";

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;
    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    private String groupName;

    private JdbcScimGroupProvisioning dao;
    private JdbcScimGroupMembershipManager memberships;
    private ScimUserProvisioning users;
    private RandomValueStringGenerator generator;

    private ScimGroup g1;
    private ScimGroup g2;
    private ScimGroup g3;
    private String g1Id;
    private String g2Id;
    private String g3Id;
    private String zoneId;
    private String group1Description;
    private String group2Description;
    private String group3Description;

    @BeforeEach
    void initJdbcScimGroupProvisioningTests() throws SQLException {
        DbUtils dbUtils = new DbUtils();
        groupName = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);

        generator = new RandomValueStringGenerator();
        SecureRandom random = new SecureRandom();
        random.setSeed(System.nanoTime());
        generator.setRandom(random);

        zoneId = generator.generate();

        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        IdentityZoneHolder.set(zone);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(new ArrayList<>());
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(null);

        validateGroupCountInZone(0, zoneId);

        dao = spy(new JdbcScimGroupProvisioning(namedJdbcTemplate,
                new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter),
                dbUtils));

        users = mock(ScimUserProvisioning.class);

        memberships = new JdbcScimGroupMembershipManager(new IdentityZoneManagerImpl(), jdbcTemplate,
                new TimeServiceImpl(), users, null, dbUtils);
        memberships.setScimGroupProvisioning(dao);
        dao.setJdbcScimGroupMembershipManager(memberships);

        JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager =
                new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        jdbcScimGroupExternalMembershipManager.setScimGroupProvisioning(dao);
        dao.setJdbcScimGroupExternalMembershipManager(jdbcScimGroupExternalMembershipManager);
        dao.setJdbcIdentityZoneProvisioning(new JdbcIdentityZoneProvisioning(jdbcTemplate));

        g1Id = "g1";
        g2Id = "g2";
        g3Id = "g3";

        group1Description = "u" + generator.generate();
        g1 = addGroup(g1Id, group1Description, zoneId);
        group2Description = "u" + generator.generate();
        g2 = addGroup(g2Id, group2Description, zoneId);
        group3Description = "op" + generator.generate();
        g3 = addGroup(g3Id, group3Description, zoneId);

        validateGroupCountInZone(3, zoneId);
    }

    @AfterEach
    void cleanSpy() {
        dao.deleteByIdentityZone(zoneId);
        validateGroupCountInZone(0, zoneId);

        reset(dao);
    }

    @Test
    void create_or_get_tries_get_first() {
        reset(dao);
        dao.createOrGet(new ScimGroup(group3Description), zoneId);
        verify(dao, times(1)).getByName(group3Description, zoneId);
        verify(dao, never()).createAndIgnoreDuplicate(anyString(), anyString());
    }

    @Test
    void create_or_get_tries_get_first_but_creates_it() {
        reset(dao);
        String name = generator.generate().toLowerCase() + System.nanoTime();
        dao.createOrGet(new ScimGroup(name), zoneId);
        verify(dao, times(2)).getByName(name, zoneId);
        verify(dao, times(1)).createAndIgnoreDuplicate(name, zoneId);
    }

    @Test
    void get_by_name() {
        assertThat(dao.getByName(group3Description, zoneId)).isNotNull();
        assertThat(dao.getByName(group1Description, zoneId)).isNotNull();
        assertThat(dao.getByName(group2Description, zoneId)).isNotNull();
    }

    @Test
    void get_by_invalid_name() {
        assertThatThrownBy(() -> dao.getByName("invalid-group-name", zoneId))
                .isInstanceOf(IncorrectResultSizeDataAccessException.class)
                .hasMessageStartingWith("Invalid result size found for");
    }

    @Test
    void get_by_empty_name() {
        assertThatThrownBy(() -> dao.getByName("", zoneId))
                .isInstanceOf(IncorrectResultSizeDataAccessException.class)
                .hasMessageStartingWith("group name must contain text");
    }

    @Test
    void get_by_null_name() {
        assertThatThrownBy(() -> dao.getByName(null, zoneId))
                .isInstanceOf(IncorrectResultSizeDataAccessException.class)
                .hasMessageStartingWith("group name must contain text");
    }

    @Test
    void canRetrieveGroups() {
        List<ScimGroup> groups = dao.retrieveAll(zoneId);
        assertThat(groups).hasSize(3);
        for (ScimGroup g : groups) {
            validateGroup(g, null, zoneId);
        }
    }

    @Test
    void canRetrieveGroupsWithFilter() {
        assertThat(dao.query("displayName eq " + "\"" + group1Description + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("displayName pr", zoneId)).hasSize(3);
        assertThat(dao.query("displayName eq \"" + group3Description + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("DISPLAYNAMe eq " + "\"" + group2Description + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("displayName EQ \"" + group3Description + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("displayName eq \"" + group3Description.toUpperCase() + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("displayName co \"" + group1Description.substring(1, group1Description.length() - 1) + "\"", zoneId)).hasSize(1);
        assertThat(dao.query("id sw \"g\"", zoneId)).hasSize(3);
        assertThat(dao.query("displayName gt \"oauth\"", zoneId)).hasSize(3);
        assertThat(dao.query("displayName lt \"oauth\"", zoneId)).isEmpty();
        assertThat(dao.query("displayName eq \"" + group3Description + "\" and meta.version eq 0", zoneId)).hasSize(1);
        assertThat(dao.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", zoneId)).hasSize(3);
        assertThat(dao.query("displayName pr and id co \"g\"", zoneId)).hasSize(3);
        assertThat(dao.query("displayName eq \"" + group3Description + "\" or displayName co \"" + group1Description.substring(1, group1Description.length() - 1) + "\"", zoneId)).hasSize(2);
        assertThat(dao.query("displayName eq \"foo\" or id sw \"g\"", zoneId)).hasSize(3);
    }

    @Test
    void canRetrieveGroupsWithFilterAndSortBy() {
        assertThat(dao.query("displayName pr", "id", true, zoneId)).hasSize(3);
        assertThat(dao.query("id co \"2\"", "displayName", false, zoneId)).hasSize(1);
    }

    @Test
    void cannotRetrieveGroupsWithIllegalQuotesFilter() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName eq \"bar", zoneId));
    }

    @Test
    void cannotRetrieveGroupsWithMissingQuotesFilter() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName eq bar", zoneId));
    }

    @Test
    void cannotRetrieveGroupsWithInvalidFieldsFilter() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("name eq \"openid\"", zoneId));
    }

    @Test
    void cannotRetrieveGroupsWithWrongFilter() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName pr \"r\"", zoneId));
    }

    @Test
    void canRetrieveGroup() {
        ScimGroup group = dao.retrieve(g1Id, zoneId);
        validateGroup(group, group1Description, zoneId);
    }

    @Test
    void cannotRetrieveNonExistentGroup() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> dao.retrieve("invalidgroup", zoneId));
    }

    @Test
    void canCreateGroup() {
        internalCreateGroup(generator.generate().toLowerCase());
    }

    @Test
    void canCreateOrGetGroup() {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        String id = g.getId();
        g.setId(null);
        ScimGroup same = dao.createOrGet(g, zoneId);
        assertThat(same).isNotNull();
        assertThat(same.getId()).isEqualTo(id);
    }

    @Test
    void canGetByName() {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        ScimGroup same = dao.getByName(g.getDisplayName(), zoneId);
        assertThat(same).isNotNull();
        assertThat(same.getId()).isEqualTo(g.getId());
    }

    @Test
    void canCreateAndGetGroupWithQuotes() {
        String nameWithQuotes = generator.generate() + "\"" + generator.generate() + "\"";
        ScimGroup g = internalCreateGroup(nameWithQuotes);
        assertThat(g).isNotNull();
        assertThat(g.getDisplayName()).isEqualTo(nameWithQuotes);
        ScimGroup same = dao.getByName(nameWithQuotes, zoneId);
        assertThat(same).isNotNull();
        assertThat(same.getId()).isEqualTo(g.getId());
    }

    @Test
    void cannotCreateNotAllowedGroup() {
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(Arrays.asList("allowedGroup"));
        assertThatThrownBy(() -> internalCreateGroup("notAllowedGroup"))
                .isInstanceOf(InvalidScimResourceException.class)
                .hasMessageContaining("is not allowed");

    }

    @Test
    void cannotUpdateNotAllowedGroup() {
        IdentityZoneHolder.get().getConfig().getUserConfig().setAllowedGroups(Arrays.asList("allowedGroup"));
        ScimGroup g = dao.retrieve(g1Id, zoneId);
        g.setDisplayName("notAllowedGroup");
        g.setDescription("description-update");
        try {
            dao.update(g1Id, g, zoneId);
            fail("");
        } catch (InvalidScimResourceException e) {
            assertThat(e.getMessage()).contains("is not allowed");
        }
    }

    @Test
    void canUpdateGroup() {
        ScimGroup g = dao.retrieve(g1Id, zoneId);
        assertThat(g.getDisplayName()).isEqualTo(group1Description);

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
    void canRemoveGroup() {
        validateGroupCountInZone(3, zoneId);
        addUserToGroup(g1.getId(), "joe@example.com");
        validateGroupCountInZone(3, zoneId);
        addUserToGroup(g1.getId(), "mary@example.com");
        ScimGroupMember bill = addUserToGroup(g2.getId(), "bill@example.com");

        dao.delete(g1Id, 0, zoneId);
        validateGroupCountInZone(2, zoneId);
        List<ScimGroupMember> remainingMemberships = jdbcTemplate.query("select " + MEMBERSHIP_FIELDS + " from " + MEMBERSHIP_TABLE,
                new JdbcScimGroupMembershipManager.ScimGroupMemberRowMapper());
        assertThat(remainingMemberships).hasSize(1);
        ScimGroupMember survivor = remainingMemberships.getFirst();
        assertThat(survivor.getType()).isEqualTo(ScimGroupMember.Type.USER);
        assertThat(survivor.getMemberId()).isEqualTo(bill.getMemberId());
    }

    @Test
    void deleteGroupWithNestedMembers() {
        ScimGroup appUsers = addGroup("appuser", "app.user", zoneId);
        addGroupToGroup(appUsers.getId(), g1.getId());
        dao.delete(appUsers.getId(), 0, zoneId);

        List<ScimGroupMember> remainingMemberships = jdbcTemplate.query("select " + MEMBERSHIP_FIELDS + " from " + MEMBERSHIP_TABLE,
                new JdbcScimGroupMembershipManager.ScimGroupMemberRowMapper());
        assertThat(remainingMemberships).isEmpty();
    }

    @Test
    void that_uaa_scopes_are_bootstrapped_when_zone_is_created() {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, "subdomain-" + id);
        IdentityZoneModifiedEvent event = IdentityZoneModifiedEvent.identityZoneCreated(zone);
        dao.onApplicationEvent(event);
        List<String> groups = dao.retrieveAll(id).stream().map(ScimGroup::getDisplayName).toList();
        ZoneManagementScopes.getSystemScopes()
                .forEach(scope ->
                        assertThat(groups).contains(scope)
                );
    }

    @Test
    void onApplicationEventShouldOnlyCreateSystemScopesInAllowList() {
        final String id = generator.generate();
        final IdentityZone zone = MultitenancyFixture.identityZone(id, "subdomain-" + id);
        zone.getConfig().getUserConfig().setDefaultGroups(List.of("password.write"));
        zone.getConfig().getUserConfig().setAllowedGroups(List.of("scim.read", "scim.write"));

        final IdentityZoneModifiedEvent event = IdentityZoneModifiedEvent.identityZoneCreated(zone);
        dao.onApplicationEvent(event);

        final List<String> groupNames = dao.retrieveAll(id).stream().map(ScimGroup::getDisplayName).toList();
        assertThat(groupNames).hasSize(3).contains(
                "scim.read", "scim.write", // part of allowed groups
                "password.write" // part of default groups
        );
    }

    @Nested
    @WithDatabaseContext
    class WithGroupsAlsoInAnotherIdentityZone {
        private String secondZoneId;

        @BeforeEach
        void addGroupToAnotherZone() {
            secondZoneId = generator.generate();
            addGroup(generator.generate(), generator.generate(), secondZoneId);
            validateGroupCountInZone(1, secondZoneId);
        }

        @Test
        void queryOnlyReturnsGroupsFromTheSpecifiedIdentityZone_whenThereIsNoFilter() {
            List<ScimGroup> groups = dao.query("", secondZoneId);
            assertThat(groups).hasSize(1);
            assertThat(groups.getFirst().getZoneId()).isEqualTo(secondZoneId);
        }

        @Test
        void queryOnlyReturnsGroupsFromTheSpecifiedIdentityZone_whenThereIsAFilter() {
            List<ScimGroup> groups = dao.query("id pr", secondZoneId);
            assertThat(groups).hasSize(1);
            assertThat(groups.getFirst().getZoneId()).isEqualTo(secondZoneId);
        }

        @Test
        void throwsInvalidScimFilter() {
            assertThatThrownBy(() -> dao.query("id pr or", zoneId))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid SCIM Filter");
        }

        @Test
        void doesNotAllowScimQueryInjectionToBeUsedToGainVisibilityIntoAnotherIdentityZone() {
            assertThatThrownBy(() -> dao.query("id pr ) or identity_zone_id pr or ( id pr", zoneId))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("No opening parenthesis matching closing parenthesis");
        }
    }

    @Test
    void sqlInjectionAttackInSortByFieldFails() {
        final String invalidSortBy = "id; select * from oauth_client_details order by id";
        assertThatThrownBy(() -> dao.query("id pr", invalidSortBy, true, zoneId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid sort field: " + invalidSortBy);
    }

    @Test
    void sqlInjectionAttack1Fails() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName='something'; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something'", zoneId));
    }

    @Test
    void sqlInjectionAttack2Fails() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName gt 'a'; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something'", zoneId));
    }

    @Test
    void sqlInjectionAttack3Fails() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName eq \"something\"; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something'", zoneId));
    }

    @Test
    void sqlInjectionAttack4Fails() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName eq \"something\"; select id from " + groupName + "  where id='''; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something'", zoneId));
    }

    @Test
    void sqlInjectionAttack5Fails() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> dao.query("displayName eq \"something\"'; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something''", zoneId));
    }

    @Test
    void createGroupNullZoneId() {
        ScimGroup g = new ScimGroup(null, "null", null);
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER);
        g.setMembers(Arrays.asList(m1, m2));
        ScimGroup errorGroup = g;
        assertThatExceptionOfType(ScimResourceConstraintFailedException.class).isThrownBy(() -> dao.create(errorGroup, null));
        g.setZoneId(zoneId);
        assertThatExceptionOfType(ScimResourceConstraintFailedException.class).isThrownBy(() -> dao.create(errorGroup, null));
        g = dao.create(g, zoneId);
        assertThat(g).isNotNull();
        assertThat(g.getZoneId()).isEqualTo(zoneId);
    }

    @Test
    void deleteGroupByOrigin() {
        ScimGroup g = new ScimGroup(UUID.randomUUID().toString(), "null", zoneId);
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.GROUP);
        m1.setOrigin("custom-origin");
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.GROUP);
        m2.setOrigin("custom-origin");
        g.setMembers(Arrays.asList(m1, m2));
        g = dao.create(g, zoneId);
        dao.deleteByOrigin("custom-origin", zoneId);
        assertThat(memberships.getMembers(g.getId(), true, zoneId)).isEmpty();
    }

    private void validateGroupCountInZone(int expected, String zoneId) {
        int existingGroupCount = jdbcTemplate.queryForObject("select count(id) from "+groupName+" where identity_zone_id='" + zoneId + "'", Integer.class);
        assertThat(existingGroupCount).isEqualTo(expected);
    }

    private void validateGroup(ScimGroup group, String name, String zoneId) {
        assertThat(group).isNotNull();
        assertThat(group.getId()).isNotNull();
        assertThat(group.getDisplayName()).isNotNull();
        if (hasText(name)) {
            assertThat(group.getDisplayName()).isEqualTo(name);
        }
        if (hasText(zoneId)) {
            assertThat(group.getZoneId()).isEqualTo(zoneId);
        }
    }

    private void validateGroup(ScimGroup group, String name, String zoneId, String description) {
        validateGroup(group, name, zoneId);
        if (hasText(description)) {
            assertThat(group.getDescription()).isEqualTo(description);
        }
    }

    private ScimGroup addGroup(String id, String name, String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.update(dao.addGroupSql,
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

    private void addGroupToGroup(String parentGroupId, String childGroupId) {
        ScimGroupMember<ScimGroup> member = new ScimGroupMember<>(dao.retrieve(childGroupId, zoneId));
        memberships.addMember(parentGroupId, member, zoneId);
    }

    private ScimGroup internalCreateGroup(String groupName) {
        ScimGroup g = new ScimGroup(null, groupName, zoneId);
        g.setDescription("description-create");
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER);
        ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER);
        g.setMembers(Arrays.asList(m1, m2));
        g = dao.create(g, zoneId);
        validateGroupCountInZone(4, zoneId);
        validateGroup(g, groupName, zoneId, "description-create");
        return g;
    }
}
