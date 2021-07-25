package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
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
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.util.StringUtils.hasText;

@WithDatabaseContext
class JdbcScimGroupProvisioningTests {

    private static final String SQL_INJECTION_FIELDS = "displayName,version,created,lastModified";

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

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
    void initJdbcScimGroupProvisioningTests() {
        generator = new RandomValueStringGenerator();
        SecureRandom random = new SecureRandom();
        random.setSeed(System.nanoTime());
        generator.setRandom(random);

        zoneId = generator.generate();

        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        IdentityZoneHolder.set(zone);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(new ArrayList<>());

        validateGroupCountInZone(0, zoneId);

        dao = spy(new JdbcScimGroupProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter)));

        users = mock(ScimUserProvisioning.class);

        memberships = new JdbcScimGroupMembershipManager(jdbcTemplate, new TimeServiceImpl(), users, null);
        memberships.setScimGroupProvisioning(dao);
        dao.setJdbcScimGroupMembershipManager(memberships);

        JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate);
        jdbcScimGroupExternalMembershipManager.setScimGroupProvisioning(dao);
        dao.setJdbcScimGroupExternalMembershipManager(jdbcScimGroupExternalMembershipManager);

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
        assertNotNull(dao.getByName(group3Description, zoneId));
        assertNotNull(dao.getByName(group1Description, zoneId));
        assertNotNull(dao.getByName(group2Description, zoneId));
    }

    @Test
    void get_by_invalid_name() {
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> dao.getByName("invalid-group-name", zoneId),
                Matchers.startsWith("Invalid result size found for")
        );
    }

    @Test
    void get_by_empty_name() {
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> dao.getByName("", zoneId),
                Matchers.startsWith("group name must contain text")
        );
    }

    @Test
    void get_by_null_name() {
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> dao.getByName(null, zoneId),
                Matchers.startsWith("group name must contain text")
        );
    }

    @Test
    void canRetrieveGroups() {
        List<ScimGroup> groups = dao.retrieveAll(zoneId);
        assertEquals(3, groups.size());
        for (ScimGroup g : groups) {
            validateGroup(g, null, zoneId);
        }
    }

    @Test
    void canRetrieveGroupsWithFilter() {
        assertEquals(1, dao.query("displayName eq " + "\"" + group1Description + "\"", zoneId).size());
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
    void canRetrieveGroupsWithFilterAndSortBy() {
        assertEquals(3, dao.query("displayName pr", "id", true, zoneId).size());
        assertEquals(1, dao.query("id co \"2\"", "displayName", false, zoneId).size());
    }

    @Test
    void cannotRetrieveGroupsWithIllegalQuotesFilter() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName eq \"bar", zoneId)
        );
    }

    @Test
    void cannotRetrieveGroupsWithMissingQuotesFilter() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName eq bar", zoneId)
        );
    }

    @Test
    void cannotRetrieveGroupsWithInvalidFieldsFilter() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("name eq \"openid\"", zoneId)
        );
    }

    @Test
    void cannotRetrieveGroupsWithWrongFilter() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName pr \"r\"", zoneId)
        );
    }

    @Test
    void canRetrieveGroup() {
        ScimGroup group = dao.retrieve(g1Id, zoneId);
        validateGroup(group, group1Description, zoneId);
    }

    @Test
    void cannotRetrieveNonExistentGroup() {
        assertThrows(
                ScimResourceNotFoundException.class,
                () -> dao.retrieve("invalidgroup", zoneId)
        );
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
        assertNotNull(same);
        assertEquals(id, same.getId());
    }

    @Test
    void canGetByName() {
        ScimGroup g = internalCreateGroup(generator.generate().toLowerCase());
        ScimGroup same = dao.getByName(g.getDisplayName(), zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    void canCreateAndGetGroupWithQuotes() {
        String nameWithQuotes = generator.generate() + "\"" + generator.generate() + "\"";
        ScimGroup g = internalCreateGroup(nameWithQuotes);
        assertNotNull(g);
        assertEquals(nameWithQuotes, g.getDisplayName());
        ScimGroup same = dao.getByName(nameWithQuotes, zoneId);
        assertNotNull(same);
        assertEquals(g.getId(), same.getId());
    }

    @Test
    void canUpdateGroup() {
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
        assertEquals(1, remainingMemberships.size());
        ScimGroupMember survivor = remainingMemberships.get(0);
        assertThat(survivor.getType(), is(ScimGroupMember.Type.USER));
        assertEquals(bill.getMemberId(), survivor.getMemberId());
    }

    @Test
    void deleteGroupWithNestedMembers() {
        ScimGroup appUsers = addGroup("appuser", "app.user", zoneId);
        addGroupToGroup(appUsers.getId(), g1.getId());
        dao.delete(appUsers.getId(), 0, zoneId);

        List<ScimGroupMember> remainingMemberships = jdbcTemplate.query("select " + MEMBERSHIP_FIELDS + " from " + MEMBERSHIP_TABLE,
                new JdbcScimGroupMembershipManager.ScimGroupMemberRowMapper());
        assertEquals(0, remainingMemberships.size());
    }

    @Test
    void test_that_uaa_scopes_are_bootstrapped_when_zone_is_created() {
        String id = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(id, "subdomain-" + id);
        IdentityZoneModifiedEvent event = IdentityZoneModifiedEvent.identityZoneCreated(zone);
        dao.onApplicationEvent(event);
        List<String> groups = dao.retrieveAll(id).stream().map(ScimGroup::getDisplayName).collect(Collectors.toList());
        ZoneManagementScopes.getSystemScopes()
                .forEach(scope ->
                        assertTrue(groups.contains(scope), "Scope:" + scope + " should have been bootstrapped into the new zone")
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
            assertThat(groups, hasSize(1));
            assertThat(groups.get(0).getZoneId(), is(secondZoneId));
        }

        @Test
        void queryOnlyReturnsGroupsFromTheSpecifiedIdentityZone_whenThereIsAFilter() {
            List<ScimGroup> groups = dao.query("id pr", secondZoneId);
            assertThat(groups, hasSize(1));
            assertThat(groups.get(0).getZoneId(), is(secondZoneId));
        }

        @Test
        void throwsInvalidScimFilter() {
            assertThrowsWithMessageThat(IllegalArgumentException.class,
                    () -> dao.query("id pr or", zoneId),
                    containsString("Invalid SCIM Filter"));
        }

        @Test
        void doesNotAllowScimQueryInjectionToBeUsedToGainVisibilityIntoAnotherIdentityZone() {
            assertThrowsWithMessageThat(IllegalArgumentException.class,
                    () -> dao.query("id pr ) or identity_zone_id pr or ( id pr", zoneId),
                    containsString("No opening parenthesis matching closing parenthesis"));
        }
    }

    @Test
    void sqlInjectionAttackInSortByFieldFails() {
        final String invalidSortBy = "id; select * from oauth_client_details order by id";
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> dao.query("id pr", invalidSortBy, true, zoneId),
                is("Invalid sort field: " + invalidSortBy)
        );
    }

    @Test
    void sqlInjectionAttack1Fails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName='something'; select " + SQL_INJECTION_FIELDS
                        + " from groups where displayName='something'", zoneId)
        );
    }

    @Test
    void sqlInjectionAttack2Fails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName gt 'a'; select " + SQL_INJECTION_FIELDS
                        + " from groups where displayName='something'", zoneId)
        );
    }

    @Test
    void sqlInjectionAttack3Fails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName eq \"something\"; select " + SQL_INJECTION_FIELDS
                        + " from groups where displayName='something'", zoneId)
        );
    }

    @Test
    void sqlInjectionAttack4Fails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName eq \"something\"; select id from groups where id='''; select " + SQL_INJECTION_FIELDS
                        + " from groups where displayName='something'", zoneId)
        );
    }

    @Test
    void sqlInjectionAttack5Fails() {
        assertThrows(
                IllegalArgumentException.class,
                () -> dao.query("displayName eq \"something\"'; select " + SQL_INJECTION_FIELDS
                        + " from groups where displayName='something''", zoneId)
        );
    }

    private void validateGroupCountInZone(int expected, String zoneId) {
        int existingGroupCount = jdbcTemplate.queryForObject("select count(id) from groups where identity_zone_id='" + zoneId + "'", Integer.class);
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

    private ScimGroup addGroup(String id, String name, String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.update(JdbcScimGroupProvisioning.ADD_GROUP_SQL,
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
