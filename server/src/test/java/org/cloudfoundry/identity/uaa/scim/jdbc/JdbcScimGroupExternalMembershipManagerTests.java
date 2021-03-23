package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithDatabaseContext
class JdbcScimGroupExternalMembershipManagerTests {

    private JdbcScimGroupProvisioning gdao;

    private JdbcScimGroupExternalMembershipManager edao;

    private static final String addGroupSqlFormat = "insert into groups (id, displayName, identity_zone_id) values ('%s','%s','%s')";

    private String origin = OriginKeys.LDAP;

    private IdentityZone otherZone;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void setUp() {

        org.cloudfoundry.identity.uaa.test.TestUtils.cleanAndSeedDb(jdbcTemplate);

        String otherZoneId = new RandomValueStringGenerator().generate();
        otherZone = MultitenancyFixture.identityZone(otherZoneId, otherZoneId);
        otherZone = new JdbcIdentityZoneProvisioning(jdbcTemplate).create(otherZone);

        JdbcTemplate template = new JdbcTemplate(dataSource);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        gdao = new JdbcScimGroupProvisioning(template, pagingListFactory);

        JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate, new TimeServiceImpl(), null, null);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(gdao);
        gdao.setJdbcScimGroupMembershipManager(jdbcScimGroupMembershipManager);

        JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate);
        jdbcScimGroupExternalMembershipManager.setScimGroupProvisioning(gdao);
        gdao.setJdbcScimGroupExternalMembershipManager(jdbcScimGroupExternalMembershipManager);

        edao = new JdbcScimGroupExternalMembershipManager(template);
        edao.setScimGroupProvisioning(gdao);

        for (String zoneId : Arrays.asList(IdentityZone.getUaaZoneId(), otherZone.getId())) {
            addGroup("g1-" + zoneId, "test1", zoneId);
            addGroup("g2-" + zoneId, "test2", zoneId);
            addGroup("g3-" + zoneId, "test3", zoneId);
        }

        validateCount(0);
    }

    private void addGroup(
            final String id,
            final String name,
            final String zoneId) {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        jdbcTemplate.execute(String.format(addGroupSqlFormat, id, name, zoneId));
    }

    private void validateCount(int expected) {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from external_group_mapping", Integer.class);
        assertEquals(expected, existingMemberCount);
    }

    @Test
    void addExternalMappingToGroup() {
        createGroupMapping();
    }

    @Test
    void deleteGroupAndMappings() {
        createGroupMapping();
        gdao.delete("g1-" + IdentityZone.getUaaZoneId(), -1, IdentityZone.getUaaZoneId());
        int mappingsCount = jdbcTemplate.queryForObject("select count(1) from " + JdbcScimGroupExternalMembershipManager.EXTERNAL_GROUP_MAPPING_TABLE, Integer.class);
        assertEquals(0, mappingsCount);
    }

    @Test
    void test_group_mapping() {
        createGroupMapping();
        assertEquals(1, edao.getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId()).size());
        assertEquals(0, edao.getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, "id").size());
    }

    private void createGroupMapping() {
        ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
        assertNotNull(group);

        ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
        assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
        assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");

        List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());

        assertEquals(1, externalMapping.size());
    }

    @Test
    void cannot_Retrieve_ById_For_OtherZone() {
        assertThrows(ScimResourceNotFoundException.class, () -> edao.getExternalGroupMapsByGroupId("g1-" + otherZone.getId(), origin, IdentityZone.getUaaZoneId()));
    }

    @Test
    void cannot_Map_ById_For_OtherZone() {
        assertThrows(ScimResourceNotFoundException.class, () -> edao.mapExternalGroup("g1-" + otherZone.getId(), "CN=engineering,OU=groups,DC=example,DC=com", origin, IdentityZone.getUaaZoneId()));
    }

    @Test
    void using_filter_query_filters_by_zone() {
        map3GroupsInEachZone();
        assertEquals(0, edao.getExternalGroupMappings("invalid-zone-id").size());
        assertEquals(3, edao.getExternalGroupMappings(otherZone.getId()).size());
    }

    protected void map3GroupsInEachZone() {
        for (String zoneId : Arrays.asList(IdentityZone.getUaaZoneId(), otherZone.getId())) {

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=engineering,ou=groups,dc=example,dc=com", origin, zoneId);
                assertEquals(member.getGroupId(), "g1-" + zoneId);
                assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=hr,ou=groups,dc=example,dc=com", origin, zoneId);
                assertEquals(member.getGroupId(), "g1-" + zoneId);
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=mgmt,ou=groups,dc=example,dc=com", origin, zoneId);
                assertEquals(member.getGroupId(), "g1-" + zoneId);
                assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
            }
        }
    }

    @Test
    void adding_ExternalMappingToGroup_IsCaseInsensitive() {
        createGroupMapping();
        ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "CN=engineering,OU=groups,DC=example,DC=com", origin, IdentityZone.getUaaZoneId());
        assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
        assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
        List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
        assertEquals(externalMapping.size(), 1);
    }

    @Test
    void addExternalMappingToGroupThatAlreadyExists() {
        createGroupMapping();

        ScimGroupExternalMember dupMember = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
        assertEquals(dupMember.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
        assertEquals(dupMember.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
    }

    @Test
    void addMultipleExternalMappingsToGroup() {
        ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
        assertNotNull(group);

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
            assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
        }

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=hr,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
            assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
        }

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
            assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
        }

        List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
        assertEquals(externalMappings.size(), 3);

        List<String> testGroups = new ArrayList<>(
                Arrays.asList(
                        new String[]{
                                "cn=engineering,ou=groups,dc=example,dc=com",
                                "cn=hr,ou=groups,dc=example,dc=com",
                                "cn=mgmt,ou=groups,dc=example,dc=com"
                        }
                )
        );
        for (ScimGroupExternalMember member : externalMappings) {
            assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
            testGroups.remove(member.getExternalGroup());
        }

        assertEquals(testGroups.size(), 0);
    }

    @Test
    void addMultipleExternalMappingsToMultipleGroup() {
        {
            ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertNotNull(group);

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g1-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertEquals(externalMappings.size(), 3);
        }
        {
            ScimGroup group = gdao.retrieve("g2-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertNotNull(group);

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g2-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g2-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g2-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g2-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertEquals(externalMappings.size(), 3);
        }
        {
            ScimGroup group = gdao.retrieve("g3-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertNotNull(group);

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g3-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g3-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertEquals(member.getGroupId(), "g3-" + IdentityZone.getUaaZoneId());
                assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g3-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertEquals(externalMappings.size(), 3);
        }

        List<String> testGroups = new ArrayList<>(Arrays.asList(new String[]{"g1-" + IdentityZone.getUaaZoneId(), "g2-" + IdentityZone.getUaaZoneId(), "g3-" + IdentityZone.getUaaZoneId()}));

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertEquals(testGroups.size(), 0);
        }

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=hr,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertEquals(testGroups.size(), 0);

            List<ScimGroupExternalMember> externalMappings2 = edao
                    .getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings2) {
                assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertEquals(testGroups.size(), 0);
        }

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertEquals(testGroups.size(), 0);
        }
    }
}
