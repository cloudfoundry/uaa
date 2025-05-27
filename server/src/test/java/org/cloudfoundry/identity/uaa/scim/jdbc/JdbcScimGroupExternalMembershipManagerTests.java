package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@WithDatabaseContext
class JdbcScimGroupExternalMembershipManagerTests {

    private JdbcScimGroupProvisioning gdao;

    private JdbcScimGroupExternalMembershipManager edao;

    private static final String addGroupSqlFormat = "insert into %s (id, displayName, identity_zone_id) values ('%s','%s','%s')";

    private String origin = OriginKeys.LDAP;

    private IdentityZone otherZone;

    private DbUtils dbUtils;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void setUp() throws SQLException {

        org.cloudfoundry.identity.uaa.test.TestUtils.cleanAndSeedDb(jdbcTemplate);

        String otherZoneId = new RandomValueStringGenerator().generate();
        otherZone = MultitenancyFixture.identityZone(otherZoneId, otherZoneId);
        otherZone = new JdbcIdentityZoneProvisioning(jdbcTemplate).create(otherZone);

        JdbcTemplate template = new JdbcTemplate(dataSource);
        dbUtils = new DbUtils();

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter);
        gdao = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);

        JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(
                new IdentityZoneManagerImpl(), jdbcTemplate, new TimeServiceImpl(), null, null, dbUtils);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(gdao);
        gdao.setJdbcScimGroupMembershipManager(jdbcScimGroupMembershipManager);

        JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager =
                new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        jdbcScimGroupExternalMembershipManager.setScimGroupProvisioning(gdao);
        gdao.setJdbcScimGroupExternalMembershipManager(jdbcScimGroupExternalMembershipManager);

        edao = new JdbcScimGroupExternalMembershipManager(template, dbUtils);
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
            final String zoneId) throws SQLException {
        TestUtils.assertNoSuchUser(jdbcTemplate, id);
        String quotedGroupsIdentifier = dbUtils.getQuotedIdentifier("groups", jdbcTemplate);
        jdbcTemplate.execute(addGroupSqlFormat.formatted(quotedGroupsIdentifier, id, name, zoneId));
    }

    private void validateCount(int expected) {
        int existingMemberCount = jdbcTemplate.queryForObject("select count(*) from external_group_mapping", Integer.class);
        assertThat(existingMemberCount).isEqualTo(expected);
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
        assertThat(mappingsCount).isZero();
    }

    @Test
    void group_mapping() {
        createGroupMapping();
        assertThat(edao.getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId())).hasSize(1);
        assertThat(edao.getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, "id")).isEmpty();
    }

    private void createGroupMapping() {
        ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
        assertThat(group).isNotNull();

        ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
        assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
        assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");

        List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());

        assertThat(externalMapping).hasSize(1);
    }

    @Test
    void cannot_Retrieve_ById_For_OtherZone() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> edao.getExternalGroupMapsByGroupId("g1-" + otherZone.getId(), origin, IdentityZone.getUaaZoneId()));
    }

    @Test
    void cannot_Map_ById_For_OtherZone() {
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() -> edao.mapExternalGroup("g1-" + otherZone.getId(), "CN=engineering,OU=groups,DC=example,DC=com", origin, IdentityZone.getUaaZoneId()));
    }

    @Test
    void using_filter_query_filters_by_zone() {
        map3GroupsInEachZone();
        assertThat(edao.getExternalGroupMappings("invalid-zone-id")).isEmpty();
        assertThat(edao.getExternalGroupMappings(otherZone.getId())).hasSize(3);
    }

    protected void map3GroupsInEachZone() {
        for (String zoneId : Arrays.asList(IdentityZone.getUaaZoneId(), otherZone.getId())) {

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=engineering,ou=groups,dc=example,dc=com", origin, zoneId);
                assertThat("g1-" + zoneId).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=hr,ou=groups,dc=example,dc=com", origin, zoneId);
                assertThat("g1-" + zoneId).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + zoneId, "cn=mgmt,ou=groups,dc=example,dc=com", origin, zoneId);
                assertThat("g1-" + zoneId).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
            }
        }
    }

    @Test
    void adding_ExternalMappingToGroup_IsCaseInsensitive() {
        createGroupMapping();
        ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "CN=engineering,OU=groups,DC=example,DC=com", origin, IdentityZone.getUaaZoneId());
        assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
        assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
        List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
        assertThat(externalMapping).hasSize(1);
    }

    @Test
    void addExternalMappingToGroupThatAlreadyExists() {
        createGroupMapping();

        ScimGroupExternalMember dupMember = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
        assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(dupMember.getGroupId());
        assertThat(dupMember.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
    }

    @Test
    void addMultipleExternalMappingsToGroup() {
        ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
        assertThat(group).isNotNull();

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
            assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
        }

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=hr,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
            assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
        }

        {
            ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
            assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
        }

        List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
        assertThat(externalMappings).hasSize(3);

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
            assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
            testGroups.remove(member.getExternalGroup());
        }

        assertThat(testGroups).isEmpty();
    }

    @Test
    void addMultipleExternalMappingsToMultipleGroup() {
        {
            ScimGroup group = gdao.retrieve("g1-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertThat(group).isNotNull();

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g1-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g1-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertThat(externalMappings).hasSize(3);
        }
        {
            ScimGroup group = gdao.retrieve("g2-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertThat(group).isNotNull();

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g2-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g2-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g2-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g2-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g2-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertThat(externalMappings).hasSize(3);
        }
        {
            ScimGroup group = gdao.retrieve("g3-" + IdentityZone.getUaaZoneId(), IdentityZone.getUaaZoneId());
            assertThat(group).isNotNull();

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g3-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g3-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
            }

            {
                ScimGroupExternalMember member = edao.mapExternalGroup("g3-" + IdentityZone.getUaaZoneId(), "cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
                assertThat("g3-" + IdentityZone.getUaaZoneId()).isEqualTo(member.getGroupId());
                assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
            }
            List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g3-" + IdentityZone.getUaaZoneId(), origin, IdentityZone.getUaaZoneId());
            assertThat(externalMappings).hasSize(3);
        }

        List<String> testGroups = new ArrayList<>(Arrays.asList(new String[]{"g1-" + IdentityZone.getUaaZoneId(), "g2-" + IdentityZone.getUaaZoneId(), "g3-" + IdentityZone.getUaaZoneId()}));

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertThat(member.getExternalGroup()).isEqualTo("cn=engineering,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertThat(testGroups).isEmpty();
        }

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=hr,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertThat(testGroups).isEmpty();

            List<ScimGroupExternalMember> externalMappings2 = edao
                    .getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings2) {
                assertThat(member.getExternalGroup()).isEqualTo("cn=hr,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertThat(testGroups).isEmpty();
        }

        {
            // LDAP groups are case preserving on fetch and case insensitive on
            // search
            List<ScimGroupExternalMember> externalMappings = edao
                    .getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com", origin, IdentityZone.getUaaZoneId());
            for (ScimGroupExternalMember member : externalMappings) {
                assertThat(member.getExternalGroup()).isEqualTo("cn=mgmt,ou=groups,dc=example,dc=com");
                testGroups.remove(member.getGroupId());
            }

            assertThat(testGroups).isEmpty();
        }
    }
}
