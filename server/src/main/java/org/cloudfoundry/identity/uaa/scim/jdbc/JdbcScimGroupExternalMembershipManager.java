package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.InvalidResultSetAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

public class JdbcScimGroupExternalMembershipManager
        implements ScimGroupExternalMembershipManager {

    private final JdbcTemplate jdbcTemplate;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String EXTERNAL_GROUP_MAPPING_FIELDS = "group_id,external_group,added,origin,identity_zone_id";

    private static final String JOIN_EXTERNAL_GROUP_MAPPING_FIELDS = "gm.group_id,gm.external_group,gm.added,g.displayName,gm.origin";

    static final String EXTERNAL_GROUP_MAPPING_TABLE = "external_group_mapping";

    private static final String GROUP_TABLE = "groups";

    private static final String JOIN_WHERE_ID = "g.id = gm.group_id and gm.origin = ?";

    private static final String ADD_EXTERNAL_GROUP_MAPPING_SQL =
            "insert into %s ( %s ) values (?,lower(?),?,?,?)".formatted(
                    EXTERNAL_GROUP_MAPPING_TABLE,
                    EXTERNAL_GROUP_MAPPING_FIELDS
            );

    private final String joinGroupTable;
    private final String getExternalGroupMappingsSql;
    private final String getExternalGroupMappingsInZoneSql;
    private final String getGroupsByExternalGroupMappingSql;
    private final String getGroupsWithExternalGroupMappingsSql;

    private static final String DELETE_EXTERNAL_GROUP_MAPPING_SQL =
            "delete from %s where group_id=? and lower(external_group)=lower(?) and origin=? and identity_zone_id = ?".formatted(
                    EXTERNAL_GROUP_MAPPING_TABLE
            );

    private static final String DELETE_ALL_MAPPINGS_FOR_GROUP_SQL =
            "delete from %s where group_id = ? and identity_zone_id = ?".formatted(
                    EXTERNAL_GROUP_MAPPING_TABLE
            );

    private final RowMapper<ScimGroupExternalMember> rowMapper;

    private ScimGroupProvisioning scimGroupProvisioning;

    public JdbcScimGroupExternalMembershipManager(final JdbcTemplate jdbcTemplate, DbUtils dbUtils) throws SQLException {
        this.jdbcTemplate = jdbcTemplate;

        this.rowMapper = new ScimGroupExternalMemberRowMapper();

        joinGroupTable = "%s g, %s gm".formatted(
                dbUtils.getQuotedIdentifier(GROUP_TABLE, jdbcTemplate), EXTERNAL_GROUP_MAPPING_TABLE);
        getGroupsWithExternalGroupMappingsSql = "select %s from %s where gm.identity_zone_id = ? and g.id=? and %s and lower(external_group) like lower(?)".formatted(
                JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                joinGroupTable,
                JOIN_WHERE_ID
        );
        getGroupsByExternalGroupMappingSql = "select %s from %s where gm.identity_zone_id = ? and %s and lower(external_group)=lower(?)".formatted(
                JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                joinGroupTable,
                JOIN_WHERE_ID
        );
        getExternalGroupMappingsInZoneSql = "select %s from %s where gm.identity_zone_id=? and g.id = gm.group_id ".formatted(
                JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                joinGroupTable
        );
        getExternalGroupMappingsSql = "select %s from %s where gm.identity_zone_id = ? and gm.group_id=? and %s".formatted(
                JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                joinGroupTable,
                JOIN_WHERE_ID
        );
    }

    public void setScimGroupProvisioning(ScimGroupProvisioning scimGroupProvisioning) {
        this.scimGroupProvisioning = scimGroupProvisioning;
    }

    @Override
    public ScimGroupExternalMember mapExternalGroup(final String groupId,
            final String externalGroup,
            final String origin,
            final String zoneId)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {

        ScimGroup group = scimGroupProvisioning.retrieve(groupId, zoneId);
        if (!StringUtils.hasText(externalGroup)) {
            throw new ScimResourceConstraintFailedException("external group must not be null when mapping an external group");
        }
        if (!StringUtils.hasText(origin)) {
            throw new ScimResourceConstraintFailedException("origin must not be null when mapping an external group");
        }
        if (null != group) {
            try {
                int result = jdbcTemplate.update(ADD_EXTERNAL_GROUP_MAPPING_SQL, ps -> {
                    ps.setString(1, groupId);
                    ps.setString(2, externalGroup);
                    ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
                    ps.setString(4, origin);
                    ps.setString(5, zoneId);

                });
            } catch (DuplicateKeyException e) {
                // we should not throw, if the mapping exist, we should leave it
                // there.
                logger.info("The mapping between group {} and external group {} already exists", group.getDisplayName(), externalGroup);
                // throw new
                // MemberAlreadyExistsException("The mapping between group " +
                // group.getDisplayName() + " and external group " +
                // externalGroup + " already exists");
            }
            return getExternalGroupMap(groupId, externalGroup, origin, zoneId);
        } else {
            throw new ScimResourceNotFoundException("Group does not exist");
        }
    }

    @Override
    public ScimGroupExternalMember unmapExternalGroup(final String groupId,
            final String externalGroup,
            final String origin,
            final String zoneId)
            throws ScimResourceNotFoundException {

        ScimGroup group = scimGroupProvisioning.retrieve(groupId, zoneId);
        ScimGroupExternalMember result = getExternalGroupMap(groupId, externalGroup, origin, zoneId);
        if (null != group && null != result) {
            int count = jdbcTemplate.update(DELETE_EXTERNAL_GROUP_MAPPING_SQL, ps -> {
                ps.setString(1, groupId);
                ps.setString(2, externalGroup);
                ps.setString(3, origin);
                ps.setString(4, zoneId);
            });
            if (count == 1) {
                return result;
            } else if (count == 0) {
                throw new ScimResourceNotFoundException("No group mappings deleted.");
            } else {
                throw new InvalidResultSetAccessException("More than one mapping deleted count=" + count, DELETE_EXTERNAL_GROUP_MAPPING_SQL, new SQLException());
            }
        } else {
            return null;
        }
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMappings(String zoneId) throws ScimResourceNotFoundException {
        return jdbcTemplate.query(getExternalGroupMappingsInZoneSql, ps -> ps.setString(1, zoneId), rowMapper);
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(final String groupId,
            final String origin,
            final String zoneId)
            throws ScimResourceNotFoundException {
        scimGroupProvisioning.retrieve(groupId, zoneId);
        return jdbcTemplate.query(getExternalGroupMappingsSql, ps -> {
            ps.setString(1, zoneId);
            ps.setString(2, groupId);
            ps.setString(3, origin);
        }, rowMapper);
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(
            final String groupName,
            final String origin,
            final String zoneId
    ) throws ScimResourceNotFoundException {
        final ScimGroup group;
        try {
            group = scimGroupProvisioning.getByName(groupName, zoneId);
        } catch (IncorrectResultSizeDataAccessException e) {
            return null;
        }

        return jdbcTemplate.query(getExternalGroupMappingsSql, ps -> {
            ps.setString(1, zoneId);
            ps.setString(2, group.getId());
            ps.setString(3, origin);
        }, rowMapper);
    }

    @Override
    public void unmapAll(String groupId, final String zoneId) throws ScimResourceNotFoundException {
        ScimGroup group = scimGroupProvisioning.retrieve(groupId, zoneId);
        if (null == group) {
            throw new ScimResourceNotFoundException("Group not found for ID " + groupId);
        }

        jdbcTemplate.update(DELETE_ALL_MAPPINGS_FOR_GROUP_SQL, ps -> {
            ps.setString(1, groupId);
            ps.setString(2, zoneId);
        });
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(final String externalGroup,
            final String origin,
            final String zoneId)
            throws ScimResourceNotFoundException {

        return jdbcTemplate.query(getGroupsByExternalGroupMappingSql, ps -> {
            ps.setString(1, zoneId);
            ps.setString(2, origin);
            ps.setString(3, externalGroup);

        }, rowMapper);
    }

    private ScimGroupExternalMember getExternalGroupMap(final String groupId,
            final String externalGroup,
            final String origin,
            final String zoneId)
            throws ScimResourceNotFoundException {
        try {
            return jdbcTemplate.queryForObject(getGroupsWithExternalGroupMappingsSql,
                    rowMapper, zoneId, groupId, origin, externalGroup);
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("The mapping between groupId " + groupId + " and external group "
                    + externalGroup + " does not exist");
        }
    }

    private static final class ScimGroupExternalMemberRowMapper implements RowMapper<ScimGroupExternalMember> {
        @Override
        public ScimGroupExternalMember mapRow(ResultSet rs, int rowNum) throws SQLException {
            String groupId = rs.getString(1);
            String externalGroup = rs.getString(2);
            Timestamp added = rs.getTimestamp(3);
            String displayName = rs.getString(4);
            String origin = rs.getString(5);
            ScimGroupExternalMember result = new ScimGroupExternalMember(groupId, externalGroup);
            result.setDisplayName(displayName);
            result.setOrigin(origin);
            result.getMeta().setCreated(added);
            result.getMeta().setLastModified(added);
            return result;
        }
    }

}
