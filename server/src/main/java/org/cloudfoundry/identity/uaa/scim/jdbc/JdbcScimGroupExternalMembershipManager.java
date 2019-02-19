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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jca.cci.InvalidResultSetAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

public class JdbcScimGroupExternalMembershipManager
    implements ScimGroupExternalMembershipManager {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String EXTERNAL_GROUP_MAPPING_FIELDS = "group_id,external_group,added,origin,identity_zone_id";

    public static final String JOIN_EXTERNAL_GROUP_MAPPING_FIELDS = "gm.group_id,gm.external_group,gm.added,g.displayName,gm.origin";

    public static final String EXTERNAL_GROUP_MAPPING_TABLE = "external_group_mapping";

    public static final String GROUP_TABLE = "groups";

    public static final String JOIN_GROUP_TABLE = String.format("%s g, %s gm",GROUP_TABLE, EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String JOIN_WHERE_ID = "g.id = gm.group_id and gm.origin = ?";

    public static final String ADD_EXTERNAL_GROUP_MAPPING_SQL =
        String.format("insert into %s ( %s ) values (?,lower(?),?,?,?)",
                      EXTERNAL_GROUP_MAPPING_TABLE,
                      EXTERNAL_GROUP_MAPPING_FIELDS
        );

    public static final String GET_EXTERNAL_GROUP_MAPPINGS_SQL =
        String.format("select %s from %s where gm.identity_zone_id = ? and gm.group_id=? and %s",
                      JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                      JOIN_GROUP_TABLE,
                      JOIN_WHERE_ID
        );

    public static final String GET_EXTERNAL_GROUP_MAPPINGS_IN_ZONE_SQL =
        String.format("select %s from %s where gm.identity_zone_id=? and g.id = gm.group_id ",
                      JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                      JOIN_GROUP_TABLE
        );

    public static final String GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL =
        String.format("select %s from %s where gm.identity_zone_id = ? and %s and lower(external_group)=lower(?)",
                      JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                      JOIN_GROUP_TABLE,
                      JOIN_WHERE_ID
        );

    public static final String GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL =
        String.format("select %s from %s where gm.identity_zone_id = ? and g.id=? and %s and lower(external_group) like lower(?)",
                      JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
                      JOIN_GROUP_TABLE,
                      JOIN_WHERE_ID
        );

    public static final String DELETE_EXTERNAL_GROUP_MAPPING_SQL =
        String.format("delete from %s where group_id=? and lower(external_group)=lower(?) and origin=? and identity_zone_id = ?",
                      EXTERNAL_GROUP_MAPPING_TABLE
        );

    public static final String DELETE_ALL_MAPPINGS_FOR_GROUP_SQL =
        String.format("delete from %s where group_id = ? and identity_zone_id = ?",
                      EXTERNAL_GROUP_MAPPING_TABLE
        );

    private final RowMapper<ScimGroupExternalMember> rowMapper = new ScimGroupExternalMemberRowMapper();

    private ScimGroupProvisioning scimGroupProvisioning;

    public JdbcScimGroupExternalMembershipManager(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }
    @Override
    public ScimGroupExternalMember mapExternalGroup(final String groupId,
                                                    final String externalGroup,
                                                    final String origin,
                                                    final String zoneId)
        throws ScimResourceNotFoundException, MemberAlreadyExistsException {

        ScimGroup group = scimGroupProvisioning.retrieve(groupId, IdentityZoneHolder.get().getId());
        if (!StringUtils.hasText(externalGroup)) {
            throw new ScimResourceConstraintFailedException("external group must not be null when mapping an external group");
        }
        if (!StringUtils.hasText(origin)) {
            throw new ScimResourceConstraintFailedException("origin must not be null when mapping an external group");
        }
        if (null != group) {
            try {
                int result = jdbcTemplate.update(ADD_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
                    @Override
                    public void setValues(PreparedStatement ps) throws SQLException {
                        ps.setString(1, groupId);
                        ps.setString(2, externalGroup);
                        ps.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
                        ps.setString(4, origin);
                        ps.setString(5, zoneId);

                    }
                });
            } catch (DuplicateKeyException e) {
                // we should not throw, if the mapping exist, we should leave it
                // there.
                logger.info("The mapping between group " + group.getDisplayName() + " and external group "
                                + externalGroup + " already exists");
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

        ScimGroup group = scimGroupProvisioning.retrieve(groupId, IdentityZoneHolder.get().getId());
        ScimGroupExternalMember result = getExternalGroupMap(groupId, externalGroup, origin, zoneId);
        if (null != group && null != result) {
            int count = jdbcTemplate.update(DELETE_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, groupId);
                    ps.setString(2, externalGroup);
                    ps.setString(3, origin);
                    ps.setString(4, zoneId);
                }
            });
            if (count==1) {
                return result;
            } else if (count==0) {
                throw new ScimResourceNotFoundException("No group mappings deleted.");
            } else {
                throw new InvalidResultSetAccessException("More than one mapping deleted count="+count, new SQLException());
            }
        } else {
            return null;
        }
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMappings(String zoneId) throws ScimResourceNotFoundException {
        return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_IN_ZONE_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, zoneId);
            }
        }, rowMapper);
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(final String groupId,
                                                                       final String origin,
                                                                       final String zoneId)
        throws ScimResourceNotFoundException {
        scimGroupProvisioning.retrieve(groupId, IdentityZoneHolder.get().getId());
        return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, zoneId);
                ps.setString(2, groupId);
                ps.setString(3, origin);
            }
        }, rowMapper);
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(final String groupName,
                                                                         final String origin,
                                                                         final String zoneId)
        throws ScimResourceNotFoundException {

        final List<ScimGroup> groups = scimGroupProvisioning.query(String.format("displayName eq \"%s\"", groupName), IdentityZoneHolder.get().getId());

        if (null != groups && groups.size() > 0) {
            return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, zoneId);
                    ps.setString(2, groups.get(0).getId());
                    ps.setString(3, origin);
                }
            }, rowMapper);
        } else {
            return null;
        }
    }

    @Override
    public void unmapAll(String groupId, final String zoneId) throws ScimResourceNotFoundException {
            ScimGroup group = scimGroupProvisioning.retrieve(groupId, IdentityZoneHolder.get().getId());
            if (null == group) {
                throw new ScimResourceNotFoundException("Group not found for ID " + groupId);
            }

            jdbcTemplate.update(DELETE_ALL_MAPPINGS_FOR_GROUP_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, groupId);
                    ps.setString(2, zoneId);
                }
            });
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(final String externalGroup,
                                                                             final String origin,
                                                                             final String zoneId)
        throws ScimResourceNotFoundException {

        return jdbcTemplate.query(GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, zoneId);
                ps.setString(2, origin);
                ps.setString(3, externalGroup);

            }
        }, rowMapper);
    }

    private ScimGroupExternalMember getExternalGroupMap(final String groupId,
                                                        final String externalGroup,
                                                        final String origin,
                                                        final String zoneId)
                    throws ScimResourceNotFoundException {
        try {
            ScimGroupExternalMember u = jdbcTemplate.queryForObject(GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL,
                                                                    rowMapper, zoneId, groupId, origin, externalGroup);
            return u;
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

    public void setScimGroupProvisioning(ScimGroupProvisioning scimGroupProvisioning) {
        this.scimGroupProvisioning = scimGroupProvisioning;
    }

}
