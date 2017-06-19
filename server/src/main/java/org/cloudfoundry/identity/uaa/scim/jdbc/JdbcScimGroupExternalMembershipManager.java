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
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jca.cci.InvalidResultSetAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

public class JdbcScimGroupExternalMembershipManager extends AbstractQueryable<ScimGroupExternalMember>
    implements ScimGroupExternalMembershipManager {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String EXTERNAL_GROUP_MAPPING_FIELDS = "group_id,external_group,added,origin";

    public static final String JOIN_EXTERNAL_GROUP_MAPPING_FIELDS = "gm.group_id,gm.external_group,gm.added,g.displayName,gm.origin";

    public static final String EXTERNAL_GROUP_MAPPING_TABLE = "external_group_mapping";

    public static final String GROUP_TABLE = "groups";

    public static final String JOIN_GROUP_TABLE = String.format("%s g, %s gm",GROUP_TABLE, EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String JOIN_WHERE_ID = "g.id = gm.group_id and gm.origin = ?";

    public static final String DELETE_FROM_TABLE_SQL ="DELETE FROM %s WHERE %s identity_zone_id='%s'";

    public static final String ADD_EXTERNAL_GROUP_MAPPING_SQL = String.format("insert into %s ( %s ) values (?,lower(?),?,?,?)",
                    EXTERNAL_GROUP_MAPPING_TABLE, EXTERNAL_GROUP_MAPPING_FIELDS + ",identity_zone_id");

    public static final String GET_EXTERNAL_GROUP_MAPPINGS_SQL = String.format(
        "select %s from %s where g.identity_zone_id=? and gm.group_id=? and %s",
        JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
        JOIN_GROUP_TABLE,
        JOIN_WHERE_ID
    );

    public static final String GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL = String.format(
        "select %s from %s where gm.identity_zone_id=? and %s and lower(external_group)=lower(?)",
        JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
        JOIN_GROUP_TABLE,
        JOIN_WHERE_ID
    );

    public static final String GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL = String.format(
        "select %s from %s where g.identity_zone_id=? and g.id=? and %s and lower(external_group) like lower(?)",
        JOIN_EXTERNAL_GROUP_MAPPING_FIELDS,
        JOIN_GROUP_TABLE,
        JOIN_WHERE_ID
    );

    public static final String DELETE_EXTERNAL_GROUP_MAPPING_SQL = String.format(
        "delete from %s where identity_zone_id=? and group_id=? and lower(external_group)=lower(?) and origin=?",
        EXTERNAL_GROUP_MAPPING_TABLE
    );

    public static final String DELETE_ALL_MAPPINGS_FOR_GROUP_SQL = String.format(
        "delete from %s where identity_zone_id=? and group_id = ?",
        EXTERNAL_GROUP_MAPPING_TABLE
    );

    private final RowMapper<ScimGroupExternalMember> rowMapper = new ScimGroupExternalMemberRowMapper();

    private ScimGroupProvisioning scimGroupProvisioning;

    public JdbcScimGroupExternalMembershipManager(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ScimGroupExternalMemberRowMapper());
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        setQueryConverter(new ScimSearchQueryConverter());
    }

    protected String adjustFilterForJoin(String filter) {
        if (StringUtils.hasText(filter)) {
            filter = filter.replace("displayName", "g.displayName");
            filter = filter.replace("externalGroup", "gm.external_group");
            filter = filter.replace("groupId", "g.id");
            filter = filter.replace("origin", "gm.origin");
        }
        return filter;
    }

    @Override
    protected String getTableName() {
        return EXTERNAL_GROUP_MAPPING_TABLE;
    }

    @Override
    public List<ScimGroupExternalMember> query(String filter) {
        return super.query(filter);
    }

    @Override
    public int delete(String filter) {
        SearchQueryConverter.ProcessedFilter where = getQueryConverter().convert(filter, null, false);
        logger.debug("Filtering groups with SQL: " + where);
        try {
            String whereClause = "";
            if (StringUtils.hasText(where.getSql())) {
                whereClause = where.getSql() + " AND ";
            }
            String completeSql = String.format(DELETE_FROM_TABLE_SQL, getTableName(), whereClause, IdentityZoneHolder.get().getId());
            logger.debug("delete sql: " + completeSql + ", params: " + where.getParams());
            return new NamedParameterJdbcTemplate(jdbcTemplate).update(completeSql, where.getParams());
        } catch (DataAccessException e) {
            logger.debug("Filter '" + filter + "' generated invalid SQL", e);
            throw new IllegalArgumentException("Invalid delete filter: " + filter);
        }
    }

    @Override
    public List<ScimGroupExternalMember> query(String filter, String sortBy, boolean ascending) {
        return super.query(adjustFilterForJoin(filter), sortBy, ascending);
    }

    @Override
    public ScimGroupExternalMember mapExternalGroup(final String groupId,
                                                    final String externalGroup,
                                                    final String origin)
        throws ScimResourceNotFoundException, MemberAlreadyExistsException {

        ScimGroup group = scimGroupProvisioning.retrieve(groupId);
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
                        ps.setString(5, IdentityZoneHolder.get().getId());

                    }
                });
                System.out.println("update count = " + result);
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
            return getExternalGroupMap(groupId, externalGroup, origin);
        } else {
            throw new ScimResourceNotFoundException("Group does not exist");
        }
    }

    @Override
    public ScimGroupExternalMember unmapExternalGroup(final String groupId,
                                                      final String externalGroup,
                                                      final String origin)
        throws ScimResourceNotFoundException {

        ScimGroup group = scimGroupProvisioning.retrieve(groupId);
        ScimGroupExternalMember result = getExternalGroupMap(groupId, externalGroup, origin);
        if (null != group && null != result) {
            int count = jdbcTemplate.update(DELETE_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, IdentityZoneHolder.get().getId());
                    ps.setString(2, groupId);
                    ps.setString(3, externalGroup);
                    ps.setString(4, origin);
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
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(final String groupId,
                                                                       final String origin)
        throws ScimResourceNotFoundException {
        scimGroupProvisioning.retrieve(groupId);
        return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, IdentityZoneHolder.get().getId());
                ps.setString(2, groupId);
                ps.setString(3, origin);
            }
        }, rowMapper);
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(final String groupName,
                                                                         final String origin)
        throws ScimResourceNotFoundException {

        final List<ScimGroup> groups = scimGroupProvisioning.query(String.format("displayName eq \"%s\"", groupName));

        if (null != groups && groups.size() > 0) {
            return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, IdentityZoneHolder.get().getId());
                    ps.setString(2, groups.get(0).getId());
                    ps.setString(3, origin);
                }
            }, rowMapper);
        } else {
            return null;
        }
    }

    @Override
    public void unmapAll(String groupId) throws ScimResourceNotFoundException {
            ScimGroup group = scimGroupProvisioning.retrieve(groupId);
            if (null == group) {
                throw new ScimResourceNotFoundException("Group not found for ID " + groupId);
            }

            jdbcTemplate.update(DELETE_ALL_MAPPINGS_FOR_GROUP_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, IdentityZoneHolder.get().getId());
                    ps.setString(2, groupId);
                }
            });
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(final String externalGroup,
                                                                             final String origin)
        throws ScimResourceNotFoundException {

        return jdbcTemplate.query(GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, IdentityZoneHolder.get().getId());
                ps.setString(2, origin);
                ps.setString(3, externalGroup);

            }
        }, rowMapper);
    }

    @Override
    protected String getQuerySQL(String filter, SearchQueryConverter.ProcessedFilter where) {
        boolean containsWhereClause = getBaseSqlQuery().contains(" where ");
        return filter == null || filter.trim().length()==0 ?
            getBaseSqlQuery() :
            getBaseSqlQuery() + (containsWhereClause ? " and " : " where ") + where.getSql();
    }

    private ScimGroupExternalMember getExternalGroupMap(final String groupId,
                                                        final String externalGroup,
                                                        final String origin)
                    throws ScimResourceNotFoundException {
        try {
            ScimGroupExternalMember u = jdbcTemplate.queryForObject(GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL,
                                                                    rowMapper,
                                                                    IdentityZoneHolder.get().getId(),
                                                                    groupId,
                                                                    origin,
                                                                    externalGroup);
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

    @Override
    protected String getBaseSqlQuery() {
        return String.format("select %s from %s where %s",
            JOIN_EXTERNAL_GROUP_MAPPING_FIELDS, JOIN_GROUP_TABLE, "g.id = gm.group_id and g.identity_zone_id='"+IdentityZoneHolder.get().getId()+"'");
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, EXTERNAL_GROUP_MAPPING_FIELDS);
    }
}
