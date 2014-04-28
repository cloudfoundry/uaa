/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.dao.standard;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupExternalMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

public class JdbcScimGroupExternalMembershipManager extends AbstractQueryable<ScimGroupExternalMemberInterface> implements
                ScimGroupExternalMembershipManager {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String EXTERNAL_GROUP_MAPPING_FIELDS = "group_id,external_group,added";

    public static final String EXTERNAL_GROUP_MAPPING_TABLE = "external_group_mapping";

    public static final String ADD_EXTERNAL_GROUP_MAPPING_SQL = String.format("insert into %s ( %s ) values (?,?,?)",
                    EXTERNAL_GROUP_MAPPING_TABLE, EXTERNAL_GROUP_MAPPING_FIELDS);

    public static final String UPDATE_EXTERNAL_GROUP_MAPPING_SQL = String.format(
                    "update %s set external_group=? where group_id=?", EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String GET_EXTERNAL_GROUP_MAP_SQL = String.format("select %s from %s",
                    EXTERNAL_GROUP_MAPPING_FIELDS, EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String GET_EXTERNAL_GROUP_MAPPINGS_SQL = String.format("select %s from %s where group_id=?",
                    EXTERNAL_GROUP_MAPPING_FIELDS, EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL = String.format(
                    "select %s from %s where lower(external_group)=lower(?)", EXTERNAL_GROUP_MAPPING_FIELDS,
                    EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL = String.format(
                    "select %s from %s where group_id=? and lower(external_group) like lower(?)",
                    EXTERNAL_GROUP_MAPPING_FIELDS, EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String DELETE_EXTERNAL_GROUP_MAPPING_SQL = String.format(
                    "delete from %s where group_id=? and lower(external_group)=lower(?)", EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String DELETE_EXTERNAL_GROUP_MAPPINGS_USING_GROUP_SQL = String.format(
                    "delete from %s where group_id=?", EXTERNAL_GROUP_MAPPING_TABLE);

    public static final String DELETE_EXTERNAL_GROUP_MAPPING_USING_EXTERNAL_GROUPS_SQL = String.format(
                    "delete from %s where lower(external_group)=lower(?)", EXTERNAL_GROUP_MAPPING_TABLE);

    private final RowMapper<ScimGroupExternalMemberInterface> rowMapper = new ScimGroupExternalMemberRowMapper();

    private ScimGroupProvisioning scimGroupProvisioning;

    public JdbcScimGroupExternalMembershipManager(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ScimGroupExternalMemberRowMapper());
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        setQueryConverter(new ScimSearchQueryConverter());
    }

    @Override
    public ScimGroupExternalMemberInterface mapExternalGroup(final String groupId, final String externalGroup)
                    throws ScimResourceNotFoundException, MemberAlreadyExistsException {
        ScimGroupInterface group = scimGroupProvisioning.retrieve(groupId);

        if (null != group) {
            try {
                jdbcTemplate.update(ADD_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
                    @Override
                    public void setValues(PreparedStatement ps) throws SQLException {
                        ps.setString(1, groupId);
                        ps.setString(2, externalGroup);
                        ps.setTimestamp(3, new Timestamp(new Date().getTime()));
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
            return getExternalGroupMap(groupId, externalGroup);
        } else {
            return null;
        }
    }

    @Override
    public List<ScimGroupExternalMemberInterface> getExternalGroupMapsByGroupId(final String groupId)
                    throws ScimResourceNotFoundException {
        return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, groupId);
            }
        }, rowMapper);
    }

    @Override
    public List<ScimGroupExternalMemberInterface> getExternalGroupMapsByGroupName(final String groupName)
                    throws ScimResourceNotFoundException {
        final List<ScimGroupInterface> groups = scimGroupProvisioning.query(String.format("displayName eq '%s'", groupName));

        if (null != groups && groups.size() > 0) {
            return jdbcTemplate.query(GET_EXTERNAL_GROUP_MAPPINGS_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, groups.get(0).getId());
                }
            }, rowMapper);
        } else {
            return null;
        }
    }

    @Override
    public List<ScimGroupExternalMemberInterface> getExternalGroupMapsByExternalGroup(final String externalGroup)
                    throws ScimResourceNotFoundException {
        return jdbcTemplate.query(GET_GROUPS_BY_EXTERNAL_GROUP_MAPPING_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, externalGroup);
            }
        }, rowMapper);
    }

    private ScimGroupExternalMemberInterface getExternalGroupMap(final String groupId, final String externalGroup)
                    throws ScimResourceNotFoundException {
        try {
            ScimGroupExternalMemberInterface u = jdbcTemplate.queryForObject(GET_GROUPS_WITH_EXTERNAL_GROUP_MAPPINGS_SQL,
                            rowMapper, groupId, externalGroup);
            return u;
        } catch (EmptyResultDataAccessException e) {
            throw new MemberNotFoundException("The mapping between groupId " + groupId + " and external group "
                            + externalGroup + " does not exist");
        }
    }

    private static final class ScimGroupExternalMemberRowMapper implements RowMapper<ScimGroupExternalMemberInterface> {
        @Override
        public ScimGroupExternalMemberInterface mapRow(ResultSet rs, int rowNum) throws SQLException {
            String groupId = rs.getString(1);
            String externalGroup = rs.getString(2);

            return new ScimGroupExternalMember(groupId, externalGroup);
        }
    }

    public void setScimGroupProvisioning(ScimGroupProvisioning scimGroupProvisioning) {
        this.scimGroupProvisioning = scimGroupProvisioning;
    }

    @Override
    protected String getBaseSqlQuery() {
        return GET_EXTERNAL_GROUP_MAP_SQL;
    }

}
