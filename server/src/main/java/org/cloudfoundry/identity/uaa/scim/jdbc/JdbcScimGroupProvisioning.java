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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationListener;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JdbcScimGroupProvisioning extends AbstractQueryable<ScimGroup>
    implements ScimGroupProvisioning, ApplicationListener<EntityDeletedEvent<?>>, SystemDeletable {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    @Override
    public Log getLogger() {
        return logger;
    }

    public static final String GROUP_FIELDS = "id,displayName,created,lastModified,version,identity_zone_id";

    public static final String GROUP_TABLE = "groups";
    public static final String GROUP_MEMBERSHIP_TABLE = "group_membership";
    public static final String EXTERNAL_GROUP_TABLE = "external_group_mapping";

    public static final String ADD_GROUP_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?,?)", GROUP_TABLE,
                    GROUP_FIELDS);

    public static final String UPDATE_GROUP_SQL = String.format(
                    "update %s set version=?, displayName=?, lastModified=? where id=? and version=?", GROUP_TABLE);

    public static final String GET_GROUP_SQL = String.format("select %s from %s where id=? and identity_zone_id=?", GROUP_FIELDS, GROUP_TABLE);

    public static final String ALL_GROUPS = String.format("select %s from %s", GROUP_FIELDS, GROUP_TABLE);

    public static final String DELETE_GROUP_SQL = String.format("delete from %s where id=? and identity_zone_id=?", GROUP_TABLE);

    public static final String DELETE_GROUP_BY_ZONE = String.format("delete from %s where identity_zone_id=?", GROUP_TABLE);
    public static final String DELETE_GROUP_MEMBERSHIP_BY_ZONE = String.format("delete from %s where group_id in (select id from %s where identity_zone_id = ?)", GROUP_MEMBERSHIP_TABLE, GROUP_TABLE);
    public static final String DELETE_EXTERNAL_GROUP_BY_ZONE = String.format("delete from %s where group_id in (select id from %s where identity_zone_id = ?)", EXTERNAL_GROUP_TABLE, GROUP_TABLE);
    public static final String DELETE_GROUP_MEMBERSHIP_BY_PROVIDER = String.format("delete from %s where group_id in (select id from %s where identity_zone_id = ?) and origin = ?", GROUP_MEMBERSHIP_TABLE, GROUP_TABLE);
    public static final String DELETE_EXTERNAL_GROUP_BY_PROVIDER = String.format("delete from %s where group_id in (select id from %s where identity_zone_id = ?) and origin = ?", EXTERNAL_GROUP_TABLE, GROUP_TABLE);

    private final RowMapper<ScimGroup> rowMapper = new ScimGroupRowMapper();

    public JdbcScimGroupProvisioning(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ScimGroupRowMapper());
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        setQueryConverter(new ScimSearchQueryConverter());
    }

    @Override
    protected String getBaseSqlQuery() {
        return ALL_GROUPS;
    }

    @Override
    public List<ScimGroup> query(String filter, String sortBy, boolean ascending) {
        if (StringUtils.hasText(filter)) {
            filter += " and";
        }
        filter += " identity_zone_id eq \""+IdentityZoneHolder.get().getId()+"\"";
        return super.query(filter, sortBy, ascending);
    }

    @Override
    protected String getTableName() {
        return GROUP_TABLE;
    }


    @Override
    public List<ScimGroup> retrieveAll() {
        return query("id pr", "created", true);
    }

    @Override
    public ScimGroup retrieve(String id) throws ScimResourceNotFoundException {
        try {
            ScimGroup group = jdbcTemplate.queryForObject(GET_GROUP_SQL, rowMapper, id, IdentityZoneHolder.get().getId());
            return group;
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("Group " + id + " does not exist");
        }
    }

    @Override
    public ScimGroup create(final ScimGroup group) throws InvalidScimResourceException {
        final String id = UUID.randomUUID().toString();
        logger.debug("creating new group with id: " + id);
        try {
            validateGroup(group);
            jdbcTemplate.update(ADD_GROUP_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, id);
                    ps.setString(2, group.getDisplayName());
                    ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                    ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                    ps.setInt(5, group.getVersion());
                    ps.setString(6, group.getZoneId());
                }
            });
        } catch (DuplicateKeyException ex) {
            throw new ScimResourceAlreadyExistsException("A group with displayName: " + group.getDisplayName()
                            + " already exists.");
        }
        return retrieve(id);
    }

    @Override
    public ScimGroup update(final String id, final ScimGroup group) throws InvalidScimResourceException,
                    ScimResourceNotFoundException {
        try {
            validateGroup(group);
            int updated = jdbcTemplate.update(UPDATE_GROUP_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setInt(1, group.getVersion() + 1);
                    ps.setString(2, group.getDisplayName());
                    ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                    ps.setString(4, id);
                    ps.setInt(5, group.getVersion());
                }
            });
            if (updated != 1) {
                throw new IncorrectResultSizeDataAccessException(1, updated);
            }
            return retrieve(id);
        } catch (DuplicateKeyException ex) {
            throw new InvalidScimResourceException("A group with displayName: " + group.getDisplayName()
                            + " already exists");
        }
    }

    @Override
    public ScimGroup delete(String id, int version) throws ScimResourceNotFoundException {
        ScimGroup group = retrieve(id);
        int deleted;
        if (version > 0) {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL + " and version=?;", id, IdentityZoneHolder.get().getId(),version);
        } else {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL, id, IdentityZoneHolder.get().getId());
        }
        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException(1, deleted);
        }
        return group;
    }

    public int deleteByIdentityZone(String zoneId) {
        jdbcTemplate.update(DELETE_EXTERNAL_GROUP_BY_ZONE, zoneId);
        jdbcTemplate.update(DELETE_GROUP_MEMBERSHIP_BY_ZONE, zoneId);
        return jdbcTemplate.update(DELETE_GROUP_BY_ZONE, zoneId);
    }

    public int deleteByOrigin(String origin, String zoneId) {
        jdbcTemplate.update(DELETE_EXTERNAL_GROUP_BY_PROVIDER, zoneId, origin);
        return jdbcTemplate.update(DELETE_GROUP_MEMBERSHIP_BY_PROVIDER, zoneId, origin);
    }

    protected void validateGroup(ScimGroup group) throws ScimResourceConstraintFailedException {
        if (!StringUtils.hasText(group.getZoneId())) {
            throw new ScimResourceConstraintFailedException("zoneId is a required field");
        }
    }

    private static final class ScimGroupRowMapper implements RowMapper<ScimGroup> {

        @Override
        public ScimGroup mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString(1);
            String name = rs.getString(2);
            Date created = rs.getTimestamp(3);
            Date modified = rs.getTimestamp(4);
            int version = rs.getInt(5);
            String zoneId = rs.getString(6);
            ScimGroup group = new ScimGroup(id, name, zoneId);
            ScimMeta meta = new ScimMeta(created, modified, version);
            group.setMeta(meta);
            return group;
        }
    }
}
