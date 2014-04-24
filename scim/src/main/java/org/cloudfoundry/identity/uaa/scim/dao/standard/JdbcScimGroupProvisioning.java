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
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

public class JdbcScimGroupProvisioning extends AbstractQueryable<ScimGroupInterface> implements ScimGroupProvisioning {

    private JdbcTemplate jdbcTemplate;

    private final Log logger = LogFactory.getLog(getClass());

    public static final String GROUP_FIELDS = "id,displayName,created,lastModified,version";

    public static final String GROUP_TABLE = "groups";

    public static final String ADD_GROUP_SQL = String.format("insert into %s ( %s ) values (?,?,?,?,?)", GROUP_TABLE,
                    GROUP_FIELDS);

    public static final String UPDATE_GROUP_SQL = String.format(
                    "update %s set version=?, displayName=?, lastModified=? where id=? and version=?", GROUP_TABLE);

    public static final String GET_GROUPS_SQL = String.format("select %s from %s", GROUP_FIELDS, GROUP_TABLE);

    public static final String GET_GROUP_SQl = String.format("select %s from %s where id=?", GROUP_FIELDS, GROUP_TABLE);

    public static final String DELETE_GROUP_SQL = String.format("delete from %s where id=?", GROUP_TABLE);

    private final RowMapper<ScimGroupInterface> rowMapper = new ScimGroupRowMapper();

    public JdbcScimGroupProvisioning(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, new ScimGroupRowMapper());
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        setQueryConverter(new ScimSearchQueryConverter());
    }

    @Override
    protected String getBaseSqlQuery() {
        return GET_GROUPS_SQL;
    }

    @Override
    public List<ScimGroupInterface> retrieveAll() {
        return query("id pr", "created", true);
    }

    @Override
    public ScimGroupInterface retrieve(String id) throws ScimResourceNotFoundException {
        try {
            ScimGroupInterface group = jdbcTemplate.queryForObject(GET_GROUP_SQl, rowMapper, id);
            return group;
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("Group " + id + " does not exist");
        }
    }

    @Override
    public ScimGroupInterface create(final ScimGroupInterface group) throws InvalidScimResourceException {
        final String id = UUID.randomUUID().toString();
        logger.debug("creating new group with id: " + id);
        try {
            jdbcTemplate.update(ADD_GROUP_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, id);
                    ps.setString(2, group.getDisplayName());
                    ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                    ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                    ps.setInt(5, group.getVersion());
                }
            });
        } catch (DuplicateKeyException ex) {
            throw new ScimResourceAlreadyExistsException("A group with displayName: " + group.getDisplayName()
                            + " already exists.");
        }
        return retrieve(id);
    }

    @Override
    public ScimGroupInterface update(final String id, final ScimGroupInterface group) throws InvalidScimResourceException,
                    ScimResourceNotFoundException {
        try {
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
    public ScimGroupInterface delete(String id, int version) throws ScimResourceNotFoundException {
        ScimGroupInterface group = retrieve(id);
        int deleted;
        if (version > 0) {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL + " and version=?;", id, version);
        } else {
            deleted = jdbcTemplate.update(DELETE_GROUP_SQL, id);
        }
        if (deleted != 1) {
            throw new IncorrectResultSizeDataAccessException(1, deleted);
        }
        return group;
    }

    private static final class ScimGroupRowMapper implements RowMapper<ScimGroupInterface> {

        @Override
        public ScimGroupInterface mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString(1);
            String name = rs.getString(2);
            Date created = rs.getTimestamp(3);
            Date modified = rs.getTimestamp(4);
            int version = rs.getInt(5);

            ScimGroupInterface group = new ScimGroup(id, name);
            ScimMeta meta = new ScimMeta(created, modified, version);
            group.setMeta(meta);
            return group;
        }
    }
}
