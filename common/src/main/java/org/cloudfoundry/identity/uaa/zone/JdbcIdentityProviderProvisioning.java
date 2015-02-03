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
package org.cloudfoundry.identity.uaa.zone;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JdbcIdentityProviderProvisioning implements IdentityProviderProvisioning {

    public static final String ID_PROVIDER_FIELDS = "id,version,created,lastModified,name,origin_key,type,config,identity_zone_id";

    public static final String CREATE_IDENTITY_PROVIDER_SQL = "insert into identity_provider(" + ID_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?,?,?)";
    
    public static final String ID_PROVIDER_UPDATE_FIELDS = "version,lastModified,name,type,config".replace(",","=?,")+"=?";

    public static final String IDENTITY_PROVIDERS_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider where identity_zone_id=?";
    
    public static final String UPDATE_IDENTITY_PROVIDER_SQL = "update identity_provider set " + ID_PROVIDER_UPDATE_FIELDS + " where id=?";

    public static final String IDENTITY_PROVIDER_BY_ID_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where id=?";
    
    public static final String IDENTITY_PROVIDER_BY_ORIGIN_QUERY = "select " + ID_PROVIDER_FIELDS + " from identity_provider " + "where origin_key=? and identity_zone_id=? ";

    protected final JdbcTemplate jdbcTemplate;

    private final RowMapper<IdentityProvider> mapper = new IdentityProviderRowMapper();

    public JdbcIdentityProviderProvisioning(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public IdentityProvider retrieve(String id) {
        IdentityProvider identityProvider = jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_ID_QUERY, mapper, id);
        return identityProvider;
    }

    @Override
    public List<IdentityProvider> retrieveAll() { return jdbcTemplate.query(IDENTITY_PROVIDERS_QUERY, mapper, IdentityZoneHolder.get().getId()); }

    @Override
    public IdentityProvider retrieveByOrigin(String origin) {
        IdentityProvider identityProvider = jdbcTemplate.queryForObject(IDENTITY_PROVIDER_BY_ORIGIN_QUERY, mapper, origin, IdentityZoneHolder.get().getId());
        return identityProvider;
    }

    @Override
    public IdentityProvider create(final IdentityProvider identityProvider) {
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_IDENTITY_PROVIDER_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, id);
                    ps.setInt(pos++, identityProvider.getVersion());
                    ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                    ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                    ps.setString(pos++, identityProvider.getName());
                    ps.setString(pos++, identityProvider.getOriginKey());
                    ps.setString(pos++, identityProvider.getType());
                    ps.setString(pos++, identityProvider.getConfig());
                    ps.setString(pos++, IdentityZoneHolder.get().getId());
                }
            });
        } catch (DuplicateKeyException e) {
            throw new IdpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }

        return retrieve(id);
    }

    private static final class IdentityProviderRowMapper implements RowMapper<IdentityProvider> {
        @Override
        public IdentityProvider mapRow(ResultSet rs, int rowNum) throws SQLException {
            IdentityProvider identityProvider = new IdentityProvider();
            int pos = 1;
            identityProvider.setId(rs.getString(pos++).trim());
            identityProvider.setVersion(rs.getInt(pos++));
            identityProvider.setCreated(rs.getTimestamp(pos++));
            identityProvider.setLastModified(rs.getTimestamp(pos++));
            identityProvider.setName(rs.getString(pos++));
            identityProvider.setOriginKey(rs.getString(pos++));
            identityProvider.setType(rs.getString(pos++));
            identityProvider.setConfig(rs.getString(pos++));
            return identityProvider;
        }
    }

    @Override
    public IdentityProvider update(final IdentityProvider identityProvider) {

        jdbcTemplate.update(UPDATE_IDENTITY_PROVIDER_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setInt(pos++, identityProvider.getVersion() + 1);
                ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
                ps.setString(pos++, identityProvider.getName());
                ps.setString(pos++, identityProvider.getType());
                ps.setString(pos++, identityProvider.getConfig());
                ps.setString(pos++, identityProvider.getId().trim());
            }
        });
        return retrieve(identityProvider.getId());
    }

}
