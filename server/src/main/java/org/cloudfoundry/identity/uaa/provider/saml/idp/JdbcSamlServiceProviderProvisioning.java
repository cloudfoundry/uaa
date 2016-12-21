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
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.jdbc.BooleanValueAdapter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
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

/**
 * Rest-template-based data access for SAML Service Provider CRUD operations.
 */
public class JdbcSamlServiceProviderProvisioning implements SamlServiceProviderProvisioning, SamlServiceProviderDeletable {

    private static final Log LOGGER = LogFactory.getLog(JdbcIdentityProviderProvisioning.class);

    public static final String SERVICE_PROVIDER_FIELDS = "id,version,created,lastmodified,name,entity_id,config,identity_zone_id,active";

    public static final String CREATE_SERVICE_PROVIDER_SQL = "insert into service_provider(" + SERVICE_PROVIDER_FIELDS
            + ") values (?,?,?,?,?,?,?,?,?)";

    public static final String DELETE_SERVICE_PROVIDER_SQL = "delete from service_provider where id=? and identity_zone_id=?";

    public static final String DELETE_SERVICE_PROVIDER_BY_ENTITY_ID_SQL = "delete from service_provider where entity_id = ? and identity_zone_id=?";

    public static final String DELETE_SERVICE_PROVIDER_BY_ZONE_SQL = "delete from service_provider where identity_zone_id=?";

    public static final String SERVICE_PROVIDERS_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider where identity_zone_id=?";
 
    public static final String ACTIVE_SERVICE_PROVIDERS_QUERY = SERVICE_PROVIDERS_QUERY + " and active=%s";

    public static final String SERVICE_PROVIDER_UPDATE_FIELDS = "version,lastmodified,name,config,active".replace(",",
            "=?,") + "=?";

    public static final String UPDATE_SERVICE_PROVIDER_SQL = "update service_provider set "
            + SERVICE_PROVIDER_UPDATE_FIELDS + " where id=? and identity_zone_id=?";

    public static final String SERVICE_PROVIDER_BY_ID_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider " + "where id=? and identity_zone_id=?";

    public static final String SERVICE_PROVIDER_BY_ENTITY_ID_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider " + "where entity_id=? and identity_zone_id=? ";

    protected final JdbcTemplate jdbcTemplate;

    private final BooleanValueAdapter booleanValueAdapter;

    private final RowMapper<SamlServiceProvider> mapper = new SamlServiceProviderRowMapper();

    public JdbcSamlServiceProviderProvisioning(JdbcTemplate jdbcTemplate, BooleanValueAdapter booleanValueAdapter) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        this.booleanValueAdapter = booleanValueAdapter;
    }

    @Override
    public SamlServiceProvider retrieve(String id) {
        SamlServiceProvider serviceProvider = jdbcTemplate.queryForObject(SERVICE_PROVIDER_BY_ID_QUERY, mapper, id,
                IdentityZoneHolder.get().getId());
        return serviceProvider;
    }

    @Override
    public void delete(String id) {
        jdbcTemplate.update(DELETE_SERVICE_PROVIDER_SQL, id, IdentityZoneHolder.get().getId());
    }

    @Override
    public int deleteByEntityId(String entityId, String zoneId) {
        return jdbcTemplate.update(DELETE_SERVICE_PROVIDER_BY_ENTITY_ID_SQL, entityId, zoneId);
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_SERVICE_PROVIDER_BY_ZONE_SQL, zoneId);
    }

    @Override
    public List<SamlServiceProvider> retrieveActive(String zoneId) {
        String activeQuery = String.format(ACTIVE_SERVICE_PROVIDERS_QUERY, this.booleanValueAdapter.getTrueValue());
        return jdbcTemplate.query(activeQuery, mapper, zoneId);
    }

    @Override
    public List<SamlServiceProvider> retrieveAll(boolean activeOnly, String zoneId) {
        if (activeOnly) {
            return retrieveActive(zoneId);
        } else {
            return jdbcTemplate.query(SERVICE_PROVIDERS_QUERY, mapper, zoneId);
        }
    }

    @Override
    public SamlServiceProvider retrieveByEntityId(String entityId, String zoneId) {
        SamlServiceProvider serviceProvider = jdbcTemplate.queryForObject(SERVICE_PROVIDER_BY_ENTITY_ID_QUERY, mapper,
                entityId, zoneId);
        return serviceProvider;
    }

    @Override
    public SamlServiceProvider create(final SamlServiceProvider serviceProvider) {
        validate(serviceProvider);
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_SERVICE_PROVIDER_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    int pos = 1;
                    ps.setString(pos++, id);
                    ps.setInt(pos++, serviceProvider.getVersion());
                    ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                    ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                    ps.setString(pos++, serviceProvider.getName());
                    ps.setString(pos++, serviceProvider.getEntityId());
                    ps.setString(pos++, JsonUtils.writeValueAsString(serviceProvider.getConfig()));
                    ps.setString(pos++, serviceProvider.getIdentityZoneId());
                    ps.setBoolean(pos++, serviceProvider.isActive());
                }
            });
        } catch (DuplicateKeyException e) {
            throw new SamlSpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return retrieve(id);
    }

    @Override
    public SamlServiceProvider update(final SamlServiceProvider serviceProvider) {
        validate(serviceProvider);
        final String zoneId = IdentityZoneHolder.get().getId();
        jdbcTemplate.update(UPDATE_SERVICE_PROVIDER_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                ps.setInt(pos++, serviceProvider.getVersion() + 1);
                ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
                ps.setString(pos++, serviceProvider.getName());
                ps.setString(pos++, JsonUtils.writeValueAsString(serviceProvider.getConfig()));
                ps.setBoolean(pos++, serviceProvider.isActive());
                ps.setString(pos++, serviceProvider.getId().trim());
                ps.setString(pos++, zoneId);
            }
        });
        return retrieve(serviceProvider.getId());
    }

    protected void validate(SamlServiceProvider provider) {
        if (provider == null) {
            throw new NullPointerException("SAML Service Provider can not be null.");
        }
        if (!StringUtils.hasText(provider.getIdentityZoneId())) {
            throw new DataIntegrityViolationException("Identity zone ID must be set.");
        }
    }

    private static final class SamlServiceProviderRowMapper implements RowMapper<SamlServiceProvider> {
        public SamlServiceProviderRowMapper() {
            // Default constructor.
        }

        @Override
        public SamlServiceProvider mapRow(ResultSet rs, int rowNum) throws SQLException {
            SamlServiceProvider samlServiceProvider = new SamlServiceProvider();
            int pos = 1;
            samlServiceProvider.setId(rs.getString(pos++).trim());
            samlServiceProvider.setVersion(rs.getInt(pos++));
            samlServiceProvider.setCreated(rs.getTimestamp(pos++));
            samlServiceProvider.setLastModified(rs.getTimestamp(pos++));
            samlServiceProvider.setName(rs.getString(pos++));
            samlServiceProvider.setEntityId(rs.getString(pos++));
            String config = rs.getString(pos++);
            SamlServiceProviderDefinition definition = JsonUtils.readValue(config, SamlServiceProviderDefinition.class);
            samlServiceProvider.setConfig(definition);
            samlServiceProvider.setIdentityZoneId(rs.getString(pos++));
            samlServiceProvider.setActive(rs.getBoolean(pos++));
            return samlServiceProvider;
        }
    }

    @Override
    public Log getLogger() {

        return LOGGER;
    }

}
