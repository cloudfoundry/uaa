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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

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

    private static final Logger LOGGER = LoggerFactory.getLogger(JdbcIdentityProviderProvisioning.class);

    public static final String SERVICE_PROVIDER_FIELDS = "id,version,created,lastmodified,name,entity_id,config,identity_zone_id,active";

    public static final String CREATE_SERVICE_PROVIDER_SQL = "insert into service_provider(" + SERVICE_PROVIDER_FIELDS
            + ") values (?,?,?,?,?,?,?,?,?)";

    public static final String DELETE_SERVICE_PROVIDER_SQL = "delete from service_provider where id=? and identity_zone_id=?";

    public static final String DELETE_SERVICE_PROVIDER_BY_ENTITY_ID_SQL = "delete from service_provider where entity_id = ? and identity_zone_id=?";

    public static final String DELETE_SERVICE_PROVIDER_BY_ZONE_SQL = "delete from service_provider where identity_zone_id=?";

    public static final String SERVICE_PROVIDERS_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider where identity_zone_id=?";

    public static final String ACTIVE_SERVICE_PROVIDERS_QUERY = SERVICE_PROVIDERS_QUERY + " and active=?";

    public static final String SERVICE_PROVIDER_UPDATE_FIELDS = "version,lastmodified,name,config,active".replace(",",
            "=?,") + "=?";

    public static final String UPDATE_SERVICE_PROVIDER_SQL = "update service_provider set "
            + SERVICE_PROVIDER_UPDATE_FIELDS + " where id=? and identity_zone_id=?";

    public static final String SERVICE_PROVIDER_BY_ID_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider " + "where id=? and identity_zone_id=?";

    public static final String SERVICE_PROVIDER_BY_ENTITY_ID_QUERY = "select " + SERVICE_PROVIDER_FIELDS
            + " from service_provider " + "where entity_id=? and identity_zone_id=? ";

    protected final JdbcTemplate jdbcTemplate;


    private final RowMapper<SamlServiceProvider> mapper = new SamlServiceProviderRowMapper();

    public JdbcSamlServiceProviderProvisioning(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public SamlServiceProvider retrieve(String id, String zoneId) {
        return jdbcTemplate.queryForObject(SERVICE_PROVIDER_BY_ID_QUERY, mapper, id, zoneId);
    }

    @Override
    public void delete(String id, String zoneId) {
        jdbcTemplate.update(DELETE_SERVICE_PROVIDER_SQL, id, zoneId);
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
        return jdbcTemplate.query(ACTIVE_SERVICE_PROVIDERS_QUERY, mapper, zoneId, true);
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
        return jdbcTemplate.queryForObject(SERVICE_PROVIDER_BY_ENTITY_ID_QUERY, mapper,
                entityId, zoneId);
    }

    @Override
    public SamlServiceProvider create(final SamlServiceProvider serviceProvider, final String zoneId) {
        validate(serviceProvider);
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_SERVICE_PROVIDER_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, id);
                ps.setInt(pos++, serviceProvider.getVersion());
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                ps.setString(pos++, serviceProvider.getName());
                ps.setString(pos++, serviceProvider.getEntityId());
                ps.setString(pos++, JsonUtils.writeValueAsString(serviceProvider.getConfig()));
                ps.setString(pos++, zoneId);
                ps.setBoolean(pos++, serviceProvider.isActive());
            });
        } catch (DuplicateKeyException e) {
            throw new SamlSpAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
        return retrieve(id, zoneId);
    }

    @Override
    public SamlServiceProvider update(final SamlServiceProvider serviceProvider, String zoneId) {
        validate(serviceProvider);
        jdbcTemplate.update(UPDATE_SERVICE_PROVIDER_SQL, ps -> {
            int pos = 1;
            ps.setInt(pos++, serviceProvider.getVersion() + 1);
            ps.setTimestamp(pos++, new Timestamp(new Date().getTime()));
            ps.setString(pos++, serviceProvider.getName());
            ps.setString(pos++, JsonUtils.writeValueAsString(serviceProvider.getConfig()));
            ps.setBoolean(pos++, serviceProvider.isActive());
            ps.setString(pos++, serviceProvider.getId().trim());
            ps.setString(pos++, zoneId);
        });
        return retrieve(serviceProvider.getId(), zoneId);
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
    public Logger getLogger() {

        return LOGGER;
    }

}
