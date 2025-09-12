package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.KeyProviderAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.KeyProviderNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

@Component("keyProviderProvisioning")
public class JdbcKeyProviderProvisioning implements KeyProviderProvisioning, SystemDeletable {
    private static final Logger logger = LoggerFactory.getLogger(JdbcKeyProviderProvisioning.class);

    public static final String INSERT_KEY_PROVIDER_CONFIG = "insert into key_provider_config(id, identity_zone_id, client_id, dcs_tenant_id) values (?,?,?,?)";
    public static final String SELECT_KEY_PROVIDER_CONFIG_BY_ZONE = "select * from key_provider_config where identity_zone_id = ?";
    public static final String SELECT_KEY_PROVIDER_CONFIG_BY_ZONE_AND_ID = "select * from key_provider_config where id = ? and identity_zone_id = ?";
    public static final String DELETE_KEY_PROVIDER_CONFIG_BY_ZONE_AND_ID = "delete from key_provider_config where id = ? and identity_zone_id = ?";
    public static final String DELETE_KEY_PROVIDER_CONFIG_BY_ZONE = "delete from key_provider_config where identity_zone_id = ?";

    protected final JdbcTemplate jdbcTemplate;

    public static final RowMapper<KeyProviderConfig> mapper = new KeyProviderRowMapper();

    public JdbcKeyProviderProvisioning(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public KeyProviderConfig retrieve(String keyProviderId) {
        KeyProviderConfig keyProviderConfig;

        try{
            logger.debug("Retrieving key provider " + keyProviderId + " for zone: " + IdentityZoneHolder.get().getId());
            keyProviderConfig = jdbcTemplate.queryForObject(SELECT_KEY_PROVIDER_CONFIG_BY_ZONE_AND_ID, mapper, keyProviderId, IdentityZoneHolder.get().getId());
        } catch(EmptyResultDataAccessException e) {
            throw new KeyProviderNotFoundException("Key provider does not exist with id: " + keyProviderId);
        }
        return keyProviderConfig;
    }

    @Override
    public KeyProviderConfig findActive() {
        KeyProviderConfig keyProviderConfig;
        try{
            logger.debug("Retrieving key provider for zone: " + IdentityZoneHolder.get().getId());
            keyProviderConfig = jdbcTemplate.queryForObject(SELECT_KEY_PROVIDER_CONFIG_BY_ZONE, mapper, IdentityZoneHolder.get().getId());
        } catch(EmptyResultDataAccessException e) {
            return null;
        }
        return keyProviderConfig;
    }

    @Override
    public KeyProviderConfig create(KeyProviderConfig config) {
        String id = UUID.randomUUID().toString();
        if( findActive() != null ) {
         throw new KeyProviderAlreadyExistsException("Key provider already exists for this zone.");
        }
        logger.debug("Creating key provider for zone: " + IdentityZoneHolder.get().getId());
        jdbcTemplate.update(INSERT_KEY_PROVIDER_CONFIG, id,  IdentityZoneHolder.get().getId(), config.getClientId(), config.getDcsTenantId());
        return retrieve(id);
    }

    @Override
    public int delete(String keyProviderId) {
        logger.debug("Deleting key provider " + keyProviderId + " for zone: " + IdentityZoneHolder.get().getId());
        return jdbcTemplate.update(DELETE_KEY_PROVIDER_CONFIG_BY_ZONE_AND_ID, keyProviderId, IdentityZoneHolder.get().getId());
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_KEY_PROVIDER_CONFIG_BY_ZONE, zoneId);
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        return 0;
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return 0;
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    private static final class KeyProviderRowMapper implements RowMapper<KeyProviderConfig> {

        @Override
        public KeyProviderConfig mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString("id");
            String identityZoneId = rs.getString("identity_zone_id");
            String clientId = rs.getString("client_id");
            String dcsTenantId = rs.getString("dcs_tenant_id");
            return new KeyProviderConfig(id, identityZoneId, clientId, dcsTenantId);
        }
    }
}
