package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

@Component("identityZoneProvisioning")
public class JdbcIdentityZoneProvisioning implements IdentityZoneProvisioning, SystemDeletable {

    public static final String ID_ZONE_FIELDS = "id,version,created,lastmodified,name,subdomain,description,config,active";

    public static final String ID_ZONE_UPDATE_FIELDS = "version,lastmodified,name,subdomain,description,config,active".replace(",", "=?,") + "=?";

    public static final String CREATE_IDENTITY_ZONE_SQL = "insert into identity_zone(" + ID_ZONE_FIELDS + ") values (?,?,?,?,?,?,?,?,?)";

    public static final String UPDATE_IDENTITY_ZONE_SQL = "update identity_zone set " + ID_ZONE_UPDATE_FIELDS + " where id=?";

    public static final String DELETE_IDENTITY_ZONE_SQL = "delete from identity_zone where id=?";

    public static final String IDENTITY_ZONES_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone ";

    public static final String IDENTITY_ZONE_BY_ID_QUERY = IDENTITY_ZONES_QUERY + "where id=?";

    public static final String IDENTITY_ZONE_BY_ID_QUERY_ACTIVE = IDENTITY_ZONE_BY_ID_QUERY + " and active = ?";

    public static final String IDENTITY_ZONE_BY_SUBDOMAIN_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone " + "where subdomain=? and active = ?";

    public static final Logger logger = LoggerFactory.getLogger(JdbcIdentityZoneProvisioning.class);

    protected final JdbcTemplate jdbcTemplate;

    private final RowMapper<IdentityZone> mapper = new IdentityZoneRowMapper();

    public JdbcIdentityZoneProvisioning(final JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public IdentityZone retrieve(String id) {
        if (id == null) {
            throw new ZoneDoesNotExistsException("Zone id cannot be null");
        }
        try {
            return jdbcTemplate.queryForObject(IDENTITY_ZONE_BY_ID_QUERY_ACTIVE, mapper, id, true);
        } catch (EmptyResultDataAccessException x) {
            throw new ZoneDoesNotExistsException("Zone[" + id + "] not found.", x);
        }
    }

    @Override
    public IdentityZone retrieveIgnoreActiveFlag(String id) {
        if (id == null) {
            throw new ZoneDoesNotExistsException("Zone id cannot be null");
        }
        try {
            return jdbcTemplate.queryForObject(IDENTITY_ZONE_BY_ID_QUERY, mapper, id);
        } catch (EmptyResultDataAccessException x) {
            throw new ZoneDoesNotExistsException("Zone[" + id + "] not found.", x);
        }
    }

    @Override
    public List<IdentityZone> retrieveAll() {
        return jdbcTemplate.query(IDENTITY_ZONES_QUERY, mapper);
    }

    @Override
    public IdentityZone retrieveBySubdomain(String subdomain) {
        if (subdomain == null) {
            throw new EmptyResultDataAccessException("Subdomain cannot be null", 1);
        }
        return jdbcTemplate.queryForObject(IDENTITY_ZONE_BY_SUBDOMAIN_QUERY, mapper, subdomain.toLowerCase(), true);
    }

    @Override
    public IdentityZone create(final IdentityZone identityZone) {

        try {
            jdbcTemplate.update(CREATE_IDENTITY_ZONE_SQL, ps -> {
                ps.setString(1, identityZone.getId().trim());
                ps.setInt(2, identityZone.getVersion());
                ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                ps.setString(5, identityZone.getName());
                ps.setString(6, identityZone.getSubdomain().toLowerCase());
                ps.setString(7, identityZone.getDescription());
                ps.setString(8, identityZone.getConfig() != null ? JsonUtils.writeValueAsString(identityZone.getConfig()) : null);
                ps.setBoolean(9, identityZone.isActive());
            });
        } catch (DuplicateKeyException e) {
            throw new ZoneAlreadyExistsException(e.getMostSpecificCause().getMessage(), e);
        }

        return retrieveIgnoreActiveFlag(identityZone.getId());
    }

    @Override
    public IdentityZone update(final IdentityZone identityZone) {

        try {
            jdbcTemplate.update(UPDATE_IDENTITY_ZONE_SQL, ps -> {
                ps.setInt(1, identityZone.getVersion() + 1);
                ps.setTimestamp(2, new Timestamp(new Date().getTime()));
                ps.setString(3, identityZone.getName());
                ps.setString(4, identityZone.getSubdomain().toLowerCase());
                ps.setString(5, identityZone.getDescription());
                ps.setString(6, identityZone.getConfig() != null ? JsonUtils.writeValueAsString(identityZone.getConfig()) : null);
                ps.setBoolean(7, identityZone.isActive());
                ps.setString(8, identityZone.getId().trim());
            });
        } catch (DuplicateKeyException e) {
            //duplicate subdomain
            throw new ZoneAlreadyExistsException(e.getMostSpecificCause().getMessage(), e);
        }
        return retrieveIgnoreActiveFlag(identityZone.getId());
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_IDENTITY_ZONE_SQL, zoneId);
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    private static final class IdentityZoneRowMapper implements RowMapper<IdentityZone> {
        @Override
        public IdentityZone mapRow(ResultSet rs, int rowNum) throws SQLException {

            IdentityZone identityZone = new IdentityZone();

            identityZone.setId(rs.getString(1).trim());
            identityZone.setVersion(rs.getInt(2));
            identityZone.setCreated(rs.getTimestamp(3));
            identityZone.setLastModified(rs.getTimestamp(4));
            identityZone.setName(rs.getString(5));
            identityZone.setSubdomain(rs.getString(6));
            identityZone.setDescription(rs.getString(7));
            String config = rs.getString(8);
            if (StringUtils.hasText(config)) {
                try {
                    identityZone.setConfig(JsonUtils.readValue(config, IdentityZoneConfiguration.class));
                } catch (JsonUtils.JsonUtilException e) {
                    logger.error("Invalid zone configuration found for zone id:{}", identityZone.getId(), e);
                    identityZone.setConfig(new IdentityZoneConfiguration());
                }
            }
            identityZone.setActive(rs.getBoolean(9));
            return identityZone;
        }
    }

}
