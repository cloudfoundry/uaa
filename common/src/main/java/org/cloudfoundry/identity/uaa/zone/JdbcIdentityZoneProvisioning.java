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
import java.util.UUID;

public class JdbcIdentityZoneProvisioning implements IdentityZoneProvisioning {

    public static final String ID_ZONE_FIELDS = "id,version,created,lastModified,name,subdomain,description";

    public static final String CREATE_IDENTITY_ZONE_SQL = "insert into identity_zone(" + ID_ZONE_FIELDS + ") values (?,?,?,?,?,?,?)";

    public static final String IDENTITY_ZONE_BY_ID_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone " + "where id=?";
    
    public static final String IDENTITY_ZONE_BY_SUBDOMAIN_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone " + "where subdomain=?";

    protected final JdbcTemplate jdbcTemplate;

    private final RowMapper<IdentityZone> mapper = new IdentityZoneRowMapper();

    public JdbcIdentityZoneProvisioning(JdbcTemplate jdbcTemplate) {
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public IdentityZone retrieve(String id) {
        IdentityZone identityZone = jdbcTemplate.queryForObject(IDENTITY_ZONE_BY_ID_QUERY, mapper, id);
        return identityZone;
    }

    @Override
    public IdentityZone retrieveBySubdomain(String subdomain) {
        IdentityZone identityZone = jdbcTemplate.queryForObject(IDENTITY_ZONE_BY_SUBDOMAIN_QUERY, mapper, subdomain);
        return identityZone;
    }

    @Override
    public IdentityZone create(final IdentityZone identityZone) {

        try {
            jdbcTemplate.update(CREATE_IDENTITY_ZONE_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, identityZone.getId().trim());
                    ps.setInt(2, identityZone.getVersion());
                    ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                    ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                    ps.setString(5, identityZone.getName());
                    ps.setString(6, identityZone.getSubdomain());
                    ps.setString(7, identityZone.getDescription());
                }
            });
        } catch (DuplicateKeyException e) {
            throw new ZoneAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }

        return retrieve(identityZone.getId());
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

            return identityZone;
        }
    }

}
