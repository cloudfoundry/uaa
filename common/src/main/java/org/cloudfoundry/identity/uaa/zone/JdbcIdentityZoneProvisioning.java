package org.cloudfoundry.identity.uaa.zone;

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

    public static final String ID_ZONE_FIELDS = "id,version,created,lastModified,name,subdomain,service_instance_id";

    public static final String CREATE_IDENTITY_ZONE_SQL = "insert into identity_zone(" + ID_ZONE_FIELDS + ") values (?,?,?,?,?,?,?)";

    public static final String IDENTITY_ZONE_BY_ID_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone " + "where id=?";

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
    public IdentityZone createZone(final IdentityZone identityZone) {
        final String id = UUID.randomUUID().toString();
        jdbcTemplate.update(CREATE_IDENTITY_ZONE_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, id);
                ps.setInt(2, identityZone.getVersion());
                ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                ps.setString(5, identityZone.getName());
                ps.setString(6, identityZone.getSubDomain());
                ps.setString(7, identityZone.getServiceInstanceId());
            }
        });
        return retrieve(id);
    }

    private static final class IdentityZoneRowMapper implements RowMapper<IdentityZone> {
        @Override
        public IdentityZone mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString(1);
            int version = rs.getInt(2);
            Date created = rs.getTimestamp(3);
            Date lastModified = rs.getTimestamp(4);
            String name = rs.getString(5);
            String subDomain = rs.getString(6);
            String serviceInstanceId = rs.getString(7);

            IdentityZone identityZone = new IdentityZone();
            identityZone.setId(id);
            identityZone.setVersion(version);
            identityZone.setCreated(created);
            identityZone.setLastModified(lastModified);
            identityZone.setName(name);
            identityZone.setSubDomain(subDomain);
            identityZone.setServiceInstanceId(serviceInstanceId);

            return identityZone;
        }
    }
}
