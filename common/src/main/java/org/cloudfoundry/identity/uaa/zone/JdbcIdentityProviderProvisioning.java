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

public class JdbcIdentityProviderProvisioning implements IdentityProviderProvisioning {

    public static final String ID_PROVIDER_FIELDS = "id,version,created,lastModified,name,origin_key,type,config,identity_zone_id";

    public static final String CREATE_IDENTITY_PROVIDER_SQL = "insert into identity_provider(" + ID_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?,?,?)";

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
                    ps.setString(1, id);
                    ps.setInt(2, identityProvider.getVersion());
                    ps.setTimestamp(3, new Timestamp(new Date().getTime()));
                    ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                    ps.setString(5, identityProvider.getName());
                    ps.setString(6, identityProvider.getOriginKey());
                    ps.setString(7, identityProvider.getType());
                    ps.setString(8, identityProvider.getConfig());
                    ps.setString(9, IdentityZoneHolder.get().getId());
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
            identityProvider.setId(rs.getString(1).trim());
            identityProvider.setVersion(rs.getInt(2));
            identityProvider.setCreated(rs.getTimestamp(3));
            identityProvider.setLastModified(rs.getTimestamp(4));
            identityProvider.setName(rs.getString(5));
            identityProvider.setOriginKey(rs.getString(6));
            identityProvider.setType(rs.getString(7));
            identityProvider.setConfig(rs.getString(8));
            return identityProvider;
        }
    }

}
