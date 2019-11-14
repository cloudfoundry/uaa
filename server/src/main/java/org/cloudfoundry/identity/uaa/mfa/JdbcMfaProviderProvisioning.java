package org.cloudfoundry.identity.uaa.mfa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaAlreadyExistsException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

public class JdbcMfaProviderProvisioning implements MfaProviderProvisioning, SystemDeletable {

    private static Logger logger = LoggerFactory.getLogger(JdbcMfaProviderProvisioning.class);
    public static final String TABLE_NAME = "mfa_providers";
    public static final String MFA_PROVIDER_FIELDS = "id,name,type,config,identity_zone_id,created,lastmodified";
    public static final String CREATE_PROVIDER_SQL = "insert into " + TABLE_NAME + "(" + MFA_PROVIDER_FIELDS + ") values (?,?,?,?,?,?,?)";

    public static final String MFA_PROVIDER_UPDATE_FIELDS = "name,type,config,identity_zone_id,lastmodified".replace(",","=?,")+"=?";

    public static final String UPDATE_PROVIDER_SQL = "update " + TABLE_NAME + " set " + MFA_PROVIDER_UPDATE_FIELDS + " where id=? and identity_zone_id=?";


    public static final String MFA_PROVIDER_BY_ID_QUERY = "select " + MFA_PROVIDER_FIELDS + " from " + TABLE_NAME + " where id=? and identity_zone_id=?";
    public static final String MFA_PROVIDER_BY_NAME_QUERY = "select " + MFA_PROVIDER_FIELDS + " from " + TABLE_NAME + " where name=? and identity_zone_id=?";
    public static final String MFA_PROVIDERS_QUERY = "select " + MFA_PROVIDER_FIELDS + " from " + TABLE_NAME + " where identity_zone_id=?";
    public static final String MFA_PROVIDER_DELETE_BY_ID = "delete from " + TABLE_NAME + " where id =? and identity_zone_id=?";
    public static final String MFA_PROVIDER_DELETE_BY_ZONE_ID = "delete from " + TABLE_NAME + " where identity_zone_id=?";

    protected final JdbcTemplate jdbcTemplate;
    private MfaProviderValidator mfaProviderValidator;
    private MfaProviderMapper mapper = new MfaProviderMapper();

    public JdbcMfaProviderProvisioning(JdbcTemplate jdbcTemplate, MfaProviderValidator mfaProviderValidator) {
        this.jdbcTemplate = jdbcTemplate;
        this.mfaProviderValidator = mfaProviderValidator;
    }

    @Override
    public MfaProvider create(MfaProvider provider, String zoneId) {
        mfaProviderValidator.validate(provider);
        final String id = UUID.randomUUID().toString();
        try {
            jdbcTemplate.update(CREATE_PROVIDER_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, id);
                ps.setString(pos++, provider.getName());
                ps.setString(pos++, provider.getType().toValue());
                ps.setString(pos++, JsonUtils.writeValueAsString(provider.getConfig()));
                ps.setString(pos++, zoneId);
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));
            });
        } catch (DuplicateKeyException e) {
            String message = e.getMostSpecificCause().getMessage();
            if (message.toUpperCase().contains("IDX_MFA_UNIQUE_NAME")) {
                message = "An MFA Provider with that name already exists.";
            }
            throw new MfaAlreadyExistsException(message);
        }
        return retrieve(id, zoneId);
    }

    @Override
    public MfaProvider update(MfaProvider provider, String zoneId) {
        try {
            jdbcTemplate.update(UPDATE_PROVIDER_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, provider.getName());
                ps.setString(pos++, provider.getType().toValue());
                ps.setString(pos++, JsonUtils.writeValueAsString(provider.getConfig()));
                ps.setString(pos++, zoneId);
                ps.setTimestamp(pos++, new Timestamp(System.currentTimeMillis()));

                ps.setString(pos++, provider.getId().trim());
                ps.setString(pos++, zoneId);

            });
        } catch (DuplicateKeyException e) {
            String message = e.getMostSpecificCause().getMessage();
            if (message.toUpperCase().contains("IDX_MFA_UNIQUE_NAME")) {
                message = "An MFA Provider with that name already exists.";
            }
            throw new MfaAlreadyExistsException(message);
        }

        return retrieve(provider.getId(), zoneId);
    }

    @Override
    public MfaProvider retrieve(String id, String zoneId) {
        return jdbcTemplate.queryForObject(MFA_PROVIDER_BY_ID_QUERY, mapper, id, zoneId);
    }

    @Override
    public MfaProvider retrieveByName(String name, String zoneId) {
        return jdbcTemplate.queryForObject(MFA_PROVIDER_BY_NAME_QUERY, mapper, name, zoneId);
    }

    @Override
    public List<MfaProvider> retrieveAll(String zoneId) {
        return jdbcTemplate.query(MFA_PROVIDERS_QUERY, mapper, zoneId);
    }

    @Override
    public int deleteByMfaProvider(String providerId, String zoneId) {
        return jdbcTemplate.update(MFA_PROVIDER_DELETE_BY_ID, providerId, zoneId);
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(MFA_PROVIDER_DELETE_BY_ZONE_ID, zoneId);
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    private static final class MfaProviderMapper implements RowMapper<MfaProvider> {
        @Override
        public MfaProvider mapRow(ResultSet rs, int rowNum) throws SQLException {
            MfaProvider result =  new MfaProvider();
            int pos = 1;

            result.setId(rs.getString(pos++).trim());
            result.setName(rs.getString(pos++));
            result.setType(MfaProvider.MfaProviderType.forValue(rs.getString(pos++)));
            //deserialize based on type
            String config = rs.getString(pos++);
            AbstractMfaProviderConfig definition = null;
            if (result.getType() == MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR) {
                definition = StringUtils.hasText(config) ? JsonUtils.readValue(config, GoogleMfaProviderConfig.class) : new GoogleMfaProviderConfig();
            }
            result.setConfig(definition);
            result.setIdentityZoneId(rs.getString(pos++));
            result.setCreated(rs.getTimestamp(pos++));
            result.setLastModified(rs.getTimestamp(pos++));

            return result;
        }
    }
}
