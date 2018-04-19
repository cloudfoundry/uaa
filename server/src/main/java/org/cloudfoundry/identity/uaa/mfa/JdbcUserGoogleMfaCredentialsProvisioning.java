package org.cloudfoundry.identity.uaa.mfa;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.cypto.EncryptionService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionServiceException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToPersistMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToRetrieveMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Base64Utils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;
import static java.lang.String.valueOf;

public class JdbcUserGoogleMfaCredentialsProvisioning implements SystemDeletable, UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> {

    private static Logger logger = LoggerFactory.getLogger(JdbcUserGoogleMfaCredentialsProvisioning.class);

    public static final String TABLE_NAME = "user_google_mfa_credentials";

    private static final String CREATE_USER_MFA_CONFIG_SQL =
      "INSERT INTO " + TABLE_NAME + "(user_id, secret_key, encrypted_validation_code, scratch_codes, mfa_provider_id, zone_id) VALUES (?,?,?,?,?,?)";

    private static final String UPDATE_USER_MFA_CONFIG_SQL =
      "UPDATE " + TABLE_NAME + " SET secret_key=?, encrypted_validation_code=?, scratch_codes=?, mfa_provider_id=?, zone_id=? WHERE user_id=?";

    private static final String QUERY_USER_MFA_CONFIG_ALL_SQL = "SELECT * FROM " + TABLE_NAME + " WHERE user_id=? AND mfa_provider_id=?";

    private static final String DELETE_USER_MFA_CONFIG_SQL = "DELETE FROM " + TABLE_NAME + " WHERE user_id=?";

    private static final String DELETE_PROVIDER_MFA_CONFIG_SQL = "DELETE FROM " + TABLE_NAME + " WHERE mfa_provider_id=?";

    private static final String DELETE_ZONE_MFA_CONFIG_SQL = "DELETE FROM " + TABLE_NAME + " WHERE zone_id=?";


    private JdbcTemplate jdbcTemplate;
    private EncryptionService encryptionService;
    private UserMfaCredentialsMapper mapper;

    public JdbcUserGoogleMfaCredentialsProvisioning(JdbcTemplate jdbcTemplate, EncryptionService encryptionService) {
        this.jdbcTemplate = jdbcTemplate;
        this.encryptionService = encryptionService;
        this.mapper = new UserMfaCredentialsMapper(encryptionService);
    }

    private String encrypt(String value) throws EncryptionServiceException {
        return Base64Utils.encodeToString(encryptionService.encrypt(value));
    }

    @Override
    public void save(UserGoogleMfaCredentials credentials, String zoneId) {
        try {
            jdbcTemplate.update(CREATE_USER_MFA_CONFIG_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, credentials.getUserId());
                try {
                    ps.setString(pos++, encrypt(credentials.getSecretKey()));
                    ps.setString(pos++, encrypt(String.valueOf(credentials.getValidationCode())));
                    ps.setString(pos++, encrypt(toCSScratchCode(credentials.getScratchCodes())));
                } catch (EncryptionServiceException e) {
                    logger.error("Unable to encrypt MFA credentials", e);
                    throw new UnableToPersistMfaException(e);
                }

                ps.setString(pos++, credentials.getMfaProviderId());
                ps.setString(pos++, zoneId);
            });
        } catch (DuplicateKeyException e) {
            throw new UserMfaConfigAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
    }

    @Override
    public void update(UserGoogleMfaCredentials credentials, String zoneId) {
        jdbcTemplate.update(UPDATE_USER_MFA_CONFIG_SQL, ps -> {
            int pos = 1;
            try {
                ps.setString(pos++, encrypt(credentials.getSecretKey()));
                ps.setString(pos++, encrypt(String.valueOf(credentials.getValidationCode())));
                ps.setString(pos++, encrypt(toCSScratchCode(credentials.getScratchCodes())));
            } catch (EncryptionServiceException e) {
                logger.error("Unable to encrypt MFA credentials", e);
                throw new UnableToPersistMfaException(e);
            }
            ps.setString(pos++, credentials.getMfaProviderId());
            ps.setString(pos++, zoneId);
            ps.setString(pos++, credentials.getUserId());
        });
        retrieve(credentials.getUserId(), credentials.getMfaProviderId());
    }

    @Override
    public UserGoogleMfaCredentials retrieve(String userId, String mfaProviderId) {
        try {
            return jdbcTemplate.queryForObject(QUERY_USER_MFA_CONFIG_ALL_SQL, mapper, userId, mfaProviderId);
        } catch (EmptyResultDataAccessException e) {
            throw new UserMfaConfigDoesNotExistException("No Creds for user " + userId);
        }
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return delete(userId);
    }

    @Override
    public int deleteByMfaProvider(String mfaProviderId, String zoneId) {
        return jdbcTemplate.update(DELETE_PROVIDER_MFA_CONFIG_SQL, mfaProviderId);
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return jdbcTemplate.update(DELETE_ZONE_MFA_CONFIG_SQL, zoneId);
    }

    @Override
    public int delete(String userId) {
        return jdbcTemplate.update(DELETE_USER_MFA_CONFIG_SQL, userId);
    }


    @Override
    public Log getLogger() {
        return LogFactory.getLog(JdbcUserGoogleMfaCredentialsProvisioning.class);
    }

    private String toCSScratchCode(List<Integer> scratchCodes) {
        return StringUtils.join(scratchCodes, ",");
    }

    private static final class UserMfaCredentialsMapper implements RowMapper<UserGoogleMfaCredentials> {
        private EncryptionService encryptionService;

        public UserMfaCredentialsMapper(EncryptionService encryptionService) {
            this.encryptionService = encryptionService;
        }

        @Override
        public UserGoogleMfaCredentials mapRow(ResultSet rs, int rowNum) throws SQLException {
            UserGoogleMfaCredentials userGoogleMfaCredentials = null;
            try {
                userGoogleMfaCredentials = new UserGoogleMfaCredentials(
                  rs.getString("user_id"),
                  new String(encryptionService.decrypt(Base64Utils.decodeFromString(rs.getString("secret_key")))),
                  valueOf(new String(encryptionService.decrypt(Base64Utils.decodeFromString(rs.getString("encrypted_validation_code"))))),
                  fromSCString(new String(encryptionService.decrypt(Base64Utils.decodeFromString(rs.getString("scratch_codes")))))
                );
            } catch (EncryptionServiceException e) {
                logger.error("Unable to decrypt MFA credentials", e);
                throw new UnableToRetrieveMfaException(e);
            }
            userGoogleMfaCredentials.setMfaProviderId(rs.getString("mfa_provider_id"));
            userGoogleMfaCredentials.setZoneId(rs.getString("zone_id"));

            return userGoogleMfaCredentials;
        }

        private List<Integer> fromSCString(String csString) {
            return Arrays.stream(csString.split(",")).map(s -> Integer.parseInt(s)).collect(Collectors.toList());
        }
    }

    public void setEncryptionService(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }
}
