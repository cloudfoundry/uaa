package org.cloudfoundry.identity.uaa.mfa;

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.cypto.EncryptionKeyService;
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

public class JdbcUserGoogleMfaCredentialsProvisioning implements SystemDeletable, UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> {

    private static Logger logger = LoggerFactory.getLogger(JdbcUserGoogleMfaCredentialsProvisioning.class);

    private static final String CREATE_USER_MFA_CONFIG_SQL =
      "INSERT INTO user_google_mfa_credentials (user_id, secret_key, encrypted_validation_code, scratch_codes, mfa_provider_id, zone_id, encryption_key_label) VALUES (?,?,?,?,?,?,?)";

    private static final String UPDATE_USER_MFA_CONFIG_SQL =
      "UPDATE user_google_mfa_credentials SET secret_key=?, encrypted_validation_code=?, scratch_codes=?, mfa_provider_id=?, zone_id=? WHERE user_id=?";

    private static final String QUERY_USER_MFA_CONFIG_ALL_SQL = "SELECT * FROM user_google_mfa_credentials WHERE user_id=? AND mfa_provider_id=?";

    private static final String DELETE_USER_MFA_CONFIG_SQL = "DELETE FROM user_google_mfa_credentials WHERE user_id=?";

    private static final String DELETE_PROVIDER_MFA_CONFIG_SQL = "DELETE FROM user_google_mfa_credentials WHERE mfa_provider_id=?";

    private static final String DELETE_ZONE_MFA_CONFIG_SQL = "DELETE FROM user_google_mfa_credentials WHERE zone_id=?";

    private JdbcTemplate jdbcTemplate;
    private UserMfaCredentialsMapper mapper;
    private EncryptionKeyService encryptionKeyService;

    public JdbcUserGoogleMfaCredentialsProvisioning(JdbcTemplate jdbcTemplate, EncryptionKeyService encryptionKeyService) {
        this.jdbcTemplate = jdbcTemplate;
        this.mapper = new UserMfaCredentialsMapper(encryptionKeyService);
        this.encryptionKeyService = encryptionKeyService;
    }

    private String encrypt(String value) throws EncryptionServiceException {
        return Base64Utils.encodeToString(encryptionKeyService.getActiveKey().encrypt(value));
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
                ps.setString(pos++, encryptionKeyService.getActiveKey().getLabel());
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
    public Logger getLogger() {
        return LoggerFactory.getLogger(JdbcUserGoogleMfaCredentialsProvisioning.class);
    }

    private String toCSScratchCode(List<Integer> scratchCodes) {
        return StringUtils.join(scratchCodes, ",");
    }

    private static final class UserMfaCredentialsMapper implements RowMapper<UserGoogleMfaCredentials> {
        private EncryptionKeyService encryptionKeyService;

        public UserMfaCredentialsMapper(EncryptionKeyService encryptionKeyService) {
            this.encryptionKeyService = encryptionKeyService;
        }

        @Override
        public UserGoogleMfaCredentials mapRow(ResultSet rs, int rowNum) throws SQLException {
            UserGoogleMfaCredentials userGoogleMfaCredentials = null;
            String encryptionKeyLabel = rs.getString("encryption_key_label");

            if (StringUtils.isEmpty(encryptionKeyLabel)) {
                userGoogleMfaCredentials = new UserGoogleMfaCredentials(
                  rs.getString("user_id"),
                  rs.getString("secret_key"),
                  rs.getInt("validation_code"),
                  fromSCString(rs.getString("scratch_codes")));
            } else {
                try {
                    EncryptionKeyService.EncryptionKey encryptionKey = encryptionKeyService.getKey(encryptionKeyLabel).orElseGet(() -> {
                        RuntimeException cause = new RuntimeException("Attempted to retrieve record with an unknown decryption key");
                        logger.error(String.format("Couldn't decrypt with unknown key label : %s", encryptionKeyLabel), cause);
                        throw new UnableToRetrieveMfaException(cause);
                    });

                    userGoogleMfaCredentials = new UserGoogleMfaCredentials(
                      rs.getString("user_id"),
                      new String(encryptionKey.decrypt(Base64Utils.decodeFromString(rs.getString("secret_key")))),
                      valueOf(new String(encryptionKey.decrypt(Base64Utils.decodeFromString(rs.getString("encrypted_validation_code"))))),
                      fromSCString(new String(encryptionKey.decrypt(Base64Utils.decodeFromString(rs.getString("scratch_codes")))))
                    );
                } catch (EncryptionServiceException e) {
                    logger.error("Unable to decrypt MFA credentials", e);
                    throw new UnableToRetrieveMfaException(e);
                }
            }

            userGoogleMfaCredentials.setMfaProviderId(rs.getString("mfa_provider_id"));
            userGoogleMfaCredentials.setZoneId(rs.getString("zone_id"));

            return userGoogleMfaCredentials;
        }

        private List<Integer> fromSCString(String csString) {
            return Arrays.stream(csString.split(",")).map(s -> Integer.parseInt(s)).collect(Collectors.toList());
        }
    }
}
