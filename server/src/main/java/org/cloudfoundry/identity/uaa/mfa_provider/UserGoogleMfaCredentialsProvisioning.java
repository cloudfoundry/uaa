package org.cloudfoundry.identity.uaa.mfa_provider;

import com.warrenstrange.googleauth.ICredentialRepository;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.mfa_provider.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa_provider.exception.UserMfaConfigDoesNotExistException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class UserGoogleMfaCredentialsProvisioning implements UserMfaCredentialsProvisioning<UserGoogleMfaCredentials>, ICredentialRepository {


    public static final String TABLE_NAME = "user_google_mfa_credentials";

    private static final String CREATE_USER_MFA_CONFIG_SQL =
            "INSERT INTO " + TABLE_NAME + "(user_id, secret_key, validation_code, scratch_codes) VALUES (?,?,?,?)";

    private static final String QUERY_USER_MFA_CONFIG_SQL = "SELECT * FROM " + TABLE_NAME + " WHERE user_id=? AND active=true";
    private static final String QUERY_USER_MFA_CONFIG_INACTIVE_SQL = "SELECT * FROM " + TABLE_NAME + " WHERE user_id=? AND active=true";

    private static final String DELETE_USER_MFA_CONFIG_SQL = "DELETE FROM " + TABLE_NAME + " WHERE user_id=?";

    private  JdbcTemplate jdbcTemplate;
    private UserMfaCredentialsMapper mapper = new UserMfaCredentialsMapper();

    public UserGoogleMfaCredentialsProvisioning(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean userCredentialExists(String userId) {
        try {
            retrieveActive(userId);
            return true;
        } catch (UserMfaConfigDoesNotExistException e) {
            return false;
        }
    }

    @Override
    public String getSecretKey(String userId) {
        UserGoogleMfaCredentials userGoogleMfaCredentials = retrieve(userId);
        //TODO Redirect to "qr_code" page when creds not found for user
        return userGoogleMfaCredentials.getSecretKey();
    }

    @Override
    public void saveUserCredentials(String userId, String secretKey, int validationCode, List<Integer> scratchCodes) {
        save(new UserGoogleMfaCredentials(userId, secretKey, validationCode, scratchCodes));
    }

    @Override
    public void save(UserGoogleMfaCredentials credentials) {
        try {
            jdbcTemplate.update(CREATE_USER_MFA_CONFIG_SQL, ps -> {
                int pos = 1;
                ps.setString(pos++, credentials.getUserId());
                ps.setString(pos++, credentials.getSecretKey());
                ps.setInt(pos++, credentials.getValidationCode());
                ps.setString(pos++, toCSScratchCode(credentials.getScratchCodes()));
            });
        } catch (DuplicateKeyException e) {
            throw new UserMfaConfigAlreadyExistsException(e.getMostSpecificCause().getMessage());
        }
    }

    @Override
    public UserGoogleMfaCredentials retrieve(String userId) {
        try{
            return jdbcTemplate.queryForObject(QUERY_USER_MFA_CONFIG_SQL, mapper, userId);
        } catch(EmptyResultDataAccessException e) {
            throw new UserMfaConfigDoesNotExistException("No Creds for user " +userId);
        }
    }

    public UserGoogleMfaCredentials retrieveActive(String userId) {
        return null;
    }

    @Override
    public int delete(String userId) {
        return jdbcTemplate.update(DELETE_USER_MFA_CONFIG_SQL, userId);
    }

    private String toCSScratchCode(List<Integer> scratchCodes) {
        return StringUtils.join(scratchCodes, ",");
    }

    private static final class UserMfaCredentialsMapper implements RowMapper<UserGoogleMfaCredentials> {
        @Override
        public UserGoogleMfaCredentials mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new UserGoogleMfaCredentials(
                    rs.getString("user_id"),
                    rs.getString("secret_key"),
                    rs.getInt("validation_code"),
                    fromSCString(rs.getString("scratch_codes"))
            );
        }

        private List<Integer> fromSCString(String csString) {
            return Arrays.stream(csString.split(",")).map( s -> Integer.parseInt(s)).collect(Collectors.toList());
        }
    }
}
