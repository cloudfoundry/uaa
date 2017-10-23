package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.mfa_provider.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa_provider.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class UserGoogleMfaCredentialsProvisioningTest extends JdbcTestBase {

    private UserGoogleMfaCredentialsProvisioning db;

    @Before
    public void initJdbcScimUserProvisioningTests() throws Exception {
        db = new UserGoogleMfaCredentialsProvisioning(jdbcTemplate);
    }


    @After
    public void clear() throws Exception {
        jdbcTemplate.execute("delete from user_google_mfa_credentials");
    }

    @Test
    public void testSaveUserGoogleMfaCredentials(){
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
                "very_sercret_key",
                74718234,
                Arrays.asList(1,22),
                true);

        db.save(userGoogleMfaCredentials);
        List<Map<String, Object>> credentials = jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials");
        assertEquals(1, credentials.size());
        Map<String, Object> record = credentials.get(0);
        assertEquals("jabbahut", record.get("user_id"));
        assertEquals("very_sercret_key", record.get("secret_key"));
        assertEquals(74718234, record.get("validation_code"));
        assertEquals("1,22", record.get("scratch_codes"));
        assertTrue((boolean) record.get("active"));
    }

    @Test(expected = UserMfaConfigAlreadyExistsException.class)
    public void testSaveUserGoogleMfaCredentials_whenExistsForUser(){
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
                "very_sercret_key",
                74718234,
                Arrays.asList(1,22));

        db.save(userGoogleMfaCredentials);
        db.save(userGoogleMfaCredentials);
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testUpdateUserGoogleMfaCredentials_noUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
            "very_sercret_key",
            74718234,
            Arrays.asList(1,22));
        db.update(userGoogleMfaCredentials);
    }


    @Test
    public void testUpdateUserGoogleMfaCredentials(){
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
            "very_sercret_key",
            74718234,
            Arrays.asList(1,22));

        db.save(userGoogleMfaCredentials);
        userGoogleMfaCredentials.setActive(true);
        userGoogleMfaCredentials.setSecretKey("new_secret_key");
        db.update(userGoogleMfaCredentials);

        UserGoogleMfaCredentials updated = db.retrieve(userGoogleMfaCredentials.getUserId());
        assertEquals("new_secret_key", updated.getSecretKey());
        assertEquals(true, updated.isActive());
    }

    @Test
    public void testRetrieveExisting() {
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)));
        UserGoogleMfaCredentials creds = db.retrieve("user1");
        assertEquals("user1", creds.getUserId());
        assertEquals("secret", creds.getSecretKey());
        assertEquals(12345, creds.getValidationCode());
        assertEquals( Collections.singletonList(123), creds.getScratchCodes());
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testRetrieveNotExisting() {
        db.retrieve("user1");
    }

    @Test
    public void testDelete() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)));
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.delete("user1");
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
    }
}