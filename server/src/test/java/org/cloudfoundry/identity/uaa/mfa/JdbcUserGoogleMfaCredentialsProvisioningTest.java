package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class JdbcUserGoogleMfaCredentialsProvisioningTest extends JdbcTestBase {

    private JdbcUserGoogleMfaCredentialsProvisioning db;

    private final static String MFA_ID = new RandomValueStringGenerator(36).generate();
    private String zoneId = new RandomValueStringGenerator(36).generate();

    @Before
    public void initJdbcScimUserProvisioningTests() throws Exception {
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate);
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
                Arrays.asList(1,22)).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        List<Map<String, Object>> credentials = jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials");
        assertEquals(1, credentials.size());
        Map<String, Object> record = credentials.get(0);
        assertEquals("jabbahut", record.get("user_id"));
        assertEquals("very_sercret_key", record.get("secret_key"));
        assertEquals(74718234, record.get("validation_code"));
        assertEquals("1,22", record.get("scratch_codes"));
        assertEquals(MFA_ID, record.get("mfa_provider_id"));
        assertEquals(zoneId, record.get("zone_id"));
    }

    // db.save is a jdbcProvisioner method and should throw error when creating duplicate
    @Test(expected = UserMfaConfigAlreadyExistsException.class)
    public void testSave_whenExistsForUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
                "very_sercret_key",
                74718234,
                Arrays.asList(1,22)).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        db.save(userGoogleMfaCredentials, zoneId);
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testUpdateUserGoogleMfaCredentials_noUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
            "very_sercret_key",
            74718234,
            Arrays.asList(1,22));
        db.update(userGoogleMfaCredentials, zoneId);
    }

    @Test
    public void testUpdateUserGoogleMfaCredentials(){
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
            "very_sercret_key",
            74718234,
            Arrays.asList(1,22));
        userGoogleMfaCredentials.setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        userGoogleMfaCredentials.setSecretKey("new_secret_key");
        db.update(userGoogleMfaCredentials, zoneId);

        UserGoogleMfaCredentials updated = db.retrieve(userGoogleMfaCredentials.getUserId(), MFA_ID);
        assertEquals("new_secret_key", updated.getSecretKey());
    }

    @Test
    public void testRetrieveExisting() {
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        UserGoogleMfaCredentials creds = db.retrieve("user1", MFA_ID);
        assertEquals("user1", creds.getUserId());
        assertEquals("secret", creds.getSecretKey());
        assertEquals(12345, creds.getValidationCode());
        assertEquals( Collections.singletonList(123), creds.getScratchCodes());
        assertEquals(MFA_ID, creds.getMfaProviderId());
        assertEquals(zoneId, creds.getZoneId());
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testRetrieveExistingDifferentMfaProvider() {
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        UserGoogleMfaCredentials creds = db.retrieve("user1", "otherMfa");
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testRetrieveNotExisting() {
        db.retrieve("user1", MFA_ID);
    }

    @Test
    public void testDelete() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.delete("user1");
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
    }

    @Test
    public void testDeleteByProvider() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.deleteByMfaProvider(MFA_ID, zoneId);
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
    }

    @Test
    public void testDeleteByZone() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.deleteByIdentityZone(zoneId);
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

    }
}