package org.cloudfoundry.identity.uaa.mfa;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.cypto.EncryptionKey;
import org.cloudfoundry.identity.uaa.cypto.EncryptionKeyService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionProperties;
import org.cloudfoundry.identity.uaa.cypto.EncryptionServiceException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToPersistMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToRetrieveMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Answers;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Base64Utils;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JdbcUserGoogleMfaCredentialsProvisioningTest extends JdbcTestBase {
    private JdbcUserGoogleMfaCredentialsProvisioning db;
    private String activeKeyLabel;
    private String inactiveKeyLabel;
    private EncryptionKeyService encryptionKeyService;
    private EncryptionKey activeEncryptionKey;
    private EncryptionKey inActiveEncryptionKey;

    @BeforeClass
    public static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    private final static String MFA_ID = new RandomValueStringGenerator(36).generate();
    private String zoneId = new RandomValueStringGenerator(36).generate();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void initJdbcScimUserProvisioningTests() throws Exception {
        activeKeyLabel = "key-1";
        inactiveKeyLabel = "key-2";

        activeEncryptionKey = new EncryptionKey(activeKeyLabel, "some-password");
        inActiveEncryptionKey = new EncryptionKey(inactiveKeyLabel, "some-other-password");

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel(activeKeyLabel);
        properties.setEncryptionKeys(Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));

        encryptionKeyService = new EncryptionKeyService(properties);

        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);
    }

    @After
    public void clear() throws Exception {
        jdbcTemplate.execute("delete from user_google_mfa_credentials");
    }

    @Test
    public void testSaveUserGoogleMfaCredentials() throws EncryptionServiceException {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
          "very_sercret_key",
          74718234,
          Arrays.asList(1, 22)).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        List<Map<String, Object>> credentials = jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials");
        assertEquals(1, credentials.size());
        Map<String, Object> record = credentials.get(0);
        assertEquals("jabbahut", record.get("user_id"));

        assertEquals("very_sercret_key", new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString((String) record.get("secret_key"))))
        );
        assertEquals(74718234, Integer.parseInt(new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString(String.valueOf(record.get("encrypted_validation_code"))))))
        );
        assertEquals("1,22", new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString(String.valueOf(record.get("scratch_codes")))))
        );

        assertEquals(MFA_ID, record.get("mfa_provider_id"));
        assertEquals(zoneId, record.get("zone_id"));
        assertEquals(activeKeyLabel, record.get("encryption_key_label"));
    }

    // db.save is a jdbcProvisioner method and should throw error when creating duplicate
    @Test(expected = UserMfaConfigAlreadyExistsException.class)
    public void testSave_whenExistsForUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
          "very_sercret_key",
          74718234,
          Arrays.asList(1, 22)).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        db.save(userGoogleMfaCredentials, zoneId);
    }

    @Test(expected = UserMfaConfigDoesNotExistException.class)
    public void testUpdateUserGoogleMfaCredentials_noUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
          "very_sercret_key",
          74718234,
          Arrays.asList(1, 22));
        db.update(userGoogleMfaCredentials, zoneId);
    }

    @Test
    public void testUpdateUserGoogleMfaCredentials() throws EncryptionServiceException {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
          "very_sercret_key",
          74718234,
          Arrays.asList(1, 22));
        userGoogleMfaCredentials.setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        userGoogleMfaCredentials.setSecretKey("new_secret_key");
        userGoogleMfaCredentials.setValidationCode(84718234);
        userGoogleMfaCredentials.setScratchCodes(Arrays.asList(2, 22));
        db.update(userGoogleMfaCredentials, zoneId);

        List<Map<String, Object>> credentials = jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials");
        assertEquals(1, credentials.size());
        Map<String, Object> record = credentials.get(0);

        assertEquals("new_secret_key", new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString((String) record.get("secret_key"))))
        );
        assertEquals(84718234, Integer.parseInt(new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString(String.valueOf(record.get("encrypted_validation_code"))))))
        );
        assertEquals("2,22", new String(
          activeEncryptionKey.decrypt(Base64Utils.decodeFromString((String) record.get("scratch_codes"))))
        );
        assertEquals(activeKeyLabel, record.get("encryption_key_label"));
    }

    @Test
    public void testRetrieveExisting() {
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        UserGoogleMfaCredentials creds = db.retrieve("user1", MFA_ID);
        assertEquals("user1", creds.getUserId());
        assertEquals("secret", creds.getSecretKey());
        assertEquals(12345, creds.getValidationCode());
        assertEquals(Collections.singletonList(123), creds.getScratchCodes());
        assertEquals(MFA_ID, creds.getMfaProviderId());
        assertEquals(zoneId, creds.getZoneId());
    }

    @Test
    public void testRetrieveExistingWithANonActiveEncryptionKey() throws EncryptionServiceException {
        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel(inactiveKeyLabel);
        properties.setEncryptionKeys(Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));

        encryptionKeyService = new EncryptionKeyService(properties);
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);

        properties.setActiveKeyLabel(activeKeyLabel);

        encryptionKeyService = new EncryptionKeyService(properties);
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);

        UserGoogleMfaCredentials creds = db.retrieve("user1", MFA_ID);
        assertThat(creds.getUserId(), is("user1"));
        assertThat(creds.getSecretKey(), is("secret"));
        assertThat(creds.getValidationCode(), is(12345));
        assertThat(creds.getScratchCodes(), containsInAnyOrder(123));
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

    @Test
    public void whenSaving_AndFailsToEncrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
        EncryptionKeyService mockEncryptionKeyService = mock(EncryptionKeyService.class, Answers.RETURNS_DEEP_STUBS);
        when(mockEncryptionKeyService.getActiveKey().encrypt(any()))
          .thenThrow(new EncryptionServiceException(new RuntimeException("message should match")));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, mockEncryptionKeyService);

        expectedException.expect(UnableToPersistMfaException.class);
        expectedException.expectMessage("message should match");

        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
    }

    @Test
    public void whenUpdating_AndFailsToEncrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials(
          "user1",
          "secret",
          12345,
          Collections.singletonList(123)
        ).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);

        EncryptionKeyService mockEncryptionKeyService = mock(EncryptionKeyService.class, Answers.RETURNS_DEEP_STUBS);
        when(mockEncryptionKeyService.getActiveKey().encrypt(any()))
          .thenThrow(new EncryptionServiceException(new RuntimeException("message should match")));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, mockEncryptionKeyService);

        userGoogleMfaCredentials.setSecretKey("new_secret");
        expectedException.expect(UnableToPersistMfaException.class);
        expectedException.expectMessage("message should match");

        db.update(userGoogleMfaCredentials, zoneId);
    }

    @Test
    public void whenReading_AndFailsToDecrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials(
          "user1",
          "secret",
          12345,
          Collections.singletonList(123)
        ).setMfaProviderId(MFA_ID);
        db.save(userGoogleMfaCredentials, zoneId);

        EncryptionKeyService mockEncryptionKeyService = mock(EncryptionKeyService.class, Answers.RETURNS_DEEP_STUBS);
        when(mockEncryptionKeyService.getKey(any()).orElseGet(any()).decrypt(any()))
          .thenThrow(new EncryptionServiceException(new RuntimeException("message should match")));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, mockEncryptionKeyService);

        expectedException.expect(UnableToRetrieveMfaException.class);
        expectedException.expectMessage("message should match");

        db.retrieve(userGoogleMfaCredentials.getUserId(), MFA_ID);
    }

    @Test
    public void whenDecryptingWithNonExistentKey_ShouldThrowMeaningfulException() {
        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel(inactiveKeyLabel);
        properties.setEncryptionKeys(Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));

        encryptionKeyService = new EncryptionKeyService(properties);
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);

        properties.setActiveKeyLabel(activeKeyLabel);
        properties.setEncryptionKeys(Lists.newArrayList(activeEncryptionKey));

        encryptionKeyService = new EncryptionKeyService(properties);
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);

        expectedException.expect(UnableToRetrieveMfaException.class);
        expectedException.expectMessage("Attempted to retrieve record with an unknown decryption key");

        db.retrieve("user1", MFA_ID);
    }

    @Test
    public void whenDecryptingRecordWithNoKeyLabel_ShouldNotAttemptToDecrypt() {
        String userId = "user1";
        int numInsertedRecords = jdbcTemplate.update("INSERT INTO user_google_mfa_credentials (user_id, secret_key, validation_code, scratch_codes, mfa_provider_id, zone_id, encryption_key_label) VALUES (?,?,?,?,?,?,?)",
          userId, "secret_key", 123456, "123", MFA_ID, zoneId, null);
        assertThat(numInsertedRecords, is(1));

        UserGoogleMfaCredentials user = db.retrieve(userId, MFA_ID);
        assertThat(user, is(notNullValue()));
        assertThat(user.getUserId(), is(userId));
        assertThat(user.getSecretKey(), is("secret_key"));
        assertThat(user.getValidationCode(), is(123456));
        assertThat(user.getScratchCodes(), containsInAnyOrder(123));
    }

    @Test
    public void whenDecryptingRecordWithEmptyKeyLabel_ShouldNotAttemptToDecrypt() {
        String userId = "user1";
        int numInsertedRecords = jdbcTemplate.update("INSERT INTO user_google_mfa_credentials (user_id, secret_key, validation_code, scratch_codes, mfa_provider_id, zone_id, encryption_key_label) VALUES (?,?,?,?,?,?,?)",
          userId, "secret_key", 123456, "123", MFA_ID, zoneId, "");
        assertThat(numInsertedRecords, is(1));

        UserGoogleMfaCredentials user = db.retrieve(userId, MFA_ID);
        assertThat(user, is(notNullValue()));
        assertThat(user.getUserId(), is(userId));
        assertThat(user.getSecretKey(), is("secret_key"));
        assertThat(user.getValidationCode(), is(123456));
        assertThat(user.getScratchCodes(), containsInAnyOrder(123));
    }

}