package org.cloudfoundry.identity.uaa.mfa;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.cypto.EncryptionKeyService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionServiceException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToPersistMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UnableToRetrieveMfaException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.test.RandomStringGetter;
import org.cloudfoundry.identity.uaa.test.RandomStringGetterExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Base64Utils;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
@ExtendWith(RandomStringGetterExtension.class)
class JdbcUserGoogleMfaCredentialsProvisioningTest {
    private JdbcUserGoogleMfaCredentialsProvisioning db;
    private String activeKeyLabel;
    private String inactiveKeyLabel;
    private EncryptionKeyService encryptionKeyService;
    private EncryptionKeyService.EncryptionKey activeEncryptionKey;
    private EncryptionKeyService.EncryptionKey inActiveEncryptionKey;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeAll
    static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    private String MFA_ID;
    private String zoneId;

    @BeforeEach
    void initJdbcScimUserProvisioningTests(
            final RandomStringGetter mfaId,
            final RandomStringGetter zoneId) {
        this.MFA_ID = StringUtils.rightPad(mfaId.get(), 36);
        this.zoneId = StringUtils.rightPad(zoneId.get(), 36);
        activeKeyLabel = "key-1";
        inactiveKeyLabel = "key-2";

        activeEncryptionKey = new EncryptionKeyService.EncryptionKey() {{
            put("label", activeKeyLabel);
            put("passphrase", "some-password");
        }};
        inActiveEncryptionKey = new EncryptionKeyService.EncryptionKey() {{
            put("label", inactiveKeyLabel);
            put("passphrase", "some-other-password");
        }};

        encryptionKeyService = new EncryptionKeyService(activeKeyLabel, Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));

        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);
    }

    @AfterEach
    void clear() {
        jdbcTemplate.execute("delete from user_google_mfa_credentials");
    }

    @Test
    void saveUserGoogleMfaCredentials() throws EncryptionServiceException {
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
    @Test
    void save_whenExistsForUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
                "very_sercret_key",
                74718234,
                Arrays.asList(1, 22)).setMfaProviderId(MFA_ID);

        db.save(userGoogleMfaCredentials, zoneId);
        assertThrows(UserMfaConfigAlreadyExistsException.class, () -> db.save(userGoogleMfaCredentials, zoneId));
    }

    @Test
    void updateUserGoogleMfaCredentials_noUser() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("jabbahut",
                "very_sercret_key",
                74718234,
                Arrays.asList(1, 22));
        assertThrows(UserMfaConfigDoesNotExistException.class, () -> db.update(userGoogleMfaCredentials, zoneId));
    }

    @Test
    void updateUserGoogleMfaCredentials() throws EncryptionServiceException {
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
    void retrieveExisting() {
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
    void retrieveExistingWithANonActiveEncryptionKey() {
        encryptionKeyService = new EncryptionKeyService(inactiveKeyLabel, Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate,
                encryptionKeyService);
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);


        encryptionKeyService = new EncryptionKeyService(activeKeyLabel, Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);

        UserGoogleMfaCredentials creds = db.retrieve("user1", MFA_ID);
        assertThat(creds.getUserId(), is("user1"));
        assertThat(creds.getSecretKey(), is("secret"));
        assertThat(creds.getValidationCode(), is(12345));
        assertThat(creds.getScratchCodes(), containsInAnyOrder(123));
    }

    @Test
    void retrieveExistingDifferentMfaProvider() {
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertThrows(UserMfaConfigDoesNotExistException.class, () -> db.retrieve("user1", "otherMfa"));
    }

    @Test
    void retrieveNotExisting() {
        assertThrows(UserMfaConfigDoesNotExistException.class, () -> db.retrieve("user1", MFA_ID));
    }

    @Test
    void delete() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.delete("user1");
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
    }

    @Test
    void deleteByProvider() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.deleteByMfaProvider(MFA_ID, zoneId);
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
    }

    @Test
    void deleteByZone() {
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);
        assertEquals(1, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

        db.deleteByIdentityZone(zoneId);
        assertEquals(0, jdbcTemplate.queryForList("SELECT * FROM user_google_mfa_credentials").size());

    }

    @Test
    void whenSaving_AndFailsToEncrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
        EncryptionKeyService mockEncryptionKeyService = mock(EncryptionKeyService.class, Answers.RETURNS_DEEP_STUBS);
        when(mockEncryptionKeyService.getActiveKey().encrypt(any()))
                .thenThrow(new EncryptionServiceException(new RuntimeException("message should match")));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, mockEncryptionKeyService);

        final UserGoogleMfaCredentials userGoogleMfaCredentials = new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123));

        assertThrowsWithMessageThat(
                UnableToPersistMfaException.class,
                () -> db.save(userGoogleMfaCredentials.setMfaProviderId(MFA_ID), zoneId),
                containsString("message should match")
        );
    }

    @Test
    void whenUpdating_AndFailsToEncrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
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

        assertThrowsWithMessageThat(
                UnableToPersistMfaException.class,
                () -> db.update(userGoogleMfaCredentials, zoneId),
                containsString("message should match")
        );
    }

    @Test
    void whenReading_AndFailsToDecrypt_ShouldThrowAMeaningfulException() throws EncryptionServiceException {
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

        assertThrowsWithMessageThat(
                UnableToRetrieveMfaException.class,
                () -> db.retrieve(userGoogleMfaCredentials.getUserId(), MFA_ID),
                containsString("message should match")
        );
    }

    @Test
    void whenDecryptingWithNonExistentKey_ShouldThrowMeaningfulException() {
        encryptionKeyService = new EncryptionKeyService(inactiveKeyLabel, Lists.newArrayList(activeEncryptionKey, inActiveEncryptionKey));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate,
                encryptionKeyService);
        db.save(new UserGoogleMfaCredentials("user1", "secret", 12345, Collections.singletonList(123)).setMfaProviderId(MFA_ID), zoneId);


        encryptionKeyService = new EncryptionKeyService(activeKeyLabel, Lists.newArrayList(activeEncryptionKey));
        db = new JdbcUserGoogleMfaCredentialsProvisioning(jdbcTemplate, encryptionKeyService);

        assertThrowsWithMessageThat(
                UnableToRetrieveMfaException.class,
                () -> db.retrieve("user1", MFA_ID),
                containsString("Attempted to retrieve record with an unknown decryption key")
        );
    }

    @Test
    void whenDecryptingRecordWithNoKeyLabel_ShouldNotAttemptToDecrypt() {
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
    void whenDecryptingRecordWithEmptyKeyLabel_ShouldNotAttemptToDecrypt() {
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