package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

abstract class ExpiringCodeStoreTests {

    ExpiringCodeStore expiringCodeStore;
    TimeService mockTimeService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() throws Exception {
        mockTimeService = mock(TimeServiceImpl.class);
    }

    abstract int countCodes();

    @Test
    void generateCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        assertNotNull(expiringCode);

        assertNotNull(expiringCode.getCode());
        assertTrue(expiringCode.getCode().trim().length() > 0);

        assertEquals(expiresAt, expiringCode.getExpiresAt());

        assertEquals(data, expiringCode.getData());
    }

    @Test
    void generateCodeWithNullData() {
        String data = null;
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        assertThrows(NullPointerException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        String data = "{}";
        Timestamp expiresAt = null;
        assertThrows(NullPointerException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithExpiresAtInThePast() {
        long now = 100000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(now - 60000);
        assertThrows(IllegalArgumentException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        Mockito.when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());
        assertThrows(DataIntegrityViolationException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void peekCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        String zoneId = IdentityZone.getUaaZoneId();

        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, zoneId);

        assertEquals(generatedCode, expiringCodeStore.peekCode(generatedCode.getCode(), zoneId));
        assertEquals(generatedCode, expiringCodeStore.peekCode(generatedCode.getCode(), zoneId));
        assertEquals(generatedCode, expiringCodeStore.peekCode(generatedCode.getCode(), zoneId));
    }

    @Test
    void retrieveCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());

        assertEquals(generatedCode, retrievedCode);

        assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId()));
    }

    @Test
    void retrieveCode_In_Another_Zone() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), "other"));

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());
        assertEquals(generatedCode, retrievedCode);
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown", IdentityZone.getUaaZoneId());

        assertNull(retrievedCode);
    }

    @Test
    void retrieveCodeWithNullCode() {
        assertThrows(NullPointerException.class,
                () -> expiringCodeStore.retrieveCode(null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void storeLargeData() {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String aaaString = new String(oneMb);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(aaaString, new Timestamp(
                System.currentTimeMillis() + 60000), null, IdentityZone.getUaaZoneId());
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code, IdentityZone.getUaaZoneId());
        assertEquals(expiringCode, actualCode);
    }

    @Test
    void expiredCodeReturnsNull() {
        long generationTime = 100000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(generationTime);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(generationTime);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        long expirationTime = 200000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(expirationTime);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());
        assertNull(retrievedCode);
    }

    @Test
    void expireCodeByIntent() {
        ExpiringCode code = expiringCodeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 60000), "Test Intent", IdentityZone.getUaaZoneId());

        assertEquals(1, countCodes());

        expiringCodeStore.expireByIntent("Test Intent", "id");
        assertEquals(1, countCodes());

        expiringCodeStore.expireByIntent("Test Intent", IdentityZone.getUaaZoneId());
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(code.getCode(), IdentityZone.getUaaZoneId());
        assertEquals(0, countCodes());
        assertNull(retrievedCode);
    }

}