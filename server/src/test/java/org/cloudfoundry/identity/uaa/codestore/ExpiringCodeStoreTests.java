package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Map;

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

    int countCodes() {
        if (expiringCodeStore instanceof InMemoryExpiringCodeStore) {
            Map map = (Map) ReflectionTestUtils.getField(expiringCodeStore, "store");
            return map.size();
        } else {
            // confirm that everything is clean prior to test.
            return jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class);
        }
    }

    @Test
    void generateCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

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
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        String data = "{}";
        Timestamp expiresAt = null;
        assertThrows(NullPointerException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void generateCodeWithExpiresAtInThePast() {
        long now = 100000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(now - 60000);
        assertThrows(IllegalArgumentException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        Mockito.when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
        assertThrows(DataIntegrityViolationException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void retrieveCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());

        assertEquals(generatedCode, retrievedCode);

        assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void retrieveCode_In_Another_Zone() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("other", "other"));
        assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId()));

        IdentityZoneHolder.clear();
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());
        assertEquals(generatedCode, retrievedCode);
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown", IdentityZoneHolder.get().getId());

        assertNull(retrievedCode);
    }

    @Test
    void retrieveCodeWithNullCode() {
        assertThrows(NullPointerException.class,
                () -> expiringCodeStore.retrieveCode(null, IdentityZoneHolder.get().getId()));
    }

    @Test
    void storeLargeData() {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String aaaString = new String(oneMb);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(aaaString, new Timestamp(
                System.currentTimeMillis() + 60000), null, IdentityZoneHolder.get().getId());
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        assertEquals(expiringCode, actualCode);
    }

    @Test
    void expiredCodeReturnsNull() {
        long generationTime = 100000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(generationTime);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(generationTime);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        long expirationTime = 200000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(expirationTime);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());
        assertNull(retrievedCode);
    }

    @Test
    void expireCodeByIntent() {
        ExpiringCode code = expiringCodeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 60000), "Test Intent", IdentityZoneHolder.get().getId());

        assertEquals(1, countCodes());

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("id", "id"));
        expiringCodeStore.expireByIntent("Test Intent", IdentityZoneHolder.get().getId());
        assertEquals(1, countCodes());

        IdentityZoneHolder.clear();
        expiringCodeStore.expireByIntent("Test Intent", IdentityZoneHolder.get().getId());
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(code.getCode(), IdentityZoneHolder.get().getId());
        assertEquals(0, countCodes());
        assertNull(retrievedCode);
    }

}
