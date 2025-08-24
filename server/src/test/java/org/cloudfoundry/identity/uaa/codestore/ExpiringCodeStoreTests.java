package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
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

        assertThat(expiringCode).isNotNull();
        assertThat(expiringCode.getCode()).isNotNull().isNotBlank();
        assertThat(expiringCode.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(expiringCode.getData()).isEqualTo(data);
    }

    @Test
    void generateCodeWithNullData() {
        String data = null;
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        String data = "{}";
        Timestamp expiresAt = null;
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithExpiresAtInThePast() {
        long now = 100000L;
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(now - 60000);
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        Mockito.when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());
        assertThatExceptionOfType(DataIntegrityViolationException.class).isThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void peekCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        String zoneId = IdentityZone.getUaaZoneId();

        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, zoneId);
        assertThat(expiringCodeStore.peekCode(generatedCode.getCode(), zoneId)).isEqualTo(generatedCode)
                .isEqualTo(generatedCode)
                .isEqualTo(generatedCode);
    }

    @Test
    void retrieveCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());

        assertThat(retrievedCode).isEqualTo(generatedCode);

        assertThat(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId())).isNull();
    }

    @Test
    void retrieveCode_In_Another_Zone() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        assertThat(expiringCodeStore.retrieveCode(generatedCode.getCode(), "other")).isNull();

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());
        assertThat(retrievedCode).isEqualTo(generatedCode);
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown", IdentityZone.getUaaZoneId());

        assertThat(retrievedCode).isNull();
    }

    @Test
    void retrieveCodeWithNullCode() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> expiringCodeStore.retrieveCode(null, IdentityZone.getUaaZoneId()));
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
        assertThat(actualCode).isEqualTo(expiringCode);
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
        assertThat(retrievedCode).isNull();
    }

    @Test
    void expireCodeByIntent() {
        ExpiringCode code = expiringCodeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 60000), "Test Intent", IdentityZone.getUaaZoneId());

        assertThat(countCodes()).isOne();

        expiringCodeStore.expireByIntent("Test Intent", "id");
        assertThat(countCodes()).isOne();

        expiringCodeStore.expireByIntent("Test Intent", IdentityZone.getUaaZoneId());
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(code.getCode(), IdentityZone.getUaaZoneId());
        assertThat(countCodes()).isZero();
        assertThat(retrievedCode).isNull();
    }

}
