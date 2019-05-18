package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class CodeStoreEndpointsTests {

    private CodeStoreEndpoints codeStoreEndpoints;
    private ExpiringCodeStore expiringCodeStore;
    private AtomicLong currentTime;
    private final String EMPTY_JSON = "{}";

    @BeforeEach
    void initCodeStoreTests(@Autowired JdbcTemplate jdbcTemplate) {
        currentTime = new AtomicLong(System.currentTimeMillis());

        expiringCodeStore = new JdbcExpiringCodeStore(jdbcTemplate.getDataSource(), new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return currentTime.get();
            }
        });
        codeStoreEndpoints = new CodeStoreEndpoints(expiringCodeStore, null);
    }

    @Test
    void generateCode() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        ExpiringCode result = codeStoreEndpoints.generateCode(expiringCode);

        assertNotNull(result);

        assertNotNull(result.getCode());
        assertEquals(10, result.getCode().trim().length());

        assertEquals(expiresAt, result.getExpiresAt());

        assertEquals(EMPTY_JSON, result.getData());
    }

    @Test
    void generateCodeWithNullData() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, null, null);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("data and expiresAt are required."));
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        ExpiringCode expiringCode = new ExpiringCode(null, null, EMPTY_JSON, null);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("data and expiresAt are required."));
    }

    @Test
    void generateCodeWithExpiresAtInThePast() {
        Timestamp expiresAt = new Timestamp(currentTime.get() - 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("expiresAt must be in the future."));
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        assertDoesNotThrow(() -> codeStoreEndpoints.generateCode(expiringCode));
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.INTERNAL_SERVER_ERROR));
        assertThat(codeStoreException.getMessage(), is("Duplicate code generated."));
    }

    @Test
    void retrieveCode() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);
        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        ExpiringCode retrievedCode = codeStoreEndpoints.retrieveCode(generatedCode.getCode());

        assertEquals(generatedCode, retrievedCode);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode(generatedCode.getCode()));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.NOT_FOUND));
        assertThat(codeStoreException.getMessage(), is("Code not found: " + generatedCode.getCode()));
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode("unknown"));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.NOT_FOUND));
        assertThat(codeStoreException.getMessage(), is("Code not found: unknown"));
    }

    @Test
    void retrieveCodeWithNullCode() {
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode(null));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("code is required."));
    }

    @Test
    void storeLargeData() {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String data = new String(oneMb);
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        String code = generatedCode.getCode();
        ExpiringCode actualCode = codeStoreEndpoints.retrieveCode(code);

        assertEquals(generatedCode, actualCode);
    }

    @Test
    void retrieveCodeWithExpiredCode() {
        int expiresIn = 1000;
        Timestamp expiresAt = new Timestamp(currentTime.get() + expiresIn);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);
        currentTime.addAndGet(expiresIn + 1);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode(generatedCode.getCode()));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.NOT_FOUND));
        assertThat(codeStoreException.getMessage(), is("Code not found: " + generatedCode.getCode()));
    }
}
