package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
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
import static org.mockito.Mockito.*;

@WithDatabaseContext
class CodeStoreEndpointsTests {

    private CodeStoreEndpoints codeStoreEndpoints;
    private ExpiringCodeStore spiedExpiringCodeStore;
    private AtomicLong currentTime;
    private final String EMPTY_JSON = "{}";
    private String currentIdentityZoneId;

    @BeforeEach
    void setUp(@Autowired JdbcTemplate jdbcTemplate) {
        currentTime = new AtomicLong(System.currentTimeMillis());

        spiedExpiringCodeStore = spy(new JdbcExpiringCodeStore(jdbcTemplate.getDataSource(), new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return currentTime.get();
            }
        }));

        currentIdentityZoneId = createDummyIdentityZone(jdbcTemplate);
        final IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        codeStoreEndpoints = new CodeStoreEndpoints(spiedExpiringCodeStore, null, mockIdentityZoneManager);
    }

    private String createDummyIdentityZone(@Autowired JdbcTemplate jdbcTemplate) {
        final RandomValueStringGenerator generator = new RandomValueStringGenerator();
        final String currentIdentityZoneId = "identityZoneId-" + generator.generate();

        final IdentityZone identityZoneToCreate = IdentityZone.getUaa();
        identityZoneToCreate.setSubdomain("identityZoneSubdomain-" + generator.generate());
        identityZoneToCreate.setId(currentIdentityZoneId);

        final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        jdbcIdentityZoneProvisioning.create(identityZoneToCreate);

        return currentIdentityZoneId;
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

        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
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
        verify(spiedExpiringCodeStore).generateCode(null, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        ExpiringCode expiringCode = new ExpiringCode(null, null, EMPTY_JSON, null);

        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("data and expiresAt are required."));
        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, null, null, currentIdentityZoneId);
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
        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        spiedExpiringCodeStore.setGenerator(generator);

        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        assertDoesNotThrow(() -> codeStoreEndpoints.generateCode(expiringCode));
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.generateCode(expiringCode));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.INTERNAL_SERVER_ERROR));
        assertThat(codeStoreException.getMessage(), is("Duplicate code generated."));
        verify(spiedExpiringCodeStore, times(2))
                .generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
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

        InOrder inOrder = inOrder(spiedExpiringCodeStore);
        inOrder.verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
        inOrder.verify(spiedExpiringCodeStore).retrieveCode(generatedCode.getCode(), currentIdentityZoneId);
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode("unknown"));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.NOT_FOUND));
        assertThat(codeStoreException.getMessage(), is("Code not found: unknown"));
        verify(spiedExpiringCodeStore).retrieveCode("unknown", currentIdentityZoneId);
    }

    @Test
    void retrieveCodeWithNullCode() {
        CodeStoreException codeStoreException =
                assertThrows(CodeStoreException.class,
                        () -> codeStoreEndpoints.retrieveCode(null));

        assertThat(codeStoreException.getStatus(), is(HttpStatus.BAD_REQUEST));
        assertThat(codeStoreException.getMessage(), is("code is required."));
        verify(spiedExpiringCodeStore).retrieveCode(null, currentIdentityZoneId);
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
        InOrder inOrder = inOrder(spiedExpiringCodeStore);
        inOrder.verify(spiedExpiringCodeStore).generateCode(data, expiresAt, null, currentIdentityZoneId);
        inOrder.verify(spiedExpiringCodeStore).retrieveCode(code, currentIdentityZoneId);
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
        verify(spiedExpiringCodeStore).retrieveCode(generatedCode.getCode(), currentIdentityZoneId);
    }
}
