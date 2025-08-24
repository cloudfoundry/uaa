package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class CodeStoreEndpointsTests {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private CodeStoreEndpoints codeStoreEndpoints;
    private ExpiringCodeStore spiedExpiringCodeStore;
    private AtomicLong currentTime;
    private static final String EMPTY_JSON = "{}";
    private String currentIdentityZoneId;

    @BeforeEach
    void setUp() {
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

        assertThat(result).isNotNull();

        assertThat(result.getCode()).isNotNull();
        assertThat(result.getCode().trim()).hasSize(32);

        assertThat(result.getExpiresAt()).isEqualTo(expiresAt);

        assertThat(result.getData()).isEqualTo(EMPTY_JSON);

        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithNullData() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, null, null);

        assertThatThrownBy(() -> codeStoreEndpoints.generateCode(expiringCode))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("data and expiresAt are required.")
                .extracting("status")
                .isEqualTo(HttpStatus.BAD_REQUEST);
        verify(spiedExpiringCodeStore).generateCode(null, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithNullExpiresAt() {
        ExpiringCode expiringCode = new ExpiringCode(null, null, EMPTY_JSON, null);

        assertThatThrownBy(() -> codeStoreEndpoints.generateCode(expiringCode))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("data and expiresAt are required.")
                .extracting("status")
                .isEqualTo(HttpStatus.BAD_REQUEST);
        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, null, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithExpiresAtInThePast() {
        Timestamp expiresAt = new Timestamp(currentTime.get() - 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        assertThatThrownBy(() -> codeStoreEndpoints.generateCode(expiringCode))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("expiresAt must be in the future.")
                .extracting("status")
                .isEqualTo(HttpStatus.BAD_REQUEST);
        verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void generateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        spiedExpiringCodeStore.setGenerator(generator);

        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);

        assertThatNoException().isThrownBy(() -> codeStoreEndpoints.generateCode(expiringCode));

        assertThatThrownBy(() -> codeStoreEndpoints.generateCode(expiringCode))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("Duplicate code generated.")
                .extracting("status")
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        verify(spiedExpiringCodeStore, times(2))
                .generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
    }

    @Test
    void retrieveCode() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, EMPTY_JSON, null);
        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        String code = generatedCode.getCode();
        ExpiringCode retrievedCode = codeStoreEndpoints.retrieveCode(code);

        assertThat(retrievedCode).isEqualTo(generatedCode);
        assertThatThrownBy(() -> codeStoreEndpoints.retrieveCode(code))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("Code not found: " + code)
                .extracting("status")
                .isEqualTo(HttpStatus.NOT_FOUND);

        InOrder inOrder = inOrder(spiedExpiringCodeStore);
        inOrder.verify(spiedExpiringCodeStore).generateCode(EMPTY_JSON, expiresAt, null, currentIdentityZoneId);
        inOrder.verify(spiedExpiringCodeStore).retrieveCode(code, currentIdentityZoneId);
    }

    @Test
    void retrieveCodeWithCodeNotFound() {
        assertThatThrownBy(() -> codeStoreEndpoints.retrieveCode("unknown"))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("Code not found: unknown")
                .extracting("status")
                .isEqualTo(HttpStatus.NOT_FOUND);
        verify(spiedExpiringCodeStore).retrieveCode("unknown", currentIdentityZoneId);
    }

    @Test
    void retrieveCodeWithNullCode() {
        assertThatThrownBy(() -> codeStoreEndpoints.retrieveCode(null))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("code is required.")
                .extracting("status")
                .isEqualTo(HttpStatus.BAD_REQUEST);
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

        assertThat(actualCode).isEqualTo(generatedCode);
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

        String code = generatedCode.getCode();
        assertThatThrownBy(() -> codeStoreEndpoints.retrieveCode(code))
                .isInstanceOf(CodeStoreException.class)
                .hasMessage("Code not found: " + code)
                .extracting("status")
                .isEqualTo(HttpStatus.NOT_FOUND);
        verify(spiedExpiringCodeStore).retrieveCode(code, currentIdentityZoneId);
    }
}
