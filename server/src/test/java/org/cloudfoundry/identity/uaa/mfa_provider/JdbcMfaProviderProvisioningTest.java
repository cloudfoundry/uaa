package org.cloudfoundry.identity.uaa.mfa_provider;

import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.PreparedStatement;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JdbcMfaProviderProvisioningTest {
    JdbcMfaProviderProvisioning mfaProviderProvisioning;
    JdbcTemplate jdbcTemplate;

    @Before
    public void setup() {
        jdbcTemplate = mock(JdbcTemplate.class);
        mfaProviderProvisioning = new JdbcMfaProviderProvisioning(jdbcTemplate);
    }

    @Test
    public void testCreate() {
        MfaProvider mfaProvider = constructGoogleProvider();

        mfaProviderProvisioning.create(mfaProvider, "uaa");

        verify(jdbcTemplate).update(eq(JdbcMfaProviderProvisioning.CREATE_PROVIDER_SQL), any(PreparedStatement.class));
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider()
                .setName(new RandomValueStringGenerator(5).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig().setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
    }
}