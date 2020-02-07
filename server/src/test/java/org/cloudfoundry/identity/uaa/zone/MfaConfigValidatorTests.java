package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.mfa.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.dao.EmptyResultDataAccessException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MfaConfigValidatorTests {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private MfaConfigValidator mfaConfigValidator;
    private MfaProviderProvisioning mockJdbcMfaProviderProvisioning;

    @Before
    public void setup() {
        mfaConfigValidator = new MfaConfigValidator();
        mockJdbcMfaProviderProvisioning = mock(JdbcMfaProviderProvisioning.class);
        mfaConfigValidator.setMfaProviderProvisioning(mockJdbcMfaProviderProvisioning);
    }

    @Test
    public void validateSuccessful() throws InvalidIdentityZoneConfigurationException {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(matches("some-provider"), anyString())).thenReturn(new MfaProvider());

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName("some-provider");
        mfaConfigValidator.validate(configuration, "some-zone");
    }

    @Test
    public void validateDisabledNoProviderId() throws InvalidIdentityZoneConfigurationException {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderName("");

        mfaConfigValidator.validate(configuration, "some-zone");
    }

    @Test
    public void validateDisabledInvalidProvider() throws InvalidIdentityZoneConfigurationException {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderName("some-provider");

        exception.expect(InvalidIdentityZoneConfigurationException.class);
        exception.expectMessage("Active MFA Provider not found with name: some-provider");
        mfaConfigValidator.validate(configuration, "some-zone");
    }

    @Test
    public void validateNoAvailableProviders() throws Exception {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        String providerName = "some-provider";

        exception.expect(InvalidIdentityZoneConfigurationException.class);
        exception.expectMessage("Active MFA Provider not found with name: " + providerName);

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName(providerName);
        mfaConfigValidator.validate(configuration, "some-zone");
    }
}