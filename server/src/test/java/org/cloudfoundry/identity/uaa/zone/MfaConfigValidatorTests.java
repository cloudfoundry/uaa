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
    public ExpectedException expection = ExpectedException.none();

    private MfaConfigValidator validator;
    private MfaProviderProvisioning provisioning;

    @Before
    public void setup() {
        validator = new MfaConfigValidator();
        provisioning = mock(JdbcMfaProviderProvisioning.class);
        validator.setMfaProviderProvisioning(provisioning);
    }

    @Test
    public void validate_successful() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieveByName(matches("some-provider"), anyString())).thenReturn(new MfaProvider());

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName("some-provider");
        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_disabled_no_provider_id() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderName("");

        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_disabled_invalid_provider() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration  = new MfaConfig().setEnabled(false).setProviderName("some-provider");

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider not found with name: some-provider");
        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_no_available_providers() throws Exception {
        when(provisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        String providerName = "some-provider";

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider not found with name: " + providerName);

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName(providerName);
        validator.validate(configuration, "some-zone");
    }
}