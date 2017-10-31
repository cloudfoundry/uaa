package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.mfa_provider.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
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
        when(provisioning.retrieve(matches("some-provider"), anyString())).thenReturn(new MfaProvider());

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderId("some-provider");
        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_disabled_no_provider_id() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderId("");

        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_disabled_invalid_provider() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration  = new MfaConfig().setEnabled(false).setProviderId("some-provider");

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider not found for id: some-provider");
        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_no_available_providers() throws Exception {
        when(provisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        String providerId = "some-provider";

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider not found for id: " + providerId);

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderId(providerId);
        validator.validate(configuration, "some-zone");
    }

    @Test
    public void validate_inactive_providers() throws Exception {
        when(provisioning.retrieve(anyString(), anyString())).thenReturn(new MfaProvider().setActive(false));
        String providerId = "some-provider";

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider not found for id: " + providerId);

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderId(providerId);
        validator.validate(configuration, "some-zone");
    }
}