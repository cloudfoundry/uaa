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


public class ZoneMfaConfigValidatorTests {

    @Rule
    public ExpectedException expection = ExpectedException.none();

    private ZoneMfaConfigValidator validator;
    private MfaProviderProvisioning provisioning;

    @Before
    public void setup() {
        validator = new ZoneMfaConfigValidator();
        provisioning = mock(JdbcMfaProviderProvisioning.class);
        validator.setMfaProviders(provisioning);
    }

    @Test
    public void validate_successful() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieve(matches("some-provider"), anyString())).thenReturn(new MfaProvider());

        ZoneMfaConfig configuration = new ZoneMfaConfig().setEnabled(true).setProviderId("some-provider");
        validator.validate(configuration);
    }

    @Test
    public void validate_disabled() throws InvalidIdentityZoneConfigurationException {
        when(provisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        ZoneMfaConfig configuration = new ZoneMfaConfig().setEnabled(false).setProviderId("some-provider");
        validator.validate(configuration);
    }

    @Test
    public void validate_no_available_providers() throws Exception {
        when(provisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        expection.expect(InvalidIdentityZoneConfigurationException.class);
        expection.expectMessage("Active MFA Provider was not found");

        ZoneMfaConfig configuration = new ZoneMfaConfig().setEnabled(true).setProviderId("some-provider");
        validator.validate(configuration);
    }
}