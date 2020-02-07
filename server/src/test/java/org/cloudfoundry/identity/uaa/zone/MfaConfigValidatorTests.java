package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.EmptyResultDataAccessException;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class MfaConfigValidatorTests {

    @Mock
    private MfaProviderProvisioning mockJdbcMfaProviderProvisioning;

    @InjectMocks
    private MfaConfigValidator mfaConfigValidator;

    @Test
    void validateSuccessful() throws InvalidIdentityZoneConfigurationException {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(matches("some-provider"), anyString())).thenReturn(new MfaProvider());

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName("some-provider");
        mfaConfigValidator.validate(configuration, "some-zone");
    }

    @Test
    void validateDisabledNoProviderId() throws InvalidIdentityZoneConfigurationException {
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderName("");

        mfaConfigValidator.validate(configuration, "some-zone");
    }

    @Test
    void validateDisabledInvalidProvider() throws InvalidIdentityZoneConfigurationException {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        MfaConfig configuration = new MfaConfig().setEnabled(false).setProviderName("some-provider");

        assertThrowsWithMessageThat(
                InvalidIdentityZoneConfigurationException.class,
                () -> mfaConfigValidator.validate(configuration, "some-zone"),
                Matchers.is("Active MFA Provider not found with name: some-provider"));
    }

    @Test
    void validateNoAvailableProviders() throws Exception {
        when(mockJdbcMfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));
        String providerName = "some-provider";

        MfaConfig configuration = new MfaConfig().setEnabled(true).setProviderName(providerName);
        assertThrowsWithMessageThat(
                InvalidIdentityZoneConfigurationException.class,
                () -> mfaConfigValidator.validate(configuration, "some-zone"),
                Matchers.is("Active MFA Provider not found with name: some-provider"));

    }
}