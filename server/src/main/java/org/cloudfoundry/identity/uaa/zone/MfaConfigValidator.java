package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class MfaConfigValidator {
    private static Logger logger = LoggerFactory.getLogger(MfaConfigValidator.class);

    private final MfaProviderProvisioning mfaProviderProvisioning;

    public MfaConfigValidator(
            final MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void validate(MfaConfig config, String zoneId) throws InvalidIdentityZoneConfigurationException {
        if (config.isEnabled() || StringUtils.hasText(config.getProviderName())) {
            try {
                mfaProviderProvisioning.retrieveByName(config.getProviderName(), zoneId);
            } catch (EmptyResultDataAccessException e) {
                logger.debug(String.format("Provider with name %s not found", config.getProviderName()));
                throw new InvalidIdentityZoneConfigurationException("Active MFA Provider not found with name: " + config.getProviderName());
            }
        }
    }
}
