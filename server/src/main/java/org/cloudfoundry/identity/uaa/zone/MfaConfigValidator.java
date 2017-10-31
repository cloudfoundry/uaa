package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.util.StringUtils;

public class MfaConfigValidator {
    private static Log logger = LogFactory.getLog(MfaConfigValidator.class);
    private MfaProviderProvisioning mfaProviderProvisioning;

    public MfaProviderProvisioning getMfaProviderProvisioning() {
        return mfaProviderProvisioning;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void validate(MfaConfig config, String zoneId) throws InvalidIdentityZoneConfigurationException {
        if(config.isEnabled() || StringUtils.hasText(config.getProviderId())) {
            try {
                MfaProvider existingProvider = mfaProviderProvisioning.retrieve(config.getProviderId(), zoneId);
                if(!existingProvider.isActive()) {
                    logger.debug(String.format("Provider with id %s is not active.", config.getProviderId()));
                    throw new InvalidIdentityZoneConfigurationException("Active MFA Provider not found for id: " + config.getProviderId());
                }
            } catch(EmptyResultDataAccessException e){
                logger.debug(String.format("Provider with id %s not found", config.getProviderId()));
                throw new InvalidIdentityZoneConfigurationException("Active MFA Provider not found for id: " + config.getProviderId());
            }
        }
    }
}
