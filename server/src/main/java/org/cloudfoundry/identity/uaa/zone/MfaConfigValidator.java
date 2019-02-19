package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
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
        if(config.isEnabled() || StringUtils.hasText(config.getProviderName())) {
            try {
                mfaProviderProvisioning.retrieveByName(config.getProviderName(), zoneId);
            } catch(EmptyResultDataAccessException e){
                logger.debug(String.format("Provider with name %s not found", config.getProviderName()));
                throw new InvalidIdentityZoneConfigurationException("Active MFA Provider not found with name: " + config.getProviderName());
            }
        }
    }
}
