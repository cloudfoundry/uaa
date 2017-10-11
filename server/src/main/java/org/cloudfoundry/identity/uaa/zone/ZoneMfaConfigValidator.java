package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
import org.springframework.dao.EmptyResultDataAccessException;

public class ZoneMfaConfigValidator {
    private MfaProviderProvisioning mfaProviders;

    public MfaProviderProvisioning getMfaProviders() {
        return mfaProviders;
    }

    public void setMfaProviders(MfaProviderProvisioning mfaProviders) {
        this.mfaProviders = mfaProviders;
    }

    public void validate(ZoneMfaConfig config) throws InvalidIdentityZoneConfigurationException {
        if(config.isEnabled()) {
            try {
                MfaProvider active = mfaProviders.retrieve(config.getProviderId(), IdentityZoneHolder.get().getId());
            } catch(EmptyResultDataAccessException e){
                throw new InvalidIdentityZoneConfigurationException("Active MFA Provider was not found");
            }
        }
    }
}
