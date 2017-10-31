package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.mfa_provider.exception.InvalidMfaProviderConfigException;
import org.cloudfoundry.identity.uaa.mfa_provider.exception.InvalidMfaProviderException;
import org.springframework.util.StringUtils;

public class GeneralMfaProviderValidator implements MfaProviderValidator{
    private MfaProviderConfigValidator configValidator;

    @Override
    public void validate(MfaProvider mfaProvider) {
        if(mfaProvider.getName() == null || StringUtils.isEmpty(mfaProvider.getName().trim())) {
            throw new InvalidMfaProviderException("Provider name is required");
        }
        mfaProvider.setName(mfaProvider.getName().trim());
        if(mfaProvider.getName().length() > 256) {
            throw new InvalidMfaProviderException("Provider name cannot be longer than 256 characters");
        }
        if(!mfaProvider.getName().matches("^[a-zA-Z0-9]+[\\sa-zA-Z0-9]*$")){
            throw new InvalidMfaProviderException("Provider name must be alphanumeric");
        }
        if(mfaProvider.getType() == null) {
            throw new InvalidMfaProviderException("Provider type is required. Must be one of " + MfaProvider.MfaProviderType.getStringValues());
        }
        if(mfaProvider.getConfig() == null) {
            throw new InvalidMfaProviderException("Provider config is required");
        }
        if(!StringUtils.hasText(mfaProvider.getIdentityZoneId())){
            throw new InvalidMfaProviderException("Provider must belong to a zone");
        }
        try {
            configValidator.validate(mfaProvider.getConfig());
        } catch (InvalidMfaProviderConfigException e) {
            throw new InvalidMfaProviderException("Invalid Config for MFA Provider. " + e.getMessage());
        }
    }


    public void setConfigValidator(MfaProviderConfigValidator configValidator) {
        this.configValidator = configValidator;
    }
}
