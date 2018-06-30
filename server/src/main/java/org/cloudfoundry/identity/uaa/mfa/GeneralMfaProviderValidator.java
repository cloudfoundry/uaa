package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaProviderException;
import org.springframework.util.StringUtils;

public class GeneralMfaProviderValidator implements MfaProviderValidator{

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
        if(mfaProvider.getConfig().getIssuer() != null && mfaProvider.getConfig().getIssuer().contains(":")) {
            throw new InvalidMfaProviderException("Provider config contains an invalid issuer. Issuer must not contain a colon");
        }
        if(!StringUtils.hasText(mfaProvider.getIdentityZoneId())){
            throw new InvalidMfaProviderException("Provider must belong to a zone");
        }
    }
}
