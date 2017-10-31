package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.mfa_provider.exception.InvalidMfaProviderConfigException;

public interface MfaProviderConfigValidator<T extends AbstractMfaProviderConfig>{
    void validate(T mfaProviderConfig) throws InvalidMfaProviderConfigException;
}
