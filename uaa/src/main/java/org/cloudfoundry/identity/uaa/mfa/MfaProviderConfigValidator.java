package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaProviderConfigException;

public interface MfaProviderConfigValidator<T extends AbstractMfaProviderConfig>{
    void validate(T mfaProviderConfig) throws InvalidMfaProviderConfigException;
}
