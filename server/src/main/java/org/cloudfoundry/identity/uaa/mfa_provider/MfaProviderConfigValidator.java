package org.cloudfoundry.identity.uaa.mfa_provider;

public interface MfaProviderConfigValidator<T extends AbstractMfaProviderConfig>{
    void validate(T mfaProviderConfig) throws InvalidMfaProviderConfigException;
}
