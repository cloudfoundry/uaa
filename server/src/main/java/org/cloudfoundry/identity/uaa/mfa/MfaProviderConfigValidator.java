package org.cloudfoundry.identity.uaa.mfa;

public interface MfaProviderConfigValidator<T extends AbstractMfaProviderConfig>{
    void validate(T mfaProviderConfig);
}
