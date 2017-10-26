package org.cloudfoundry.identity.uaa.mfa_provider;

public interface MfaProviderValidator {
    void validate(MfaProvider mfaProvider);
}
