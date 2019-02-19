package org.cloudfoundry.identity.uaa.mfa;

public interface MfaProviderValidator {
    void validate(MfaProvider mfaProvider);
}
