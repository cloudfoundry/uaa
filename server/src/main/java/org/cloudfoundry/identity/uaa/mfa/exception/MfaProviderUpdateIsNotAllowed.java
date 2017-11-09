package org.cloudfoundry.identity.uaa.mfa.exception;

public class MfaProviderUpdateIsNotAllowed extends Exception {
    public MfaProviderUpdateIsNotAllowed() {
        super("Updating an MFA provider is not allowed.");
    }
}
