package org.cloudfoundry.identity.uaa.mfa_provider;

public interface MfaProviderProvisioning {
    MfaProvider create(MfaProvider provider, String zoneId);

    MfaProvider retrieve(String id, String zoneId);

}
