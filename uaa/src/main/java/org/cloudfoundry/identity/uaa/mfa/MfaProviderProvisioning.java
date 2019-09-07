package org.cloudfoundry.identity.uaa.mfa;

import java.util.List;

public interface MfaProviderProvisioning {
    MfaProvider create(MfaProvider provider, String zoneId);

    MfaProvider update(MfaProvider provider, String zoneId);

    MfaProvider retrieve(String id, String zoneId);

    MfaProvider retrieveByName(String name, String zoneId);

    List<MfaProvider> retrieveAll(String zoneId);
}
