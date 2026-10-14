package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/** Checks persisted references after zone and client bootstraps have finished. */
@Component
public class MtlsTrustBundleStartupValidator implements SmartInitializingSingleton {
    private final IdentityZoneProvisioning zones;
    private final MultitenantClientServices clients;

    public MtlsTrustBundleStartupValidator(IdentityZoneProvisioning zones,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clients) {
        this.zones = zones;
        this.clients = clients;
    }

    @Override
    public void afterSingletonsInstantiated() {
        for (var zone : zones.retrieveAll()) {
            MtlsTrustBundles.validate(zone.getConfig().getMtlsTrustBundles());
            for (var client : clients.listClientDetails(zone.getId())) {
                var info = client.getAdditionalInformation();
                if (info.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF)
                        || info.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF)) {
                    try {
                        for (String inline : java.util.List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)) {
                            MtlsTrustBundles.resolve(info, inline, inline + "-ref", zone.getConfig().getMtlsTrustBundles());
                        }
                    } catch (InvalidClientDetailsException e) {
                        throw new InvalidClientDetailsException("Invalid mTLS trust for client_id=" + client.getClientId()
                                + " in identity_zone_id=" + zone.getId() + ": " + e.getMessage(), e);
                    }
                }
            }
        }
    }
}
