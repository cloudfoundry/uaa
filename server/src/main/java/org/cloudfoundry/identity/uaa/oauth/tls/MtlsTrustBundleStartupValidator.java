package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/** Checks persisted references after zone and client bootstraps have finished. */
@Component
public class MtlsTrustBundleStartupValidator implements SmartInitializingSingleton {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(MtlsTrustBundleStartupValidator.class);
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
            try {
                validateZone(zone);
            } catch (InvalidClientDetailsException e) {
                if (zone.isUaa()) {
                    throw e;
                }
                // A tenant administrator must not prevent every other zone from starting.
                // Runtime trust resolution still denies clients whose references no longer resolve.
                logger.warn("Invalid mTLS trust in identity_zone_id={}; affected clients will be denied: {}",
                        zone.getId(), e.getMessage());
            }
        }
    }

    private void validateZone(IdentityZone zone) {
        MtlsTrustBundles.validate(zone.getConfig().getMtls().getTrustBundles());
        for (var client : clients.listClientDetails(zone.getId())) {
            var info = client.getAdditionalInformation();
            if (info.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF)
                    || info.containsKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF)) {
                try {
                    for (String inline : java.util.List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)) {
                        MtlsTrustBundles.resolve(info, inline, inline + "-ref", zone.getConfig().getMtls().getTrustBundles());
                    }
                } catch (InvalidClientDetailsException e) {
                    throw new InvalidClientDetailsException("Invalid mTLS trust for client_id=" + client.getClientId()
                            + " in identity_zone_id=" + zone.getId() + ": " + e.getMessage(), e);
                }
            }
        }
    }
}
