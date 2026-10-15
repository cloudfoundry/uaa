package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Checks that persisted client references to named mTLS trust bundles resolve.
 *
 * <p>Startup inspects only the default zone, after zone and client bootstraps have finished:
 * installations can have tens of thousands of zones, so enumerating them would make startup
 * scale with the tenant count. A tenant zone is checked instead when an update turns mTLS on for
 * it ({@link #validateOnEnable}). Runtime trust resolution still denies any client whose
 * reference no longer resolves, so an unchecked zone fails closed.
 *
 * <p>Zones where mTLS is not effectively enabled are skipped: their clients are inert, and a
 * stale reference must not prevent startup or unrelated zone updates.
 */
@Component
public class MtlsTrustBundleStartupValidator implements SmartInitializingSingleton {
    private static final List<String> REFERENCE_KEYS = List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF,
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF);

    private final boolean deploymentEnabled;
    private final IdentityZoneProvisioning zones;
    private final MultitenantClientServices clients;

    public MtlsTrustBundleStartupValidator(@Value("${uaa.mtls.enabled:false}") boolean deploymentEnabled,
            IdentityZoneProvisioning zones,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clients) {
        this.deploymentEnabled = deploymentEnabled;
        this.zones = zones;
        this.clients = clients;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!deploymentEnabled) {
            return;
        }
        IdentityZone defaultZone = zones.retrieve(IdentityZone.getUaaZoneId());
        if (MtlsFeaturePolicy.isEnabled(true, defaultZone)) {
            MtlsTrustBundles.validate(defaultZone.getConfig().getMtls().getTrustBundles());
            validateClientReferences(defaultZone);
        }
    }

    /**
     * Rejects an update that turns mTLS on for a zone whose clients reference trust bundles the
     * updated configuration does not provide. Bundle contents are validated by the zone
     * configuration validator; updates that keep mTLS on or turn it off are not revalidated.
     */
    public void validateOnEnable(IdentityZone previous, IdentityZone updated) {
        if (!MtlsFeaturePolicy.isEnabled(deploymentEnabled, previous)
                && MtlsFeaturePolicy.isEnabled(deploymentEnabled, updated)) {
            validateClientReferences(updated);
        }
    }

    private void validateClientReferences(IdentityZone zone) {
        // Only clients that reference a bundle are loaded; most clients have no mTLS configuration.
        for (var client : clients.listClientDetailsWithAdditionalInformationKey(zone.getId(), REFERENCE_KEYS)) {
            var info = client.getAdditionalInformation();
            try {
                for (String inline : List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
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
