package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.zone.GeneralIdentityZoneConfigurationValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MtlsTrustBundleStartupValidatorTest {
    @Test
    void allowedTenantBundleRemovalCannotPreventOtherZonesFromStarting() throws Exception {
        IdentityZone tenant = new IdentityZone();
        tenant.setId("tenant");
        tenant.getConfig().getMtls().setTrustBundles(Map.of());
        // Removing a bundle is a valid zone update. Existing clients retain their references.
        assertThat(new GeneralIdentityZoneConfigurationValidator().validate(tenant, IdentityZoneValidator.Mode.MODIFY))
                .isSameAs(tenant.getConfig());
        UaaClientDetails client = referencingClient();
        assertThatThrownBy(() -> MtlsTrustBundles.resolve(client.getAdditionalInformation(),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF,
                tenant.getConfig().getMtls().getTrustBundles()))
                .isInstanceOf(InvalidClientDetailsException.class).hasMessageContaining("unknown or empty");
        assertThatCode(() -> validator(tenant, client).afterSingletonsInstantiated()).doesNotThrowAnyException();
    }

    @Test
    void missingOperatorBundleStillPreventsDefaultZoneStartup() {
        assertThatThrownBy(() -> validator(IdentityZone.getUaa(), referencingClient()).afterSingletonsInstantiated())
                .isInstanceOf(InvalidClientDetailsException.class).hasMessageContaining("identity_zone_id=uaa");
    }

    private static UaaClientDetails referencingClient() {
        UaaClientDetails client = new UaaClientDetails();
        client.setClientId("workload");
        client.addAdditionalInformation(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF, "removed");
        return client;
    }

    private static MtlsTrustBundleStartupValidator validator(IdentityZone zone, UaaClientDetails client) {
        IdentityZoneProvisioning zones = mock(IdentityZoneProvisioning.class);
        MultitenantClientServices clients = mock(MultitenantClientServices.class);
        when(zones.retrieveAll()).thenReturn(List.of(zone));
        when(clients.listClientDetails(zone.getId())).thenReturn(List.of(client));
        return new MtlsTrustBundleStartupValidator(zones, clients);
    }
}
