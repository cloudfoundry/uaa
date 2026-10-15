package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.zone.GeneralIdentityZoneConfigurationValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class MtlsTrustBundleStartupValidatorTest {
    private static final String TENANT = "tenant";
    private static final List<String> REFERENCE_KEYS = List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF,
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF);
    private IdentityZoneProvisioning zones;
    private MultitenantClientServices clients;

    @BeforeEach
    void setUp() {
        zones = mock(IdentityZoneProvisioning.class);
        clients = mock(MultitenantClientServices.class);
        when(clients.listClientDetailsWithAdditionalInformationKey(anyString(), eq(REFERENCE_KEYS)))
                .thenReturn(List.of(referencingClient()));
    }

    @Nested
    class Startup {
        @Test
        void missingOperatorBundleStillPreventsDefaultZoneStartup() {
            givenDefaultZone(true);
            assertThatThrownBy(() -> validator(true).afterSingletonsInstantiated())
                    .isInstanceOf(InvalidClientDetailsException.class).hasMessageContaining("identity_zone_id=uaa");
        }

        @Test
        void neverEnumeratesZones() {
            givenDefaultZone(true);
            when(clients.listClientDetailsWithAdditionalInformationKey(IdentityZone.getUaaZoneId(), REFERENCE_KEYS))
                    .thenReturn(List.of());

            validator(true).afterSingletonsInstantiated();

            verify(zones, never()).retrieveAll();
            verify(clients).listClientDetailsWithAdditionalInformationKey(IdentityZone.getUaaZoneId(), REFERENCE_KEYS);
            verify(clients, never()).listClientDetailsWithAdditionalInformationKey(eq(TENANT), any());
        }

        @Test
        void neverLoadsEveryClientOfAZone() {
            givenDefaultZone(true);
            when(clients.listClientDetailsWithAdditionalInformationKey(anyString(), eq(REFERENCE_KEYS)))
                    .thenReturn(List.of());

            validator(true).afterSingletonsInstantiated();
            validator(true).validateOnEnable(zone(TENANT, false), zone(TENANT, true));

            verify(clients, never()).listClientDetails(anyString());
        }

        @Test
        void deploymentSwitchOffMakesUnresolvableDefaultZoneReferencesInert() {
            givenDefaultZone(true);

            assertThatCode(() -> validator(false).afterSingletonsInstantiated())
                    .as("uaa.mtls.enabled=false must make previously registered mTLS clients inert, not fatal")
                    .doesNotThrowAnyException();
            verifyNoInteractions(clients);
        }

        @Test
        void defaultZoneDisabledMakesItsUnresolvableReferencesInert() {
            givenDefaultZone(false);

            assertThatCode(() -> validator(true).afterSingletonsInstantiated())
                    .as("a default zone that disabled mTLS must not fail startup on its inert clients")
                    .doesNotThrowAnyException();
            verifyNoInteractions(clients);
        }
    }

    /** Tenant zones are validated when an update turns mTLS on, independently of the default zone. */
    @Nested
    class EnablingAZone {
        @Test
        void unresolvableReferenceIsRejected() {
            assertThatThrownBy(() -> validator(true).validateOnEnable(zone(TENANT, false), zone(TENANT, true)))
                    .isInstanceOf(InvalidClientDetailsException.class)
                    .hasMessageContaining("client_id=workload")
                    .hasMessageContaining("identity_zone_id=" + TENANT);
        }

        @Test
        void referenceResolvedByTheSameUpdateIsAccepted() {
            IdentityZone enabled = zone(TENANT, true);
            // Bundle contents are validated by the zone configuration validator; this checks references.
            enabled.getConfig().getMtls().setTrustBundles(Map.of("removed", "restored-bundle-pem"));

            assertThatCode(() -> validator(true).validateOnEnable(zone(TENANT, false), enabled))
                    .doesNotThrowAnyException();
            verify(clients).listClientDetailsWithAdditionalInformationKey(TENANT, REFERENCE_KEYS);
        }

        @Test
        void updatesThatKeepMtlsEnabledAreNotRevalidated() throws Exception {
            IdentityZone tenant = zone(TENANT, true);
            tenant.getConfig().getMtls().setTrustBundles(Map.of());
            // Removing a bundle is a valid zone update. Existing clients retain their references.
            assertThat(new GeneralIdentityZoneConfigurationValidator().validate(tenant, IdentityZoneValidator.Mode.MODIFY))
                    .isSameAs(tenant.getConfig());

            assertThatCode(() -> validator(true).validateOnEnable(zone(TENANT, true), tenant))
                    .doesNotThrowAnyException();
            verifyNoInteractions(clients);
        }

        @Test
        void disablingIsNotValidated() {
            assertThatCode(() -> validator(true).validateOnEnable(zone(TENANT, true), zone(TENANT, false)))
                    .doesNotThrowAnyException();
            verifyNoInteractions(clients);
        }

        @Test
        void deploymentSwitchOffSkipsValidation() {
            assertThatCode(() -> validator(false).validateOnEnable(zone(TENANT, false), zone(TENANT, true)))
                    .doesNotThrowAnyException();
            verifyNoInteractions(clients);
        }

        @Test
        void tenantIsValidatedWhileDefaultZoneIsDisabled() {
            givenDefaultZone(false);
            validator(true).afterSingletonsInstantiated();

            assertThatThrownBy(() -> validator(true).validateOnEnable(zone(TENANT, false), zone(TENANT, true)))
                    .isInstanceOf(InvalidClientDetailsException.class);
        }
    }

    private void givenDefaultZone(boolean mtlsEnabled) {
        when(zones.retrieve(IdentityZone.getUaaZoneId())).thenReturn(zone(IdentityZone.getUaaZoneId(), mtlsEnabled));
    }

    private MtlsTrustBundleStartupValidator validator(boolean deploymentEnabled) {
        return new MtlsTrustBundleStartupValidator(deploymentEnabled, zones, clients);
    }

    private static IdentityZone zone(String id, boolean mtlsEnabled) {
        IdentityZone zone = IdentityZone.getUaaZoneId().equals(id) ? IdentityZone.getUaa() : new IdentityZone();
        zone.setId(id);
        zone.getConfig().getMtls().setEnabled(mtlsEnabled);
        return zone;
    }

    private static UaaClientDetails referencingClient() {
        UaaClientDetails client = new UaaClientDetails();
        client.setClientId("workload");
        client.addAdditionalInformation(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF, "removed");
        return client;
    }
}
