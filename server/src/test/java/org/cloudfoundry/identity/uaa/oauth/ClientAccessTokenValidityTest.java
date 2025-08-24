package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientAccessTokenValidityTest {

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(MockitoExtension.class)
    class GetValiditySeconds {

        @Mock
        private MultitenantClientServices mockMultitenantClientServices;

        @Mock
        private IdentityZoneManager mockIdentityZoneManager;

        @InjectMocks
        private ClientAccessTokenValidity clientAccessTokenValidity;

        @Mock
        private ClientDetails mockClientDetails;

        private String currentIdentityZoneId;

        @BeforeEach
        void setUp() {
            currentIdentityZoneId = "currentIdentityZoneId-" + new AlphanumericRandomValueStringGenerator().generate();
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        }

        @Test
        void whenClientPresent() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId)).thenReturn(mockClientDetails);
            when(mockClientDetails.getAccessTokenValiditySeconds()).thenReturn(9999);

            assertThat(clientAccessTokenValidity.getValiditySeconds("clientId")).isEqualTo(9999);
        }

        @Test
        void whenClientPresent_doesNotHaveATokenValiditySet() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId)).thenReturn(mockClientDetails);
            when(mockClientDetails.getAccessTokenValiditySeconds()).thenReturn(null);

            assertThat(clientAccessTokenValidity.getValiditySeconds("clientId")).isNull();
        }

        @Test
        void whenNoClientPresent_ReturnsNull() {
            when(mockMultitenantClientServices.loadClientByClientId("notExistingClientId", currentIdentityZoneId))
                    .thenThrow(ClientRegistrationException.class);

            assertThat(clientAccessTokenValidity.getValiditySeconds("notExistingClientId")).isNull();
        }

        @Test
        void whenClientPresent_ButUnableToRetrieveTheClient() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId))
                    .thenThrow(RuntimeException.class);

            assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> clientAccessTokenValidity.getValiditySeconds("clientId"));
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(MockitoExtension.class)
    class GetZoneValiditySeconds {
        @Mock
        private IdentityZoneManager mockIdentityZoneManager;

        @InjectMocks
        private ClientAccessTokenValidity clientAccessTokenValidity;

        @ParameterizedTest
        @ValueSource(ints = {
                0,
                -1,
                97531
        })
        void zoneValidityReturnsAccessTokenValidity(final int zoneValiditySeconds) {
            IdentityZone mockIdentityZone = mock(IdentityZone.class);
            IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
            TokenPolicy mockTokenPolicy = mock(TokenPolicy.class);

            when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
            when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
            when(mockIdentityZoneConfiguration.getTokenPolicy()).thenReturn(mockTokenPolicy);
            when(mockTokenPolicy.getAccessTokenValidity()).thenReturn(zoneValiditySeconds);

            assertThat(clientAccessTokenValidity.getZoneValiditySeconds()).isEqualTo(zoneValiditySeconds);
        }
    }
}