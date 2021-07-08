package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
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
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientRefreshTokenValidityTest {

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(MockitoExtension.class)
    class GetValiditySeconds {

        @Mock
        private MultitenantClientServices mockMultitenantClientServices;

        @Mock
        private IdentityZoneManager mockIdentityZoneManager;

        @InjectMocks
        private ClientRefreshTokenValidity clientRefreshTokenValidity;

        @Mock
        private ClientDetails mockClientDetails;

        private String currentIdentityZoneId;

        @BeforeEach
        void setUp() {
            currentIdentityZoneId = "currentIdentityZoneId-" + new RandomValueStringGenerator().generate();
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        }

        @Test
        void whenClientPresent() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId)).thenReturn(mockClientDetails);
            when(mockClientDetails.getRefreshTokenValiditySeconds()).thenReturn(9999);

            assertThat(clientRefreshTokenValidity.getValiditySeconds("clientId"), is(9999));
        }

        @Test
        void whenClientPresent_doesNotHaveATokenValiditySet() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId)).thenReturn(mockClientDetails);
            when(mockClientDetails.getRefreshTokenValiditySeconds()).thenReturn(null);

            assertThat(clientRefreshTokenValidity.getValiditySeconds("clientId"), is(nullValue()));
        }

        @Test
        void whenNoClientPresent_ReturnsNull() {
            when(mockMultitenantClientServices.loadClientByClientId("notExistingClientId", currentIdentityZoneId))
                    .thenThrow(ClientRegistrationException.class);

            assertThat(clientRefreshTokenValidity.getValiditySeconds("notExistingClientId"), is(nullValue()));
        }

        @Test
        void whenClientPresent_ButUnableToRetrieveTheClient() {
            when(mockMultitenantClientServices.loadClientByClientId("clientId", currentIdentityZoneId))
                    .thenThrow(RuntimeException.class);

            assertThrows(RuntimeException.class,
                    () -> clientRefreshTokenValidity.getValiditySeconds("clientId"));
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(MockitoExtension.class)
    class GetZoneValiditySeconds {
        @Mock
        private IdentityZoneManager mockIdentityZoneManager;

        @InjectMocks
        private ClientRefreshTokenValidity clientRefreshTokenValidity;

        @ParameterizedTest
        @ValueSource(ints = {
                0,
                -1,
                97531
        })
        void zoneValidityReturnsRefreshTokenValidity(final int zoneValiditySeconds) {
            IdentityZone mockIdentityZone = mock(IdentityZone.class);
            IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
            TokenPolicy mockTokenPolicy = mock(TokenPolicy.class);

            when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
            when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
            when(mockIdentityZoneConfiguration.getTokenPolicy()).thenReturn(mockTokenPolicy);
            when(mockTokenPolicy.getRefreshTokenValidity()).thenReturn(zoneValiditySeconds);

            assertThat(clientRefreshTokenValidity.getZoneValiditySeconds(), is(zoneValiditySeconds));
        }
    }
}