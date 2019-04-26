package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(IdentityZoneHolder.class)
public class ClientRefreshTokenValidityTest {
    ClientRefreshTokenValidity clientRefreshTokenValidity;
    ClientDetails clientDetails;
    ClientServicesExtension clientServicesExtension;
    private IdentityZone defaultZone;

    @Before
    public void setUp() {
        clientServicesExtension = mock(ClientServicesExtension.class);

        clientDetails = mock(ClientDetails.class);
        when(clientDetails.getRefreshTokenValiditySeconds()).thenReturn(42);

        defaultZone = IdentityZone.getUaa();
        PowerMockito.mockStatic(IdentityZoneHolder.class);
        when(IdentityZoneHolder.get()).thenReturn(defaultZone);

        when(clientServicesExtension.loadClientByClientId("clientId", "uaa")).thenReturn(clientDetails);
        clientRefreshTokenValidity = new ClientRefreshTokenValidity(clientServicesExtension);
    }

    @Test
    public void testRefreshClientValidity_whenClientPresent() {
        assertThat(clientRefreshTokenValidity.getValiditySeconds("clientId"), is(42));
    }

    @Test
    public void testRefreshClientValidity_whenClientPresentInADifferentZone() {
        IdentityZone notUaa = new IdentityZone();
        notUaa.setId("uaa_not");
        clientDetails = mock(ClientDetails.class);
        when(IdentityZoneHolder.get()).thenReturn(notUaa);
        when(clientDetails.getRefreshTokenValiditySeconds()).thenReturn(24);
        when(clientServicesExtension.loadClientByClientId("clientId", "uaa_not")).thenReturn(clientDetails);

        Integer validitySeconds = clientRefreshTokenValidity.getValiditySeconds("clientId");

        assertThat(validitySeconds, is(24));
    }

    @Test
    public void testRefreshClientValidity_whenClientPresent_doesNotHaveARefreshTokenValiditySet() {
        when(clientDetails.getRefreshTokenValiditySeconds()).thenReturn(null);
        assertThat(clientRefreshTokenValidity.getValiditySeconds("clientId"), is(nullValue()));
    }

    @Test
    public void testRefreshClientValidity_whenNoClientPresent_ReturnsNull() {
        when(clientServicesExtension.loadClientByClientId("notExistingClientId", "uaa")).thenThrow(ClientRegistrationException.class);
        assertThat(clientRefreshTokenValidity.getValiditySeconds("notExistingClientId"), is(nullValue()));
    }

    @Test(expected = RuntimeException.class)
    public void testRefreshClientValidity_whenClientPresent_ButUnableToRetrieveTheClient() {
        when(clientServicesExtension.loadClientByClientId("clientId", "uaa")).thenThrow(RuntimeException.class);
        clientRefreshTokenValidity.getValiditySeconds("clientId");
    }


    @Test
    public void testZoneValidityReturnsAccessTokenValidity() {
        assertThat(clientRefreshTokenValidity.getZoneValiditySeconds(), is(-1));
    }

    @Test
    public void testZoneValidityReturnsCorrectAccessTokenValidity() {
        defaultZone.getConfig().getTokenPolicy().setRefreshTokenValidity(1);

        assertThat(clientRefreshTokenValidity.getZoneValiditySeconds(), is(1));
    }
}