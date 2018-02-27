package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.joda.time.DateTimeUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Date;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest(IdentityZoneHolder.class)
public class TokenValidityResolverTest {

    private ClientDetailsService clientDetailsService;
    private TokenValidityResolver resolver;

    @Before
    public void setup() {
        int globalAccessTokenValiditySeconds = 120;

        DateTimeUtils.setCurrentMillisFixed(1000L);

        clientDetailsService = mock(ClientDetailsService.class);
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setAccessTokenValiditySeconds(100);
        when(clientDetailsService.loadClientByClientId("clientId")).thenReturn(clientDetails);
        resolver = new TokenValidityResolver(clientDetailsService, globalAccessTokenValiditySeconds);
    }

    @After
    public void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void whenClientValidityConfigured() {
        Date validity = resolver.resolveAccessTokenValidity("clientId");

        assertThat(validity.getTime(), is(101_000l));
    }

    @Test
    public void whenClientValidityNotConfigured_fallsBackToZoneConfiguration() {
        PowerMockito.mockStatic(IdentityZoneHolder.class);
        IdentityZone zone = new IdentityZone();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(50);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(IdentityZoneHolder.get()).thenReturn(zone);

        when(clientDetailsService.loadClientByClientId("clientId")).thenReturn(new BaseClientDetails());

        Date validity = resolver.resolveAccessTokenValidity("clientId");

        assertThat(validity.getTime(), is(51_000l));
    }

    @Test
    public void whenClientIdNotFound_defaultsToZoneConfiguration() {
        PowerMockito.mockStatic(IdentityZoneHolder.class);
        IdentityZone zone = new IdentityZone();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(50);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(IdentityZoneHolder.get()).thenReturn(zone);

        when(clientDetailsService.loadClientByClientId("clientId")).thenThrow(ClientRegistrationException.class);

        Date validity = resolver.resolveAccessTokenValidity("clientId");

        assertThat(validity.getTime(), is(51_000l));
    }

    @Test
    public void whenZoneValidityNotConfigured_fallsBackToGlobalPolicy() {
        PowerMockito.mockStatic(IdentityZoneHolder.class);
        IdentityZone zone = new IdentityZone();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(-1);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(IdentityZoneHolder.get()).thenReturn(zone);

        when(clientDetailsService.loadClientByClientId("clientId")).thenReturn(new BaseClientDetails());

        Date validity = resolver.resolveAccessTokenValidity("clientId");

        assertThat(validity.getTime(), is(121_000l));
    }
}