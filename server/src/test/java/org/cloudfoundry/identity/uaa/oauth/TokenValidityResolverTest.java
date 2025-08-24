package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenValidityResolverTest {

    private TokenValidityResolver resolver;
    private ClientTokenValidity clientTokenValidity;

    @BeforeEach
    void setup() {
        int globalAccessTokenValiditySeconds = 120;

        clientTokenValidity = mock(ClientTokenValidity.class);
        TimeService timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        when(clientTokenValidity.getValiditySeconds("clientId")).thenReturn(100);

        resolver = new TokenValidityResolver(clientTokenValidity, globalAccessTokenValiditySeconds, timeService);
    }

    @Test
    void whenClientValidityConfigured() {
        Date validity = resolver.resolve("clientId");

        assertThat(validity.getTime()).isEqualTo(101_000l);
    }

    @Test
    void whenClientValidityNotConfigured_fallsBackToZoneConfiguration() {
        when(clientTokenValidity.getZoneValiditySeconds()).thenReturn(50);
        when(clientTokenValidity.getValiditySeconds("clientId")).thenReturn(null);

        Date validity = resolver.resolve("clientId");

        assertThat(validity.getTime()).isEqualTo(51_000l);
    }

    @Test
    void whenZoneValidityNotConfigured_fallsBackToGlobalPolicy() {
        when(clientTokenValidity.getZoneValiditySeconds()).thenReturn(-1);
        when(clientTokenValidity.getValiditySeconds("clientId")).thenReturn(null);

        Date validity = resolver.resolve("clientId");

        assertThat(validity.getTime()).isEqualTo(121_000l);
    }

}