package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OpenIdConnectEndpointsTest {

    private OpenIdConnectEndpoints endpoints;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setUp() {
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(IdentityZone.getUaa());
        endpoints = new OpenIdConnectEndpoints("https://uaa.example.com/oauth/token", mockIdentityZoneManager, true);
    }

    @Test
    void mtlsEndpointAliasesIsPopulatedInDiscovery() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("uaa.example.com");
        request.setServerPort(443);
        request.setContextPath("");

        ResponseEntity<OpenIdConfiguration> response = endpoints.getOpenIdConfiguration(request);

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMtlsEndpointAliases())
                .isNotNull()
                .containsKey("token_endpoint");
        assertThat(response.getBody().getMtlsEndpointAliases().get("token_endpoint"))
                .endsWith("/oauth/mtls/token");
    }

    @Test
    void mtlsEndpointAliasesIsAbsentWhenMtlsDisabled() throws Exception {
        OpenIdConnectEndpoints mtlsDisabledEndpoints =
                new OpenIdConnectEndpoints("https://uaa.example.com/oauth/token", mockIdentityZoneManager, false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("uaa.example.com");
        request.setServerPort(443);
        request.setContextPath("");

        ResponseEntity<OpenIdConfiguration> response = mtlsDisabledEndpoints.getOpenIdConfiguration(request);

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMtlsEndpointAliases()).isNull();
    }
}
