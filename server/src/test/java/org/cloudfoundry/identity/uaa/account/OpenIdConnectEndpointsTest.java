package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
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

    @Test
    void mtlsAdvertisementsAreConsistentWhenMtlsEnabled() throws Exception {
        // Guards against the two mTLS discovery gates (tokenAMR's tls_client_auth entry and
        // mtls_endpoint_aliases) ever drifting apart: whenever mTLS is enabled, a discovery client
        // must see BOTH tls_client_auth advertised AND the mtls_endpoint_aliases pointing at it --
        // never just one without the other, which would itself be a contradictory discovery document.
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("uaa.example.com");
        request.setServerPort(443);
        request.setContextPath("");

        OpenIdConfiguration conf = endpoints.getOpenIdConfiguration(request).getBody();

        assertThat(conf).isNotNull();
        assertThat(conf.getTokenAMR()).contains(ClientAuthentication.TLS_CLIENT_AUTH);
        assertThat(conf.getMtlsEndpointAliases()).isNotNull().containsKey("token_endpoint");
    }

    @Test
    void mtlsAdvertisementsAreConsistentWhenMtlsDisabled() throws Exception {
        OpenIdConnectEndpoints mtlsDisabledEndpoints =
                new OpenIdConnectEndpoints("https://uaa.example.com/oauth/token", mockIdentityZoneManager, false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/openid-configuration");
        request.setScheme("https");
        request.setServerName("uaa.example.com");
        request.setServerPort(443);
        request.setContextPath("");

        OpenIdConfiguration conf = mtlsDisabledEndpoints.getOpenIdConfiguration(request).getBody();

        assertThat(conf).isNotNull();
        assertThat(conf.getTokenAMR()).doesNotContain(ClientAuthentication.TLS_CLIENT_AUTH);
        assertThat(conf.getMtlsEndpointAliases()).isNull();
    }
}
