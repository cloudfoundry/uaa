package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExternalOAuthAuthenticationManagerTrustCacheTest {
    private RestTemplate trustingRestTemplate;
    private RestTemplate nonTrustingRestTemplate;
    private IdpOutboundTrustCache trustCache;
    private ExternalOAuthAuthenticationManager authManager;

    @BeforeEach
    void setup() {
        trustingRestTemplate = mock(RestTemplate.class);
        nonTrustingRestTemplate = mock(RestTemplate.class);
        trustCache = mock(IdpOutboundTrustCache.class);
        authManager = new ExternalOAuthAuthenticationManager(
                mock(IdentityProviderProvisioning.class),
                mock(IdentityZoneManager.class),
                trustingRestTemplate,
                nonTrustingRestTemplate,
                mock(TokenEndpointBuilder.class),
                new KeyInfoService("http://uaa.example.com"),
                mock(OidcMetadataFetcher.class),
                false,
                trustCache,
                RestTemplateConfig.createDefaults()
        );
    }

    @Test
    void getRestTemplate_delegatesToTrustCacheWithIdentityProviderIdAndCaCertificates() {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setCaCertificates(List.of("cert-pem"));
        config.setSkipSslValidation(false);
        IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("idp-id-1");
        idp.setConfig(config);

        RestTemplate expected = mock(RestTemplate.class);
        when(trustCache.resolveRestTemplate(eq("idp-id-1"), eq(config.getCaCertificates()), eq(false),
                anyInt(), anyInt(), any(), eq(trustingRestTemplate), eq(nonTrustingRestTemplate)))
                .thenReturn(expected);

        assertThat(authManager.getRestTemplate(idp)).isSameAs(expected);
    }

    @Test
    void getRestTemplate_noCaCertificates_stillRoutesThroughTrustCacheForFallback() {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("idp-id-2");
        idp.setConfig(config);

        when(trustCache.resolveRestTemplate(eq("idp-id-2"), isNull(), eq(false),
                anyInt(), anyInt(), any(), eq(trustingRestTemplate), eq(nonTrustingRestTemplate)))
                .thenReturn(nonTrustingRestTemplate);

        assertThat(authManager.getRestTemplate(idp)).isSameAs(nonTrustingRestTemplate);
    }

    @Test
    void getRestTemplate_skipSslValidationTrue_stillDelegatesPrecedenceToTrustCache() {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setCaCertificates(List.of("cert-pem"));
        config.setSkipSslValidation(true);
        IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setId("idp-id-3");
        idp.setConfig(config);

        when(trustCache.resolveRestTemplate(eq("idp-id-3"), eq(config.getCaCertificates()), eq(true),
                anyInt(), anyInt(), any(), eq(trustingRestTemplate), eq(nonTrustingRestTemplate)))
                .thenReturn(trustingRestTemplate);

        assertThat(authManager.getRestTemplate(idp)).isSameAs(trustingRestTemplate);
    }
}
