package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.security.IdpOutboundTrustCache;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {
    @Value("${rest.template.timeout:10000}")
    public int timeout;

    @Value("${rest.template.maxTotal:10}")
    public int maxTotal;

    @Value("${rest.template.maxPerRoute:5}")
    public int maxPerRoute;

    @Value("${rest.template.maxKeepAlive:0}")
    public int maxKeepAlive;

    @Value("${rest.template.validateAfterInactivity:2000}")
    public int validateAfterInactivity;

    @Value("${rest.template.retryCount:0}")
    public int retryCount;

    @Bean
    public RestTemplate nonTrustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false, timeout, timeout, this));
    }

    @Bean
    public RestTemplate trustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(true, timeout, timeout, this));
    }

    @Bean
    public RestTemplate safeRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createSafeRequestFactory(this));
    }

    /**
     * Shared, per-IdP outbound TLS trust cache -- consumed by OIDC/OAuth2, SAML, and LDAP connectors
     * (as each is wired in) so a per-IdP caCertificates config builds trust material once and reuses it,
     * rather than every consumer building its own.
     */
    @Bean
    public IdpOutboundTrustCache idpOutboundTrustCache() {
        return new IdpOutboundTrustCache();
    }


    public static RestTemplateConfig createDefaults() {
        RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
        restTemplateConfig.timeout = 10000;
        restTemplateConfig.maxTotal = 10;
        restTemplateConfig.maxPerRoute = 5;
        restTemplateConfig.maxKeepAlive = 0;
        restTemplateConfig.validateAfterInactivity = 2000;
        restTemplateConfig.retryCount = 0;
        return restTemplateConfig;
    }
}
