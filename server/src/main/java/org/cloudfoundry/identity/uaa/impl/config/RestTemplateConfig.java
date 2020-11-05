package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {
    @Value("${rest.template.timeout:10000}")
    public int timeout;

    @Value("${rest.template.maxTotal:20}")
    public int maxTotal;

    @Value("${rest.template.maxPerRoute:2}")
    public int maxPerRoute;

    @Value("${rest.template.maxKeepAlive:0}")
    public int maxKeepAlive;

    @Bean
    public RestTemplate nonTrustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false, timeout, maxTotal, maxPerRoute, maxKeepAlive));
    }

    @Bean
    public RestTemplate trustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(true, timeout, maxTotal, maxPerRoute, maxKeepAlive));
    }
}
