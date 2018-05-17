package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate nonTrustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false, 30_000));
    }

    @Bean
    public RestTemplate trustingRestTemplate() {
        return new RestTemplate(UaaHttpRequestUtils.createRequestFactory(true, 30_000));
    }
}
