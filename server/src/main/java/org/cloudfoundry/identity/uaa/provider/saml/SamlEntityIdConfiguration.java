package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SamlEntityIdConfiguration {

    @Value("${login.entityID:unit-test-sp}")
    private String samlEntityID;

    @Bean
    public String samlEntityID() {
        return samlEntityID;
    }
}