package org.cloudfoundry.identity.uaa.alias;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AliasEntitiesConfig {
    @Bean
    public boolean aliasEntitiesEnabled(@Value("${login.aliasEntitiesEnabled:false}") final boolean enabled) {
        return enabled;
    }
}
