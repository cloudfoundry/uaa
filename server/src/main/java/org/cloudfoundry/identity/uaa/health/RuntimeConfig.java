package org.cloudfoundry.identity.uaa.health;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RuntimeConfig {
    @Bean
    public Runtime runtime() {
        return Runtime.getRuntime();
    }
}
