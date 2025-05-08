package org.cloudfoundry.identity.uaa;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.util.Set;

@Configuration
@ConfigurationProperties
@EnableConfigurationProperties({LimitedModeProperties.class, LimitedModeProperties.Permitted.class})
public class LimitedModeProperties {

    @Value("${uaa.limitedFunctionality.statusFile:#{null}}")
    File statusFile;

    @Autowired
    Permitted permitted;

    @ConfigurationProperties(prefix = "uaa.limitedfunctionality.whitelist")
    record Permitted(
        @DefaultValue({}) Set<String> endpoints,
        @DefaultValue({}) Set<String> methods
    ) {}

}


