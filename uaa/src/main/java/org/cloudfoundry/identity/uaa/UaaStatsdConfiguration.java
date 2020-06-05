package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.statsd.StatsdConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(StatsdConfiguration.class)
@ConditionalOnProperty(name = "statsd.enabled", havingValue = "true")
public class UaaStatsdConfiguration {
}
