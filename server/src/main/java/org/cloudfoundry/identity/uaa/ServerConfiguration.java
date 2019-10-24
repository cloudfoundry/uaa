package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.cypto.EncryptionProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(EncryptionProperties.class)
public class ServerConfiguration {
}
