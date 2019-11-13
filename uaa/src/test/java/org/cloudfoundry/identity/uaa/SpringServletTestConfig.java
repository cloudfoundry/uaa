package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.cypto.EncryptionKeyService;
import org.cloudfoundry.identity.uaa.cypto.EncryptionProperties;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import java.util.List;

@Configuration
@ImportResource(locations = {"classpath*:spring-servlet.xml"})
@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
@ComponentScan(
        basePackageClasses = {
                UaaAuthorizationEndpoint.class,
                ScimGroupEndpoints.class,
                UaaTokenEndpoint.class
        }
)
public class SpringServletTestConfig {

    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean
    public EncryptionProperties encryptionProperties(
            final @Value("${encryption.active_key_label}") String activeKeyLabel,
            final @Value("#{@config['encryption']['encryption_keys']}") List<EncryptionKeyService.EncryptionKey> encryptionKeys) {

        return new EncryptionProperties(activeKeyLabel, encryptionKeys);
    }
}
