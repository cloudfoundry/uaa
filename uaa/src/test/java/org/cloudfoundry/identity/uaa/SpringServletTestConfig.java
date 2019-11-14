package org.cloudfoundry.identity.uaa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

@Configuration
@ImportResource(locations = {"file:./src/main/webapp/WEB-INF/spring-servlet.xml"})
@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
public class SpringServletTestConfig {
    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }
}
