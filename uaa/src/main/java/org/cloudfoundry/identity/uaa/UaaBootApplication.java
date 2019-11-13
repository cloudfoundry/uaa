package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication(exclude = {
//        DispatcherServletAutoConfiguration.class,
        ErrorMvcAutoConfiguration.class,
//        WebMvcAutoConfiguration.class,
        SessionAutoConfiguration.class,
        SecurityAutoConfiguration.class
})
@EnableWebSecurity
public class UaaBootApplication extends SpringBootServletInitializer {

    public static void main(String... args) {
        new SpringApplicationBuilder(UaaBootApplication.class)
                .initializers(new YamlServletProfileInitializer())
                .run(args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder
                .sources(UaaBootApplication.class, UaaAuthorizationEndpoint.class)
                .initializers(new YamlServletProfileInitializer());
    }

    @Configuration
    @ImportResource({"/WEB-INF/spring-servlet.xml"})
    public static class XMLConfigs {

    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

}
