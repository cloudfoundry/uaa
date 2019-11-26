package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.RequestContextFilter;

import javax.servlet.DispatcherType;

@SpringBootApplication(exclude = {WebMvcAutoConfiguration.class, SecurityAutoConfiguration.class})
@EnableWebSecurity
public class UaaBootApplication extends SpringBootServletInitializer {
    public static void main(String... args) {
        new SpringApplicationBuilder(UaaBootApplication.class)
                .initializers(new YamlServletProfileInitializer())
                .run(args);
    }

    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application
            .sources(UaaBootApplication.class)
            .initializers(new YamlServletProfileInitializer());
    }

    @Bean
    static DisableSpringUaaSpringSecurityFilterRegistrationBean fixIt() {
        return new DisableSpringUaaSpringSecurityFilterRegistrationBean();
    }

    @Configuration
    @ImportResource({"file:**/WEB-INF/spring-servlet.xml"})
    public static class WebInfSpringServletConfiguration {
    }
}

