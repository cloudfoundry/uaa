package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
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

    @Configuration
    @ImportResource({"classpath*:spring-servlet.xml"})
    public static class XMLConfigs {
    }
}

