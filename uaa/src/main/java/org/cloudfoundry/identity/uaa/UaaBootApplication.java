package org.cloudfoundry.identity.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@SpringBootApplication
@EnableWebSecurity
public class UaaBootApplication {
    public static void main(String... args) {
        SpringApplication.run(UaaBootApplication.class, args);
    }

}

