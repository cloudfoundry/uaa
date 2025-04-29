package org.cloudfoundry.identity.uaa;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebMvc
@EnableAutoConfiguration
@ComponentScan(basePackages = "org.cloudfoundry.identity.uaa")
public class UaaApplicationConfiguration {

}
