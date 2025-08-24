package org.cloudfoundry.identity.uaa.web;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.authentication.manager.AutologinRequestConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import java.util.List;

/**
 * Web stack configuration. It relies on Spring Boot's {@link WebMvcAutoConfiguration},
 * with a few adjustments in a properties file to match the legacy behavior from UAA.
 */
@Configuration
@EnableWebMvc
@PropertySource("classpath:spring-mvc.properties")
class WebConfig implements WebMvcConfigurer {

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new AutologinRequestConverter());
    }

    @Autowired
    private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

    @PostConstruct
    public void init() {
        requestMappingHandlerAdapter.setIgnoreDefaultModelOnRedirect(false);
    }
}
