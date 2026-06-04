package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.authentication.manager.AutologinRequestConverter;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

@Configuration
@EnableWebMvc
class WebConfig implements WebMvcConfigurer {

    private final JsonMapper jsonMapper;

    WebConfig(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        // @EnableWebMvc disables Boot's auto-config, so the default JacksonJsonHttpMessageConverter
        // is built with stock Jackson 3 settings — replace it with one that uses UAA's JsonMapper
        // (lenient FAIL_ON_NULL_FOR_PRIMITIVES, stable property order, etc.).
        for (int i = 0; i < converters.size(); i++) {
            if (converters.get(i) instanceof JacksonJsonHttpMessageConverter) {
                converters.set(i, new JacksonJsonHttpMessageConverter(jsonMapper));
                break;
            }
        }
        converters.add(new AutologinRequestConverter());
    }
}
