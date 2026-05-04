package org.cloudfoundry.identity.uaa.impl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.cfg.ConstructorDetector;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

@Configuration
public class JacksonMapperCustomizer implements WebMvcConfigurer {

    @Bean
    @Primary
    public JsonMapper jsonMapper() {
        return JsonMapper.builder()
                .enable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .constructorDetector(ConstructorDetector.DEFAULT.withAllowImplicitWithDefaultConstructor(false))
                .build();
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        JsonMapper mapper = jsonMapper();
        for (int i = 0; i < converters.size(); i++) {
            if (converters.get(i) instanceof JacksonJsonHttpMessageConverter) {
                converters.set(i, new JacksonJsonHttpMessageConverter(mapper));
                break;
            }
        }
    }
}
