package org.cloudfoundry.identity.uaa.impl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.cfg.ConstructorDetector;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class JacksonMapperCustomizer {

    @Bean
    @Primary
    public JsonMapper jsonMapper() {
        return JsonMapper.builder()
                .enable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                // Jackson 3 flipped this default to true; UAA payloads historically
                // tolerate missing primitive fields (e.g. counters defaulting to 0),
                // so keep the lenient Jackson 2 behavior to avoid breaking clients.
                .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .constructorDetector(ConstructorDetector.DEFAULT.withAllowImplicitWithDefaultConstructor(false))
                .build();
    }


}
