package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        SpringServletTestConfig.class,
        TestClientAndMockMvcTestConfig.class,
})
public @interface DefaultTestContext {
}

@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
@ComponentScan(excludeFilters = {
        @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = WebConfiguration.class),
})
class SpringServletTestConfig {
    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }
}

class TestClientAndMockMvcTestConfig {
    @Bean
    public MockMvc mockMvc(
            final WebApplicationContext webApplicationContext,
            @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") FilterChainProxy springSecurityFilterChain
    ) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Bean
    public TestClient testClient(
            final MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }
}
