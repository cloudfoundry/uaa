package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.test.TestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@Configuration
public class TestClientAndMockMvcTestConfig {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") FilterChainProxy springSecurityFilterChain
    ) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Bean
    public TestClient testClient(
            MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }
}
