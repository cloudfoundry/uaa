package org.cloudfoundry.identity.uaa.mock;

import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;

public class EndpointDocs {

    @Autowired
    protected WebApplicationContext webApplicationContext;

    protected MockMvc mockMvc;
    protected TestClient testClient;

    @BeforeEach
    void setupWebMvc(ManualRestDocumentation manualRestDocumentation) {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .apply(documentationConfiguration(manualRestDocumentation)
                        .uris().withPort(80)
                        .and()
                        .snippets()
                        .withTemplateFormat(markdown()))
                .build();

        testClient = new TestClient(mockMvc);
    }
}
