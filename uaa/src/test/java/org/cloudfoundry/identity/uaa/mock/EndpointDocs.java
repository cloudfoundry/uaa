package org.cloudfoundry.identity.uaa.mock;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;

@ExtendWith(JUnitRestDocumentationExtension.class)
@DefaultTestContext
public class EndpointDocs {

    @Autowired
    protected WebApplicationContext webApplicationContext;

    @Autowired
    protected IdentityZoneManager identityZoneManager;

    protected MockMvc mockMvc;
    protected TestClient testClient;

    @BeforeEach
    void setupWebMvc(ManualRestDocumentation manualRestDocumentation) {
        FilterChainProxy securityFilterChain = webApplicationContext.getBean(SPRING_SECURITY_FILTER_CHAIN, FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(securityFilterChain)
                .apply(documentationConfiguration(manualRestDocumentation)
                        .uris().withPort(80)
                        .and()
                        .snippets()
                        .withTemplateFormat(markdown()))
                .build();

        testClient = new TestClient(mockMvc);
    }
}
