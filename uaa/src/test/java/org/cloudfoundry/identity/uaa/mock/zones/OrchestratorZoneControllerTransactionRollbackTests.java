package org.cloudfoundry.identity.uaa.mock.zones;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.cloudfoundry.identity.uaa.NestedMapPropertySourceFactory;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = OrchestratorZoneTestConfiguration.class)
public class OrchestratorZoneControllerTransactionRollbackTests {

    private static final String ZONE_NAME = "The Twiglet Zone";
    private static final String SUB_DOMAIN_NAME = "sub-domain-01";
    private static final String ADMIN_CLIENT_SECRET = "admin-secret-01";

    private MockMvc mockMvc;
    private ApplicationContext applicationContext;

    @BeforeEach
    void setUp(@Autowired MockMvc mockMvc, @Autowired ApplicationContext applicationContext) {
        this.mockMvc = mockMvc;
        this.applicationContext = applicationContext;
    }

    @Test
    void testCreateZone_TransactionRollBack() throws Exception {

        BeanDefinitionRegistry registry = null;
        BeanDefinition originalBeanDefinition = null;
        try {
            AutowireCapableBeanFactory factory = applicationContext.getAutowireCapableBeanFactory();
            registry = (BeanDefinitionRegistry) factory;
            originalBeanDefinition = registry.getBeanDefinition("identityProviderProvisioning");

            GenericBeanDefinition genericBeanDefinition = new GenericBeanDefinition();
            genericBeanDefinition.setBeanClass(MockIdentityProviderProvisioning.class);
            registry.removeBeanDefinition("identityProviderProvisioning");

            registry.registerBeanDefinition("identityProviderProvisioning", genericBeanDefinition);

            OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                                         SUB_DOMAIN_NAME);

            MvcResult result = mockMvc.perform(post("/orchestrator/zones").contentType(APPLICATION_JSON).content(
                JsonUtils.writeValueAsString(orchestratorZoneRequest))).andReturn();

            processZoneAPI(get("/orchestrator/zones"), ZONE_NAME, status().isNotFound());
        } finally {
            assertNotNull(originalBeanDefinition);
            registry.removeBeanDefinition("identityProviderProvisioning");
            registry.registerBeanDefinition("identityProviderProvisioning", originalBeanDefinition);
        }
    }

    private OrchestratorZoneResponse processZoneAPI(MockHttpServletRequestBuilder mockRequestBuilder,
                                                    String nameParameter, ResultMatcher expectedStatus)
        throws Exception {
        MvcResult result =
            mockMvc.perform(mockRequestBuilder.param("name", nameParameter)).andExpect(expectedStatus).andReturn();
        if (StringUtils.hasLength(result.getResponse().getContentAsString()) &&
            result.getResponse().getStatus() == 200) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), OrchestratorZoneResponse.class);
        } else {
            return null;
        }
    }

    private OrchestratorZoneRequest getOrchestratorZoneRequest(String name, String adminClientSecret,
                                                               String subdomain) {
        OrchestratorZone orchestratorZone = new OrchestratorZone(adminClientSecret, subdomain);
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(name);
        orchestratorZoneRequest.setParameters(orchestratorZone);
        return orchestratorZoneRequest;
    }
}

@ImportResource(locations = { "file:./src/main/webapp/WEB-INF/spring-servlet.xml" })
@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
class OrchestratorZoneTestConfiguration {

    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean
    public MockMvc mockMvc(WebApplicationContext webApplicationContext) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }
}
