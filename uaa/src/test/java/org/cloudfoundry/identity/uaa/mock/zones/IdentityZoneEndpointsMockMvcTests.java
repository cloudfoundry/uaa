package org.cloudfoundry.identity.uaa.mock.zones;


import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneEndpointsMockMvcTests {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;

    @BeforeClass
    public static void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean(FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
            .build();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        webApplicationContext.close();
    }

    @Test
    public void testCreateZone() throws Exception {
        IdentityZone identityZone = getIdentityZone(UUID.randomUUID().toString());

        MvcResult result = mockMvc.perform(post("/identity-zones")
                                            .contentType(APPLICATION_JSON)
                                            .accept(APPLICATION_JSON)
                                            .content(new ObjectMapper().writeValueAsString(identityZone)))
                                    .andExpect(status().isCreated())
                                    .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                                    .andReturn();

        IdentityZone createdIdentityZone = new ObjectMapper().readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        assertEquals(identityZone.getServiceInstanceId(), createdIdentityZone.getServiceInstanceId());
        assertEquals(identityZone.getSubDomain(), createdIdentityZone.getSubDomain());
        assertEquals(identityZone.getName(), createdIdentityZone.getName());
        assertEquals(identityZone.getDescription(), createdIdentityZone.getDescription());
        UUID.fromString(createdIdentityZone.getId());
    }

    private IdentityZone getIdentityZone(String salt) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubDomain("subdomain-" + salt);
        identityZone.setServiceInstanceId("a-service-instance-id");
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();

        mockMvc.perform(post("/identity-zones")
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(identityZone)))
        .andExpect(status().isBadRequest());
    }

    @Test
    public void testCreateDuplicateZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubDomain("other-subdomain");
        identityZone.setName("The Twiglet Zone 2");

        mockMvc.perform(post("/identity-zones")
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                  .andExpect(status().isCreated());

        mockMvc.perform(post("/identity-zones")
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                  .andExpect(status().isConflict());
    }
}
