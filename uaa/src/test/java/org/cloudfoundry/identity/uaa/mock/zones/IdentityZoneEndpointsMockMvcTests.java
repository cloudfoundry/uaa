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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
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
        IdentityZone identityZone = getIdentityZone("mysubdomain");
        String id = UUID.randomUUID().toString();

        mockMvc.perform(put("/identity-zones/" + id)
                                    .contentType(APPLICATION_JSON)
                                    .content(new ObjectMapper().writeValueAsString(identityZone)))
                                    .andExpect(status().isCreated())
                                    .andExpect(content().string(""))
                                    .andReturn();

    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubDomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        String id = UUID.randomUUID().toString();

        mockMvc.perform(put("/identity-zones/" + id)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(identityZone)))
            .andExpect(status().isBadRequest());
    }
    
    // update a zone with a subdomain that already exists
    // update a zone in place  with different data (happy)
    // update a zone with exactly the same data (happy)

    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubDomain("other-subdomain");
        identityZone.setName("The Twiglet Zone 2");

        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isCreated());

        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isConflict());
    }
    
}
