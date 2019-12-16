package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.SpringServletTestConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER;
import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = SpringServletTestConfig.class)
public class XFrameOptionsTheories {
    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;

    @Before
    public void setup() {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Test
    public void responsesHaveXFrameOptionsHeaderHtml() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.TEXT_HTML);
        mockMvc.perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }

    @Test
    public void responsesHaveXFrameOptionsHeaderJson() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.APPLICATION_JSON);
        mockMvc.perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }
}
