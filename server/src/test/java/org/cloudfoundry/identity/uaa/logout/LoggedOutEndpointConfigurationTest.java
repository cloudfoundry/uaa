package org.cloudfoundry.identity.uaa.logout;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = LoggedOutEndpointConfigurationTest.ContextConfiguration.class)
@TestPropertySource(properties = {
        "logged_out.message=Custom test message from properties",
        "logged_out.link_text=Custom test link text",
        "logged_out.link_url=http://test.example.com/login"
})
class LoggedOutEndpointConfigurationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Test
    void loggedOutEndpoint_shouldUseConfigurationProperties() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        mockMvc.perform(get("/logged_out"))
                .andExpect(status().isOk())
                .andExpect(view().name("logged_out"))
                .andExpect(model().attribute("message", "Custom test message from properties"))
                .andExpect(model().attribute("linkText", "Custom test link text"))
                .andExpect(model().attribute("linkUrl", "http://test.example.com/login"));
    }

    @EnableWebMvc
    @Import({ThymeleafConfig.class, LoggedOutEndpoint.class})
    static class ContextConfiguration {
        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
        }
    }
}

@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = LoggedOutEndpointDefaultConfigurationTest.ContextConfiguration.class)
class LoggedOutEndpointDefaultConfigurationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Test
    void loggedOutEndpoint_shouldUseDefaultValuesWhenPropertiesNotSet() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        mockMvc.perform(get("/logged_out"))
                .andExpect(status().isOk())
                .andExpect(view().name("logged_out"))
                .andExpect(model().attribute("message", "You have successfully logged out."))
                .andExpect(model().attribute("linkText", "Back to Sign In"))
                .andExpect(model().attribute("linkUrl", "/login"));
    }

    @EnableWebMvc
    @Import({ThymeleafConfig.class, LoggedOutEndpoint.class})
    static class ContextConfiguration {
        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
        }
    }
}