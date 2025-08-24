package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
class SessionControllerMockMvcTests {
    private MockMvc mockMvc;

    @BeforeEach
    void setUp(@Autowired MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void sessionEndpointWhichSupportsLegacyUaaSingular() throws Exception {
        mockMvc.perform(get("/session")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(view().name("session"));
    }

    @Test
    void sessionManagementEndpointWhichSupportsUaaSingular() throws Exception {
        mockMvc.perform(get("/session_management")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(view().name("session_management"));
    }
}
