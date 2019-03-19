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
    void legacy_sessionControllerReturnsSessionView() throws Exception {
        mockMvc.perform(get("/session")
                .param("clientId", "1")
                .param("messageOrigin", "origin"))
                .andExpect(view().name("session"))
                .andExpect(status().isOk());
    }

    @Test
    void sessionManagement_ReturnsSessionManagementView() throws Exception {
        mockMvc.perform(get("/session_management")
                .param("clientId", "1")
                .param("messageOrigin", "origin"))
                .andExpect(view().name("session_management"))
                .andExpect(status().isOk());
    }
}
