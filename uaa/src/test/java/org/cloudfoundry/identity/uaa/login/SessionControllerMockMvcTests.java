package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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

    /**
     * The /session and /session_management endpoints are loaded by the uaa-singular library
     * inside a cross-origin iframe (opFrame) to implement OIDC session management via postMessage.
     * Browsers refuse to render pages in iframes when X-Frame-Options: DENY is set, which would
     * prevent the logout callback from ever firing. These endpoints must not send that header.
     *
     * Regression: introduced by the Spring Boot 3.4.6 upgrade (9954ddaba) which accidentally
     * changed frameOptions().disable() to frameOptions(withDefaults()) — the latter means DENY.
     */
    @Test
    void sessionEndpointMustNotSendXFrameOptionsDeny() throws Exception {
        mockMvc.perform(get("/session")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-Frame-Options"));
    }

    @Test
    void sessionManagementEndpointMustNotSendXFrameOptionsDeny() throws Exception {
        mockMvc.perform(get("/session_management")
                        .param("clientId", "1")
                        .param("messageOrigin", "origin"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-Frame-Options"));
    }
}
