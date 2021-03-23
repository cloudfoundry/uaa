package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER;
import static org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

@DefaultTestContext
class XFrameOptionsTheories {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void responsesHaveXFrameOptionsHeaderHtml() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.TEXT_HTML);
        mockMvc.perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }

    @Test
    void responsesHaveXFrameOptionsHeaderJson() throws Exception {
        RequestBuilder request = MockMvcRequestBuilders.get("/login").accept(MediaType.APPLICATION_JSON);
        mockMvc.perform(request).andExpect(header().string(XFRAME_OPTIONS_HEADER, DENY.toString()));
    }
}
