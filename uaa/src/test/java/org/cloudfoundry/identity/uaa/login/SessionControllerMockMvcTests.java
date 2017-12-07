package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class SessionControllerMockMvcTests extends InjectedMockContextTest {
  @Test
  public void sessionController_escapesClientIdValue() throws Exception {
    String input = "1'\"";
    getMockMvc().perform(get("/session")
        .param("clientId", input)
        .param("messageOrigin", "origin"))
        .andExpect(view().name("session"))
        .andExpect(status().isOk())
        .andExpect(model().size(2))
        .andExpect(model().attribute("clientId", "\"1'\\\"\""))
        .andExpect(content().string(containsString("\"1'\\\"\"")));
  }

  @Test
  public void sessionController_escapesMessageOriginValue() throws Exception {
    getMockMvc().perform(get("/session")
        .param("clientId","1")
        .param("messageOrigin", "origin\""))
        .andExpect(view().name("session"))
        .andExpect(status().isOk())
        .andExpect(model().attribute("messageOrigin", "\"origin\\\"\""))
        .andExpect(content().string(containsString("\"origin\\\"\"")));
  }
}
