package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class SessionControllerMockMvcTests extends InjectedMockContextTest {
  @Test
  public void sessionControllerReturnsSessionView() throws Exception {
    getMockMvc().perform(get("/session"))
      .andExpect(view().name("session"))
      .andExpect(status().isOk());
  }
}
