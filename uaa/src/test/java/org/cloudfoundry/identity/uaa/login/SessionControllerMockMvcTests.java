package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class SessionControllerMockMvcTests {
  @Autowired
  public WebApplicationContext webApplicationContext;
  private MockMvc mockMvc;

  @Before
  public void setup() {
    FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
  }

  @Test
  public void legacy_sessionControllerReturnsSessionView() throws Exception {
    mockMvc.perform(get("/session")
        .param("clientId","1")
        .param("messageOrigin", "origin"))
      .andExpect(view().name("session"))
      .andExpect(status().isOk());
  }

  @Test
  public void sessionManagement_ReturnsSessionManagementView() throws Exception {
    mockMvc.perform(get("/session_management")
      .param("clientId","1")
      .param("messageOrigin", "origin"))
      .andExpect(view().name("session_management"))
      .andExpect(status().isOk());
  }
}
