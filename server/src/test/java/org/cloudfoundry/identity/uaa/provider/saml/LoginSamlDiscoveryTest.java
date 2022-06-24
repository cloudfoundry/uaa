package org.cloudfoundry.identity.uaa.provider.saml;

import org.junit.jupiter.api.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LoginSamlDiscoveryTest {

  @Test
  void doFilter() throws ServletException, IOException {
    LoginSamlDiscovery samlDiscovery = new LoginSamlDiscovery();
    HttpServletResponse servletResponse = mock(HttpServletResponse.class);
    HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    HttpSession session = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);
    when(servletRequest.getSession(true)).thenReturn(session);
    samlDiscovery.doFilter(servletRequest, servletResponse, chain);
    assertNotNull(servletRequest);
  }
}