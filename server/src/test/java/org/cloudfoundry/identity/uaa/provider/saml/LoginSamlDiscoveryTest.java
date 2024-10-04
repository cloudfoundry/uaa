package org.cloudfoundry.identity.uaa.provider.saml;

import org.junit.jupiter.api.Test;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

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