package org.cloudfoundry.identity.uaa.security.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FixHttpsSchemeRequestTest {

  MockHttpServletRequest request;
  FixHttpsSchemeRequest fixHttpsSchemeRequest;
  @BeforeEach
  void setup() {
    request = new MockHttpServletRequest("GET", "http://server.url.org/path");
    request.addHeader("X-Forwarded-Proto", "https");
    request.setServerName("server.url.org");
    request.setScheme("http");
    request.setServerPort(-1);
    request.setRequestURI("/path");
    fixHttpsSchemeRequest = new FixHttpsSchemeRequest(request);
  }

  @Test
  void getScheme() {
    assertEquals("https", fixHttpsSchemeRequest.getScheme());
  }

  @Test
  void getServerPort() {
    assertEquals(443, fixHttpsSchemeRequest.getServerPort());
  }

  @Test
  void getRequestURL() {
    assertEquals("https://server.url.org/path", fixHttpsSchemeRequest.getRequestURL().toString());
  }
}