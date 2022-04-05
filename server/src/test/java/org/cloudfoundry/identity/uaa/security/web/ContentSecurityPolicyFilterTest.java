package org.cloudfoundry.identity.uaa.security.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class ContentSecurityPolicyFilterTest {
    private ContentSecurityPolicyFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new ContentSecurityPolicyFilter();

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
    }

    @Test
    void verifyRequestHasHeader() throws ServletException, IOException {
        filter.doFilter(request, response, chain);

        assertEquals("script-src 'self'",
                response.getHeader("Content-Security-Policy"));
    }

    @Test
    void verifySamlRequestHasHeader() throws ServletException, IOException {
        request.setRequestURI("/saml/idp/example.html");
        filter.doFilter(request, response, chain);

        assertEquals("script-src 'self' 'unsafe-inline'",
                response.getHeader("Content-Security-Policy"));
    }

    @Test
    void verifyChainRequest() throws ServletException, IOException {
        filter.doFilter(request, response, chain);

        Mockito.verify(chain).doFilter(request, response);
    }
}
