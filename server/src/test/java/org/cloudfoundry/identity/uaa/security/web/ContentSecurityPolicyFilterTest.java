package org.cloudfoundry.identity.uaa.security.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ContentSecurityPolicyFilterTest {
    private ContentSecurityPolicyFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new ContentSecurityPolicyFilter(Arrays.asList("'self'"));

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
    }

    @Test
    void verifyRequestHasHeader() throws ServletException, IOException {
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("script-src 'self'");
    }

    @Test
    void shouldNotAddHeader_WhenRespondingTo_SamlAuthRequests() throws ServletException, IOException {
        request.setServletPath("/saml/some-path");
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isNull();
    }

    @Test
    void shouldAddHeader_ForSamlSomeOtherThing() throws ServletException, IOException {
        request.setServletPath("/samlSomeOtherThing");
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
    }

    @Test
    void shouldAddHeader_ForSamlInMiddleOfPath() throws ServletException, IOException {
        request.setServletPath("/other/saml/");
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
    }

    @Test
    void shouldNotAddHeader_WhenRespondingTo_LoginImplicitPageRequests() throws ServletException, IOException {
        request.setServletPath("/login_implicit");
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isNull();
    }

    @Test
    void verifyChainRequest() throws ServletException, IOException {
        filter.doFilter(request, response, chain);

        Mockito.verify(chain).doFilter(request, response);
    }

    @Test
    void customScriptSrc() throws ServletException, IOException {
        filter = new ContentSecurityPolicyFilter(Arrays.asList("'self'", "custom"));
        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("Content-Security-Policy")).isEqualTo("script-src 'self' custom");
    }
}
