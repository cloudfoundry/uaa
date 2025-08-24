package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AuthenticationEntryPointTests {

    private OAuth2AuthenticationEntryPoint entryPoint;

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;


    @BeforeEach
    void setUp() {
        entryPoint = new OAuth2AuthenticationEntryPoint();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        entryPoint.setRealmName("foo");
    }

    @Test
    void commenceWithJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}");
        assertThat(response.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void commenceWithOAuth2Exception() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad", new InvalidClientException(
                "Bad client")));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_client\",\"error_description\":\"Bad client\"}");
        assertThat(response.getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void commenceWithXml() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_XML_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        //changed with Spring Boot (spring-web)Upgrade
        assertThat(response.getErrorMessage()).isNotNull();
    }

    @Test
    void typeName() throws Exception {
        entryPoint.setTypeName("Foo");
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Foo realm=\"foo\", error=\"unauthorized\", error_description=\"Bad\"");
    }

    @Test
    void commenceWithEmptyAccept() throws Exception {
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}");
        assertThat(MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.valueOf(response.getContentType()))).isTrue();
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void commenceWithHtmlAccept() throws Exception {
        request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        // TODO: maybe use forward / redirect for HTML content?
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_ACCEPTABLE);
        assertThat(response.getContentAsString()).isEmpty();
        //changed with Spring Boot (spring-web)Upgrade
        assertThat(response.getErrorMessage()).isNotNull();
    }

    @Test
    void commenceWithHtmlAndJsonAccept() throws Exception {
        request.addHeader("Accept", "%s,%s".formatted(MediaType.TEXT_HTML_VALUE, MediaType.APPLICATION_JSON));
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getErrorMessage()).isNull();
    }

}
