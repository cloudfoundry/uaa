package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2AuthenticationEntryPointTests {

    private final OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    {
        entryPoint.setRealmName("foo");
    }

    @Test
    public void testCommenceWithJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}", response.getContentAsString());
        assertTrue(response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE));
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testCommenceWithOAuth2Exception() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad", new InvalidClientException(
                "Bad client")));
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"Bad client\"}", response.getContentAsString());
        assertTrue(response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE));
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testCommenceWithXml() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_XML_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testTypeName() throws Exception {
        entryPoint.setTypeName("Foo");
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertEquals("Foo realm=\"foo\", error=\"unauthorized\", error_description=\"Bad\"",
                response.getHeader("WWW-Authenticate"));
    }

    @Test
    public void testCommenceWithEmptyAccept() throws Exception {
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals("{\"error\":\"unauthorized\",\"error_description\":\"Bad\"}", response.getContentAsString());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.valueOf(response.getContentType())));
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testCommenceWithHtmlAccept() throws Exception {
        request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        // TODO: maybe use forward / redirect for HTML content?
        assertEquals(HttpServletResponse.SC_NOT_ACCEPTABLE, response.getStatus());
        assertEquals("", response.getContentAsString());
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testCommenceWithHtmlAndJsonAccept() throws Exception {
        request.addHeader("Accept", "%s,%s".formatted(MediaType.TEXT_HTML_VALUE, MediaType.APPLICATION_JSON));
        entryPoint.commence(request, response, new BadCredentialsException("Bad"));
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertEquals(null, response.getErrorMessage());
    }

}
