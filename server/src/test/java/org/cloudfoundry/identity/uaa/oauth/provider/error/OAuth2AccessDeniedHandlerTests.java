package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2AccessDeniedHandlerTests {

    private final OAuth2AccessDeniedHandler handler = new OAuth2AccessDeniedHandler();

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    public void testHandleWithJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        handler.handle(request, response, new AccessDeniedException("Bad"));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertTrue(response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE));
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testHandleSetter() throws Exception {
        handler.setExceptionRenderer(new DefaultOAuth2ExceptionRenderer());
        handler.setExceptionTranslator(new DefaultWebResponseExceptionTranslator());
        handler.doHandle(request, response, new AccessDeniedException("Bad"));
    }
}
