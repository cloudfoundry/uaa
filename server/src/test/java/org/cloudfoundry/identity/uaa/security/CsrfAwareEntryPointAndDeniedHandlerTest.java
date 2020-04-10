package org.cloudfoundry.identity.uaa.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.*;

public class CsrfAwareEntryPointAndDeniedHandlerTest {

    protected CsrfAwareEntryPointAndDeniedHandler handler = new CsrfAwareEntryPointAndDeniedHandler("/csrf", "/login");
    protected MockHttpServletRequest request = new MockHttpServletRequest();
    protected MockHttpServletResponse response = new MockHttpServletResponse();

    @Before
    public void setUpCsrfAccessDeniedHandler() {
        response.setCommitted(false);
    }

    @After
    public void cleanUpAuth() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testHandleWhenNotLoggedInAndNoCsrf() throws Exception {
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FOUND, response.getStatus());
        assertSame(request.getAttribute(WebAttributes.ACCESS_DENIED_403), ex);
        assertTrue(response.isCommitted());
        assertEquals("http://localhost/login", response.getHeader("Location"));
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
    }

    @Test
    public void testHandleWhenCsrfMissingForJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertEquals("{\"error\":\"Could not verify the provided CSRF token because your session was not found.\"}", response.getContentAsString());
        assertNull(response.getErrorMessage());
    }

    @Test
    public void testHandleWhenNotLoggedIn() throws Exception {
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FOUND, response.getStatus());
        assertSame(request.getAttribute(WebAttributes.ACCESS_DENIED_403), ex);
        assertTrue(response.isCommitted());
        assertEquals("http://localhost/login", response.getHeader("Location"));
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
    }

    @Test
    public void testHandleWhenNotLoggedInJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertEquals("{\"error\":\"something\"}", response.getContentAsString());
        assertNull(response.getErrorMessage());
    }

    @Test(expected = NullPointerException.class)
    public void testNullCsrfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler(null, "/login");
    }

    @Test(expected = NullPointerException.class)
    public void testInvalidCsrfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("csrf", "/login");
    }

    @Test(expected = NullPointerException.class)
    public void testNullLoginfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("/csrf", null);
    }

    @Test(expected = NullPointerException.class)
    public void testInvalidLoginUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("/csrf", "login");
    }

}