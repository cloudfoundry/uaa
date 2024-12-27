package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import javax.servlet.http.HttpServletRequest;

import org.hamcrest.core.IsIterableContaining;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

class RequestInfoImplTest {

    HttpServletRequest mockHSRequest = mock(HttpServletRequest.class);

    @Test
    void from_getServletPath() {
        RequestInfo requestInfo = RequestInfoImpl.from(null);
        assertNotNull(requestInfo);
        assertEquals(RequestInfoImpl.NO_HTTP_SERVLET_REQUEST_TO_PROXY, requestInfo.getServletPath());
        assertNull(requestInfo.getAuthorizationHeader());
        assertNull(requestInfo.getClientIP());

        when(mockHSRequest.getServletPath()).thenReturn(" Mocked ");
        requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertNotNull(requestInfo);
        assertEquals(" Mocked ", requestInfo.getServletPath()); // No cleaning!
    }

    @Test
    void getAuthorizationHeader() {
        when(mockHSRequest.getHeader("Authorization")).thenReturn("Mocking Bearer ");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertNotNull(requestInfo);
        assertEquals("Mocking Bearer", requestInfo.getAuthorizationHeader());
    }

    @Test
    void getClientIP_X_Client() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn("Mocked-IP-C ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn("Mocked-IP-R ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0, Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertNotNull(requestInfo);
        assertEquals("Mocked-IP-C", requestInfo.getClientIP());
    }

    @Test
    void getClientIP_X_Real() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn("Mocked-IP-R ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0 , Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertNotNull(requestInfo);
        assertEquals("Mocked-IP-R", requestInfo.getClientIP());
    }

    @Test
    void getClientIP_X_Forwarded() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0 , Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertNotNull(requestInfo);
        assertEquals("Mocked-IP-FF0", requestInfo.getClientIP());
    }

    @Test
    void proxyingWorking() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContextPath()).thenReturn("/testContext");
        when(mockRequest.getServletPath()).thenReturn("/testServlet");
        when(mockRequest.getHeader("Authorization")).thenReturn("Bearer eyasdf");
        when(mockRequest.getHeaders("authorization")).thenReturn(Collections.enumeration(Arrays.asList("Bearer eyasdf")));
        when(mockRequest.getHeaderNames()).thenReturn(Collections.enumeration(Arrays.asList("Authorization", "X-Forwarded-For")));
        Principal principal = mock(Principal.class);
        when(mockRequest.getUserPrincipal()).thenReturn(principal);
        when(mockRequest.getAuthType()).thenReturn("someType");
        when(mockRequest.getMethod()).thenReturn("GET");
        when(mockRequest.getRequestURI()).thenReturn("requestURI");
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(mockRequest.getRemoteUser()).thenReturn("fake@example.org");
        RequestInfoImpl request = (RequestInfoImpl) RequestInfoImpl.from(mockRequest);

        assertEquals("/testServlet", request.getServletPath());
        assertEquals("/testContext", request.getContextPath());
        assertEquals("Bearer eyasdf", request.getAuthorizationHeader());
        assertTrue(request.hasHeaderNames());
        assertThat(request.getHeaderNames(), IsIterableContaining.hasItems("Authorization", "X-Forwarded-For"));
        assertTrue(request.hasHeaders("Authorization"));
        assertFalse(request.hasHeaders("X-Real-IP"));
        assertThat(request.getHeaders("Authorization"), IsIterableContaining.hasItems("Bearer eyasdf"));
        assertEquals("Bearer eyasdf", request.getHeader("Authorization"));
        assertEquals(principal, request.getPrincipal());
        assertEquals("someType", request.getAuthType());
        assertEquals("GET", request.getMethod());
        assertEquals("requestURI", request.getRequestURI());
        assertEquals("127.0.0.1", request.getRemoteAddr());
        assertEquals("fake@example.org", request.getRemoteUser());

        String toString = request.toString();
        assertThat(toString, containsString("authType='someType'"));
        assertThat(toString, containsString("contextPath='/testContext'"));
        assertThat(toString, containsString("method='GET'"));
        assertThat(toString, containsString("requestURI='requestURI'"));
        assertThat(toString, containsString("remoteAddr='127.0.0.1'"));
        assertThat(toString, containsString("remoteUser='fake@example.org'"));
        assertThat(toString, containsString("servletPath='/testServlet'"));
        assertThat(toString, containsString("principal=")); //No details as Mock object is used
        assertThat(toString, containsString("hasHeaderNames=true"));
        assertThat(toString, containsString("headerNames=[Authorization, X-Forwarded-For]"));
        assertThat(toString, containsString("header:Authorization=Bearer eyasdf"));
    }
}