package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.junit.jupiter.api.Test;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequestInfoImplTest {

    HttpServletRequest mockHSRequest = mock(HttpServletRequest.class);

    @Test
    void from_getServletPath() {
        RequestInfo requestInfo = RequestInfoImpl.from(null);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getServletPath()).isEqualTo(RequestInfoImpl.NO_HTTP_SERVLET_REQUEST_TO_PROXY);
        assertThat(requestInfo.getAuthorizationHeader()).isNull();
        assertThat(requestInfo.getClientIP()).isNull();

        when(mockHSRequest.getServletPath()).thenReturn(" Mocked ");
        requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getServletPath()).isEqualTo(" Mocked "); // No cleaning!
    }

    @Test
    void getAuthorizationHeader() {
        when(mockHSRequest.getHeader("Authorization")).thenReturn("Mocking Bearer ");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getAuthorizationHeader()).isEqualTo("Mocking Bearer");
    }

    @Test
    void getClientIP_X_Client() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn("Mocked-IP-C ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn("Mocked-IP-R ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0, Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getClientIP()).isEqualTo("Mocked-IP-C");
    }

    @Test
    void getClientIP_X_Real() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn("Mocked-IP-R ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0 , Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getClientIP()).isEqualTo("Mocked-IP-R");
    }

    @Test
    void getClientIP_X_Forwarded() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn(" ");
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn("Mocked-IP-FF0 , Mocked-IP-FF1");
        RequestInfo requestInfo = RequestInfoImpl.from(mockHSRequest);
        assertThat(requestInfo).isNotNull();
        assertThat(requestInfo.getClientIP()).isEqualTo("Mocked-IP-FF0");
    }

    @Test
    void proxyingWorking() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContextPath()).thenReturn("/testContext");
        when(mockRequest.getServletPath()).thenReturn("/testServlet");
        when(mockRequest.getHeader("Authorization")).thenReturn("Bearer eyasdf");
        when(mockRequest.getHeaders("authorization")).thenReturn(Collections.enumeration(List.of("Bearer eyasdf")));
        when(mockRequest.getHeaderNames()).thenReturn(Collections.enumeration(List.of("Authorization", "X-Forwarded-For")));
        Principal principal = mock(Principal.class);
        when(mockRequest.getUserPrincipal()).thenReturn(principal);
        when(mockRequest.getAuthType()).thenReturn("someType");
        when(mockRequest.getMethod()).thenReturn("GET");
        when(mockRequest.getRequestURI()).thenReturn("requestURI");
        when(mockRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(mockRequest.getRemoteUser()).thenReturn("fake@example.org");
        RequestInfoImpl request = (RequestInfoImpl) RequestInfoImpl.from(mockRequest);

        assertThat(request.getServletPath()).isEqualTo("/testServlet");
        assertThat(request.getContextPath()).isEqualTo("/testContext");
        assertThat(request.getAuthorizationHeader()).isEqualTo("Bearer eyasdf");
        assertThat(request.hasHeaderNames()).isTrue();
        assertThat(request.getHeaderNames()).contains("Authorization", "X-Forwarded-For");
        assertThat(request.hasHeaders("Authorization")).isTrue();
        assertThat(request.hasHeaders("X-Real-IP")).isFalse();
        assertThat(request.getHeaders("Authorization")).contains("Bearer eyasdf");
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer eyasdf");
        assertThat(request.getPrincipal()).isEqualTo(principal);
        assertThat(request.getAuthType()).isEqualTo("someType");
        assertThat(request.getMethod()).isEqualTo("GET");
        assertThat(request.getRequestURI()).isEqualTo("requestURI");
        assertThat(request.getRemoteAddr()).isEqualTo("127.0.0.1");
        assertThat(request.getRemoteUser()).isEqualTo("fake@example.org");

        String toString = request.toString();
        assertThat(toString).contains("authType='someType'")
                .contains("contextPath='/testContext'")
                .contains("method='GET'")
                .contains("requestURI='requestURI'")
                .contains("remoteAddr='127.0.0.1'")
                .contains("remoteUser='fake@example.org'")
                .contains("servletPath='/testServlet'")
                .contains("principal=")
                //No details as Mock object are used
                .contains("hasHeaderNames=true")
                .contains("headerNames=[Authorization, X-Forwarded-For]")
                .contains("header:Authorization=Bearer eyasdf");
    }
}
