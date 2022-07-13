package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class RequestInfoImplTest {

    HttpServletRequest mockHSRequest = Mockito.mock( HttpServletRequest.class );

    @Test
    void from_getServletPath() {
        RequestInfo requestInfo = RequestInfoImpl.from( null );
        assertNotNull( requestInfo );
        assertEquals( RequestInfoImpl.NO_HTTP_SERVLET_REQUEST_TO_PROXY, requestInfo.getServletPath() );
        assertNull(requestInfo.getAuthorizationHeader());
        assertNull(requestInfo.getClientIP());

        when(mockHSRequest.getServletPath()).thenReturn( " Mocked " );
        requestInfo = RequestInfoImpl.from( mockHSRequest );
        assertNotNull( requestInfo );
        assertEquals( " Mocked ", requestInfo.getServletPath() ); // No cleaning!
    }

    @Test
    void getAuthorizationHeader() {
        when(mockHSRequest.getHeader("Authorization")).thenReturn( "Mocking Bearer " );
        RequestInfo requestInfo = RequestInfoImpl.from( mockHSRequest );
        assertNotNull( requestInfo );
        assertEquals( "Mocking Bearer", requestInfo.getAuthorizationHeader() );
    }

    @Test
    void getClientIP_X_Client() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn( "Mocked-IP-C " );
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn( "Mocked-IP-R " );
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn( "Mocked-IP-FF0, Mocked-IP-FF1" );
        RequestInfo requestInfo = RequestInfoImpl.from( mockHSRequest );
        assertNotNull( requestInfo );
        assertEquals( "Mocked-IP-C", requestInfo.getClientIP() );
    }

    @Test
    void getClientIP_X_Real() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn( " " );
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn( "Mocked-IP-R " );
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn( "Mocked-IP-FF0 , Mocked-IP-FF1" );
        RequestInfo requestInfo = RequestInfoImpl.from( mockHSRequest );
        assertNotNull( requestInfo );
        assertEquals( "Mocked-IP-R", requestInfo.getClientIP() );
    }

    @Test
    void getClientIP_X_Forwarded() {
        when(mockHSRequest.getHeader("X-Client-IP")).thenReturn( " " );
        when(mockHSRequest.getHeader("X-Real-IP")).thenReturn( " " );
        when(mockHSRequest.getHeader("X-Forwarded-For")).thenReturn( "Mocked-IP-FF0 , Mocked-IP-FF1" );
        RequestInfo requestInfo = RequestInfoImpl.from( mockHSRequest );
        assertNotNull( requestInfo );
        assertEquals( "Mocked-IP-FF0", requestInfo.getClientIP() );
    }
}