package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class IdentityZoneResolvingFilterTest {
    
    private boolean wasFilterExecuted = false;
    
    @Test
    public void holderIsSetWithMatchingIdentityZone() throws Exception {
        happyTest("myzone", "uaa.mycf.com");
    }
    
    @Test
    public void holderIsSetWithMatchingIdentityZoneWhenSubdomainContainsUaaHostname() throws Exception {
        happyTest("foo.uaa.mycf.com", "uaa.mycf.com");
    }

    @Test
    public void holderIsSetWithUAAIdentityZone() throws Exception {
        happyTest("",  "uaa.mycf.com");
    }
    
    private void happyTest(final String incomingSubdomain, String uaaHostname) throws ServletException, IOException {
        String incomingHostname = null;
        if ("".equals(incomingSubdomain) ) {
            incomingHostname = uaaHostname;
        } else {
            incomingHostname = incomingSubdomain+"."+uaaHostname;
        }

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        IdentityZoneProvisioning dao = Mockito.mock(IdentityZoneProvisioning.class);
        filter.setDao(dao);
        filter.setUaaHostname(uaaHostname);
        
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(incomingSubdomain);
        Mockito.when(dao.retrieveBySubdomain(Mockito.eq(incomingSubdomain))).thenReturn(identityZone);
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                assertNotNull(IdentityZoneHolder.get());
                assertEquals(incomingSubdomain, IdentityZoneHolder.get().getSubdomain());
                wasFilterExecuted = true;
            }
        };
        
        filter.doFilter(request, response, filterChain);
        assertTrue(wasFilterExecuted);
        Mockito.verify(dao).retrieveBySubdomain(Mockito.eq(incomingSubdomain));
        assertNull(IdentityZoneHolder.get());
    }
    
    @Test
    public void holderIsNotSetWithNonMatchingIdentityZone() throws Exception {
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        IdentityZoneProvisioning dao = Mockito.mock(IdentityZoneProvisioning.class);
        FilterChain chain = Mockito.mock(FilterChain.class);
        filter.setDao(dao);
        filter.setUaaHostname(uaaHostname);
        
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(incomingSubdomain);
        Mockito.when(dao.retrieveBySubdomain(Mockito.eq(incomingSubdomain))).thenThrow(new EmptyResultDataAccessException(1));
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();
        
        filter.doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertNull(IdentityZoneHolder.get());
        Mockito.verifyZeroInteractions(chain);
    }

}
