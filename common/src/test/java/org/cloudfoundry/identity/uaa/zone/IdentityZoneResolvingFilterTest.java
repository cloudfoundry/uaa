package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.sql.SQLNonTransientConnectionException;
import java.util.Arrays;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class IdentityZoneResolvingFilterTest {

    private boolean wasFilterExecuted = false;

    @Test
    public void holderIsSetWithDefaultIdentityZone() {
        IdentityZoneHolder.clear();
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    @Test
    public void holderIsSetWithMatchingIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("myzone", "myzone.uaa.mycf.com", "uaa.mycf.com","login.mycf.com");
    }

    @Test
    public void holderIsSetWithMatchingIdentityZoneWhenSubdomainContainsUaaHostname() throws Exception {
        assertFindsCorrectSubdomain("foo.uaa.mycf.com", "foo.uaa.mycf.com.uaa.mycf.com", "uaa.mycf.com", "login.mycf.com");
    }

    @Test
    public void holderIsSetWithUAAIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "uaa.mycf.com", "uaa.mycf.com","login.mycf.com");
        assertFindsCorrectSubdomain("", "login.mycf.com", "uaa.mycf.com","login.mycf.com");
    }

    @Test
    public void doNotThrowException_InCase_RetrievingZoneFails() throws Exception {
        IdentityZoneProvisioning dao = Mockito.mock(IdentityZoneProvisioning.class);
        when(dao.retrieveBySubdomain(anyString())).thenThrow(new CannotGetJdbcConnectionException("blah", new SQLNonTransientConnectionException()));

        MockHttpServletRequest request = new MockHttpServletRequest();
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = Mockito.mock(FilterChain.class);
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));
        filter.doFilter(request, response, chain);

        assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyZeroInteractions(chain);
    }

    private void assertFindsCorrectSubdomain(final String expectedSubdomain, final String incomingHostname, String... additionalInternalHostnames) throws ServletException, IOException {

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        IdentityZoneProvisioning dao = Mockito.mock(IdentityZoneProvisioning.class);
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(additionalInternalHostnames)));

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(expectedSubdomain);
        when(dao.retrieveBySubdomain(Mockito.eq(expectedSubdomain))).thenReturn(identityZone);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                assertNotNull(IdentityZoneHolder.get());
                assertEquals(expectedSubdomain, IdentityZoneHolder.get().getSubdomain());
                wasFilterExecuted = true;
            }
        };

        filter.doFilter(request, response, filterChain);
        assertTrue(wasFilterExecuted);
        Mockito.verify(dao).retrieveBySubdomain(Mockito.eq(expectedSubdomain));
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    @Test
    public void holderIsNotSetWithNonMatchingIdentityZone() throws Exception {
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        IdentityZoneProvisioning dao = Mockito.mock(IdentityZoneProvisioning.class);
        FilterChain chain = Mockito.mock(FilterChain.class);
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(incomingSubdomain);
        when(dao.retrieveBySubdomain(Mockito.eq(incomingSubdomain))).thenThrow(new EmptyResultDataAccessException(1));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyZeroInteractions(chain);
    }

}
