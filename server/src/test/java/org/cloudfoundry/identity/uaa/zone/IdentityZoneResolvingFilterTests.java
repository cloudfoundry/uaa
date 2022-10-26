package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
class IdentityZoneResolvingFilterTests {

    private boolean wasFilterExecuted;
    private IdentityZoneProvisioning dao;

    @BeforeEach
    void setUp(@Autowired JdbcTemplate jdbcTemplate) {
        dao = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        wasFilterExecuted = false;
    }

    @Test
    void holderIsSetWithDefaultIdentityZone() {
        IdentityZoneHolder.clear();
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    @Test
    void holderIsSetWithMatchingIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("myzone", "myzone.uaa.mycf.com", "uaa.mycf.com", "login.mycf.com");
    }

    @Test
    void holderIsSetWithMatchingIdentityZoneWhenSubdomainContainsUaaHostname() throws Exception {
        assertFindsCorrectSubdomain("foo.uaa.mycf.com", "foo.uaa.mycf.com.uaa.mycf.com", "uaa.mycf.com", "login.mycf.com");
    }

    @Test
    void holderIsSetWithUAAIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "uaa.mycf.com", "uaa.mycf.com", "login.mycf.com");
        assertFindsCorrectSubdomain("", "login.mycf.com", "uaa.mycf.com", "login.mycf.com");
    }

    @Test
    void holderIsResolvedWithCaseInsensitiveIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "Login.MyCF.COM", "uaa.mycf.com", "login.mycf.com");
    }

    @Test
    void holderIsSetWithCaseInsensitiveIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "login.mycf.com", "uaa.mycf.com", "Login.MyCF.COM");
    }

    @Test
    void doNotThrowException_InCase_RetrievingZoneFails() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain + "." + uaaHostname;
        request.setServerName(incomingHostname);
        request.setRequestURI("/uaa/login.html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = Mockito.mock(FilterChain.class);
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Collections.singletonList(uaaHostname)));
        filter.doFilter(request, response, chain);

        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyNoInteractions(chain);
    }

    @Test
    public void serveStaticContent_InCase_RetrievingZoneFails() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;
        request.setServerName(incomingHostname);
        request.setRequestURI("/uaa/resources/css/application.css");
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockFilterChain filterChain = new MockFilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                assertNotNull(IdentityZoneHolder.get());
                wasFilterExecuted = true;
            }
        };
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));
        filter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        assertTrue(wasFilterExecuted);
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    private void assertFindsCorrectSubdomain(final String subDomainInput, final String incomingHostname, String... additionalInternalHostnames) throws ServletException, IOException {
        final String expectedSubdomain = subDomainInput.toLowerCase();
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(additionalInternalHostnames)));

        IdentityZone identityZone = MultitenancyFixture.identityZone(subDomainInput, subDomainInput);
        identityZone.setSubdomain(subDomainInput);
        try {
            identityZone = dao.create(identityZone);
        } catch (ZoneAlreadyExistsException x) {
            identityZone = dao.retrieveBySubdomain(subDomainInput);
        }
        assertEquals(expectedSubdomain, identityZone.getSubdomain());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) {
                assertNotNull(IdentityZoneHolder.get());
                assertEquals(expectedSubdomain, IdentityZoneHolder.get().getSubdomain());
                wasFilterExecuted = true;
            }
        };

        filter.doFilter(request, response, filterChain);
        assertTrue(wasFilterExecuted);
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    @Test
    void holderIsNotSetWithNonMatchingIdentityZone() throws Exception {
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain + "." + uaaHostname;

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);

        FilterChain chain = Mockito.mock(FilterChain.class);
        filter.setAdditionalInternalHostnames(new HashSet<>(Collections.singletonList(uaaHostname)));

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(incomingSubdomain);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyNoInteractions(chain);
    }

    @Test
    void setDefaultZoneHostNamesWithNull() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setDefaultInternalHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    void setAdditionalZoneHostNamesWithNull() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setAdditionalInternalHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    void setRestoreZoneHostNamesWithNull() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setDefaultInternalHostnames(new HashSet<>(Collections.singletonList("uaa.mycf.com")));
        filter.restoreDefaultHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    void setDefaultZoneHostNames() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setDefaultInternalHostnames(new HashSet<>(Collections.singletonList("uaa.mycf.com")));
        filter.setDefaultInternalHostnames(new HashSet<>(Collections.singletonList("uaa.MYCF2.com")));
        assertEquals(2, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf.com"));
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }

    @Test
    void setAdditionalZoneHostNames() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Collections.singletonList("uaa.mycf.com")));
        filter.setAdditionalInternalHostnames(new HashSet<>(Collections.singletonList("uaa.MYCF2.com")));
        assertEquals(2, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf.com"));
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }

    @Test
    void setRestoreZoneHostNames() {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter(dao);
        filter.setDefaultInternalHostnames(new HashSet<>(Collections.singletonList("uaa.mycf.com")));
        filter.restoreDefaultHostnames(new HashSet<>(Collections.singletonList("uaa.MYCF2.com")));
        assertEquals(1, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }
}
