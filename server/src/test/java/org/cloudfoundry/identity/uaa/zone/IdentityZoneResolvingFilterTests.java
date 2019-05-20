/**
 *******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
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
import java.util.HashSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class IdentityZoneResolvingFilterTests extends JdbcTestBase {

    private boolean wasFilterExecuted = false;
    private IdentityZoneProvisioning dao;

    @Before
    public void createDao() {
        dao = new JdbcIdentityZoneProvisioning(jdbcTemplate);
    }

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
    public void holderIsResolvedWithCaseInsensitiveIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "Login.MyCF.COM", "uaa.mycf.com","login.mycf.com");
    }

    @Test
    public void holderIsSetWithCaseInsensitiveIdentityZone() throws Exception {
        assertFindsCorrectSubdomain("", "login.mycf.com", "uaa.mycf.com","Login.MyCF.COM");
    }

    @Test
    public void doNotThrowException_InCase_RetrievingZoneFails() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;
        request.setServerName(incomingHostname);
        request.setRequestURI("/uaa/login.html");
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = Mockito.mock(FilterChain.class);
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));
        filter.doFilter(request, response, chain);

        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyZeroInteractions(chain);
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
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));
        filter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        assertTrue(wasFilterExecuted);
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
    }

    private void assertFindsCorrectSubdomain(final String subDomainInput, final String incomingHostname, String... additionalInternalHostnames) throws ServletException, IOException {
        final String expectedSubdomain = subDomainInput.toLowerCase();
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setIdentityZoneProvisioning(dao);
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
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
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
    public void holderIsNotSetWithNonMatchingIdentityZone() throws Exception {
        String incomingSubdomain = "not_a_zone";
        String uaaHostname = "uaa.mycf.com";
        String incomingHostname = incomingSubdomain+"."+uaaHostname;

        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();

        FilterChain chain = Mockito.mock(FilterChain.class);
        filter.setIdentityZoneProvisioning(dao);
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList(uaaHostname)));

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(incomingSubdomain);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName(incomingHostname);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_NOT_FOUND, response.getStatus());
        assertEquals(IdentityZone.getUaa(), IdentityZoneHolder.get());
        Mockito.verifyZeroInteractions(chain);
    }

    @Test
    public void setDefaultZoneHostnamesWithNull() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setDefaultInternalHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    public void setAdditionalZoneHostnamesWithNull() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setAdditionalInternalHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    public void setRestoreZoneHostnamesWithNull() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setDefaultInternalHostnames(new HashSet<>(Arrays.asList("uaa.mycf.com")));
        filter.restoreDefaultHostnames(null);
        assertTrue(filter.getDefaultZoneHostnames().isEmpty());
    }

    @Test
    public void setDefaultZoneHostnames() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setDefaultInternalHostnames(new HashSet<>(Arrays.asList("uaa.mycf.com")));
        filter.setDefaultInternalHostnames(new HashSet<>(Arrays.asList("uaa.MYCF2.com")));
        assertEquals(2, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf.com"));
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }

    @Test
    public void setAdditionalZoneHostnames() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList("uaa.mycf.com")));
        filter.setAdditionalInternalHostnames(new HashSet<>(Arrays.asList("uaa.MYCF2.com")));
        assertEquals(2, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf.com"));
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }

    @Test
    public void setRestoreZoneHostnames() throws Exception {
        IdentityZoneResolvingFilter filter = new IdentityZoneResolvingFilter();
        filter.setDefaultInternalHostnames(new HashSet<>(Arrays.asList("uaa.mycf.com")));
        filter.restoreDefaultHostnames(new HashSet<>(Arrays.asList("uaa.MYCF2.com")));
        assertEquals(1, filter.getDefaultZoneHostnames().size());
        assertTrue(filter.getDefaultZoneHostnames().contains("uaa.mycf2.com"));
    }
}
