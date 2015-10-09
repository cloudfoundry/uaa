/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import java.net.URLDecoder;
import java.net.URLEncoder;

import org.apache.commons.httpclient.util.URIUtil;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriUtils;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.*;

public class UaaUrlUtilsTest {

    private UaaUrlUtils uaaURLUtils;

    @Before
    public void setUp() throws Exception {
        uaaURLUtils = new UaaUrlUtils();

        MockHttpServletRequest request = new MockHttpServletRequest();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    @After
    public void tearDown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testGetUaaUrl() throws Exception {
        assertEquals("http://localhost", uaaURLUtils.getUaaUrl());
    }

    @Test
    public void testGetUaaUrlWithPath() throws Exception {
        assertEquals("http://localhost/login", uaaURLUtils.getUaaUrl("/login"));
    }

    @Test
    public void testGetUaaUrlWithZone() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost", uaaURLUtils.getUaaUrl());
    }

    @Test
    public void testGetUaaUrlWithZoneAndPath() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("http://zone1.localhost/login", uaaURLUtils.getUaaUrl("/login"));
    }

    @Test
    public void testGetHost() throws Exception {
        assertEquals("localhost", uaaURLUtils.getUaaHost());
    }

    @Test
    public void testGetHostWithZone() throws Exception {
        setIdentityZone("zone1");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("zone1.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        assertEquals("zone1.localhost", uaaURLUtils.getUaaHost());
    }

    @Test
    public void testLocalhostPortAndContextPathUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.setContextPath("/uaa");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        UaaUrlUtils urlUtils = new UaaUrlUtils();
        String url = urlUtils.getUaaUrl("/something");
        assertThat(url, is("http://localhost:8080/uaa/something"));
    }

    @Test
    public void testSecurityProtocol() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerPort(8443);
        request.setServerName("localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        UaaUrlUtils urlUtils = new UaaUrlUtils();
        String url = urlUtils.getUaaUrl("/something");
        assertThat(url, is("https://localhost:8443/something"));
    }

    @Test
    public void testMultiDomainUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        UaaUrlUtils urlUtils = new UaaUrlUtils();
        String url = urlUtils.getUaaUrl("/something");
        assertThat(url, is("http://login.localhost/something"));
    }

    @Test
    public void testZonedAndMultiDomainUrls() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("testzone1-id", "testzone1"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("testzone1.login.localhost");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        UaaUrlUtils urlUtils = new UaaUrlUtils();
        String url = urlUtils.getUaaUrl("/something");
        assertThat(url, is("http://testzone1.login.localhost/something"));
    }

    @Test
    public void testXForwardedPrefixUrls() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("login.localhost");
        request.addHeader("X-Forwarded-Prefix", "/prefix");

        ServletRequestAttributes attrs = new ServletRequestAttributes(request);

        RequestContextHolder.setRequestAttributes(attrs);

        UaaUrlUtils urlUtils = new UaaUrlUtils();
        String url = urlUtils.getUaaUrl("/something");
        assertThat(url, is("http://login.localhost/prefix/something"));
    }

    private void setIdentityZone(String subdomain) {
        IdentityZone zone = new IdentityZone();
        zone.setSubdomain(subdomain);
        IdentityZoneHolder.set(zone);
    }
}
