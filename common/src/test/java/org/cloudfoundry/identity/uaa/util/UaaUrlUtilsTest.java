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

import java.net.URI;
import java.net.URLDecoder;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.web.util.UriComponentsBuilder;

import static org.junit.Assert.*;

public class UaaUrlUtilsTest {

    private UaaUrlUtils uaaURLUtils;

    @Before
    public void setUp() throws Exception {
        uaaURLUtils = new UaaUrlUtils("http://uaa.example.com");
    }

    @After
    public void tearDown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testEncodedUrl() throws Exception {
        String url = "https://example.com/dashboard/?appGuid=app-guid&ace_config=%7B%22orgGuid%22%3A%22org-guid%22%2C%22spaceGuid%22%3A%22space-guid%22%2C%22appGuid%22%3A%22app-guid%22%2C%22redirect%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
        String extraValueEncoded = "this%20is%20my%25special%20string%20that%20has%26some%3Dspecial%20values";
        String extraValueDecoded = URLDecoder.decode(extraValueEncoded, "UTF-8");
        UriComponentsBuilder template = uaaURLUtils.parseAndDecodeUrl(url);
        uriEquals(new URI(url), new URI(template.build().encode().toUriString()));
        url += "&param1="+extraValueEncoded;
        template.queryParam("param1", extraValueDecoded);
        uriEquals(new URI(url), new URI(template.build().encode().toUriString()));
        url += "&param2="+extraValueEncoded;
        template.queryParam("param2", "{param2}");
        uriEquals(new URI(url), new URI(template.build().expand(extraValueDecoded).encode().toUriString()));
    }

    public static void uriEquals(URI uri1, URI uri2) {
        if (compare(uri1.getScheme(),uri2.getScheme()) &&
            compare(uri1.getAuthority(),uri2.getAuthority()) &&
            compare(uri1.getUserInfo(), uri2.getUserInfo()) &&
            compare(uri1.getHost(), uri2.getHost()) &&
            uri1.getPort()==uri2.getPort() &&
            compare(trimBeginningAndEndSlashes(uri1.getPath()), trimBeginningAndEndSlashes(uri2.getPath())) &&
            compare(uri1.getQuery(), uri2.getQuery()) &&
            compare(uri1.getFragment(), uri2.getFragment())) {
        } else {
            fail(format(null, uri1.toString(), uri2.toString()));
        }
    }

    public static String trimBeginningAndEndSlashes(String s) {
        if (s==null) {
            return null;
        } else if (s.startsWith("/")) {
            return trimBeginningAndEndSlashes(s.substring(1));
        } else if (s.endsWith("/")) {
            return trimBeginningAndEndSlashes(s.substring(0,s.length()-1));
        } else {
            return s;
        }
    }

    public static String format(String message, Object expected, Object actual) {
        String formatted = "";
        if (message != null && !message.equals("")) {
            formatted = message + " ";
        }
        String expectedString = String.valueOf(expected);
        String actualString = String.valueOf(actual);
        if (expectedString.equals(actualString)) {
            return formatted + "expected: "
                + expectedString
                + " but was: " + actualString;
        } else {
            return formatted + "expected:<" + expectedString + "> but was:<"
                + actualString + ">";
        }
    }

    public static boolean compare(String s1, String s2) {
        if (s1==null && s2==null) {
            return true;
        } else if (s1==null) {
            return false;
        } else {
            return s1.equals(s2);
        }
    }

    @Test
    public void testGetUaaUrl() throws Exception {
        assertEquals("http://uaa.example.com", uaaURLUtils.getUaaUrl());
    }

    @Test
    public void testGetUaaUrlWithPath() throws Exception {
        assertEquals("http://uaa.example.com/login", uaaURLUtils.getUaaUrl("/login"));
        assertEquals("http://uaa.example.com/login", uaaURLUtils.getUaaUrl("login"));
    }

    @Test
    public void testGetUaaUrlWithZone() throws Exception {
        setIdentityZone("zone1");

        assertEquals("http://zone1.uaa.example.com", uaaURLUtils.getUaaUrl());
    }

    @Test
    public void testGetUaaUrlWithZoneAndPath() throws Exception {
        setIdentityZone("zone1");

        assertEquals("http://zone1.uaa.example.com/login", uaaURLUtils.getUaaUrl("/login"));
    }

    @Test
    public void testGetHost() throws Exception {
        assertEquals("uaa.example.com", uaaURLUtils.getUaaHost());
    }

    @Test
    public void testGetHostWithZone() throws Exception {
        setIdentityZone("zone1");

        assertEquals("zone1.uaa.example.com", uaaURLUtils.getUaaHost());
    }

    private void setIdentityZone(String subdomain) {
        IdentityZone zone = new IdentityZone();
        zone.setSubdomain(subdomain);
        IdentityZoneHolder.set(zone);
    }
}