/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.util;


import org.cloudfoundry.identity.uaa.message.LocalUaaRestTemplate;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LocalUaaRestTemplateMockMvcTests extends InjectedMockContextTest {

    @Test
    public void testLocalUaaRestTemplateAcquireToken() throws Exception {
        LocalUaaRestTemplate restTemplate = getWebApplicationContext().getBean(LocalUaaRestTemplate.class);
        OAuth2AccessToken token = restTemplate.acquireAccessToken(new DefaultOAuth2ClientContext());
        assertTrue("Scopes should contain oauth.login", token.getScope().contains("oauth.login"));
        assertTrue("Scopes should contain notifications.write", token.getScope().contains("notifications.write"));
        assertTrue("Scopes should contain critical_notifications.write", token.getScope().contains("critical_notifications.write"));
    }

    @Test
    public void testUaaRestTemplateContainsBearerHeader() throws Exception {
        LocalUaaRestTemplate restTemplate = getWebApplicationContext().getBean(LocalUaaRestTemplate.class);
        OAuth2AccessToken token = restTemplate.acquireAccessToken(restTemplate.getOAuth2ClientContext());
        Method createRequest = OAuth2RestTemplate.class.getDeclaredMethod("createRequest",URI.class, HttpMethod.class);
        ReflectionUtils.makeAccessible(createRequest);
        ClientHttpRequest request = (ClientHttpRequest)createRequest.invoke(restTemplate, new URI("http://localhost/oauth/token"), HttpMethod.POST);
        assertEquals("authorization bearer header should be present", 1, request.getHeaders().get("Authorization").size());
        assertNotNull("authorization bearer header should be present", request.getHeaders().get("Authorization").get(0));
        assertEquals("bearer "+token.getValue(), request.getHeaders().get("Authorization").get(0));
    }

    @Test
    @Ignore("Only run Self Signed Test when we have an actual environment to test against.")
    public void testSelfSignedCertificate() throws Exception {
        String url = "https://notifications.uaa-acceptance.cf-app.com/info";
        //String url = "https://notifications.uaa-acceptance.cf-app.com/notifications";
        LocalUaaRestTemplate restTemplate = getWebApplicationContext().getBean(LocalUaaRestTemplate.class);
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
