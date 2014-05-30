/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * @author Luke Taylor
 */
public class RemoteAuthenticationEndpointTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Test
    public void remoteAuthenticationSucceedsWithCorrectCredentials() throws Exception {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = authenticate(testAccounts.getUserName(), testAccounts.getPassword());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(testAccounts.getUserName(), response.getBody().get("username"));
    }

    @Test
    public void remoteAuthenticationFailsWithIncorrectCredentials() throws Exception {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = authenticate(testAccounts.getUserName(), "wrong");
        assertFalse(HttpStatus.OK == response.getStatusCode());
        assertFalse(testAccounts.getUserName().equals(response.getBody().get("username")));
    }

    @Test
    public void validateLdapOrKeystoneOrigin() throws Exception {
        String profiles = System.getProperty("spring.profiles.active");
        if (profiles!=null && profiles.contains("ldap")) {
            validateOrigin("marissa3","ldap3","ldap");
        } else if (profiles!=null && profiles.contains("keystone")) {
            validateOrigin("marissa2", "keystone", "keystone");
        }
    }

    public void validateOrigin(String username, String password, String origin) throws Exception {
        ResponseEntity<Map> authResp = authenticate(username,password);
        assertEquals(HttpStatus.OK, authResp.getStatusCode());

        ResponseEntity<Map> response = serverRunning.getForObject("/Users" + "?attributes=id,userName,origin", Map.class);
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
        List<Map> list = (List) results.get("resources");
        boolean found = false;
        for (int i=0; i<list.size(); i++) {
            Map user = list.get(i);
            assertTrue(user.containsKey("id"));
            assertTrue(user.containsKey("userName"));
            assertTrue(user.containsKey("origin"));
            assertFalse(user.containsKey("name"));
            assertFalse(user.containsKey("emails"));
            if ("ldap3".equals(user.get("userName"))) {
                found = true;
                assertEquals(origin, user.get("origin"));
            }
        }
        assertTrue(found);
    }



    @SuppressWarnings("rawtypes")
    ResponseEntity<Map> authenticate(String username, String password) {
        RestTemplate restTemplate = new RestTemplate();
        // The default java.net client doesn't allow you to handle 4xx responses
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            protected boolean hasError(HttpStatus statusCode) {
                return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
            }
        });
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, Object> parameters = new LinkedMultiValueMap<String, Object>();
        parameters.set("username", username);
        parameters.set("password", password);

        ResponseEntity<Map> result = restTemplate.exchange(serverRunning.getUrl("/authenticate"),
                        HttpMethod.POST, new HttpEntity<MultiValueMap<String, Object>>(parameters, headers), Map.class);
        return result;
    }
}
