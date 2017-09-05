package org.cloudfoundry.identity.statsd.integration;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_PASSWORD;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_USERNAME;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.UAA_BASE_URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/*******************************************************************************
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
 *******************************************************************************/


public class UaaMetricsEmitterIT {
    private DatagramSocket serverSocket;
    private byte[] receiveData;
    private DatagramPacket receivePacket;


    @Before
    public void setUp() throws IOException {
        serverSocket = new DatagramSocket(8125);
        receiveData = new byte[65535];
        receivePacket = new DatagramPacket(receiveData, receiveData.length);
    }

    @Test
    public void testStatsDClientEmitsMetricsCollectedFromUAA() throws InterruptedException, IOException {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(UAA_BASE_URL + "/login",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                String.class);

        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());

        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", TEST_USERNAME);
        body.add("password", TEST_PASSWORD);
        body.add("X-Uaa-Csrf", csrf);
        loginResponse = template.exchange(UAA_BASE_URL + "/login.do",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
        assertNotNull(getMessage("uaa.audit_service.user_authentication_count:1", 5000));
    }

    protected String getMessage(String fragment, int timeout) throws IOException {
        long startTime = System.currentTimeMillis();
        String found = null;
        do {
            serverSocket.receive(receivePacket);
            String message = new String(receivePacket.getData());
            System.out.println(message);
            if (message.startsWith(fragment)) {
                found = message;
            }
        } while (found == null && (System.currentTimeMillis() < startTime + timeout));
        return found;
    }
}
