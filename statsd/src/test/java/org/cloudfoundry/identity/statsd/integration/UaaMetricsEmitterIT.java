/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.statsd.integration;

import org.junit.BeforeClass;
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
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_PASSWORD;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_USERNAME;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.UAA_BASE_URL;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class UaaMetricsEmitterIT {
    public static final int WAIT_FOR_MESSAGE = 5500;
    private static DatagramSocket serverSocket;
    private static byte[] receiveData;
    private static DatagramPacket receivePacket;

    @BeforeClass
    public static void setUpOnce() throws IOException {
        serverSocket = new DatagramSocket(8125);
        serverSocket.setSoTimeout(1000);
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
        assertNotNull(getMessage("uaa.audit_service.user.authentication.count:", WAIT_FOR_MESSAGE));
    }

    @Test
    public void global_counts() throws IOException {
        List<String> fragments = Arrays.asList(
            "uaa.requests.global.completed.count",
            "uaa.requests.global.completed.count",
            "uaa.requests.global.unhealthy.time",
            "uaa.requests.global.unhealthy.count"
        );
        Map<String,String> firstBatch = getMessages(fragments, WAIT_FOR_MESSAGE);
        performSimpleGet();
        Map<String,String> secondBatch = getMessages(fragments, WAIT_FOR_MESSAGE);

        String message = firstBatch.get("uaa.requests.global.completed.count");
        long previousValue = IntegrationTestUtils.getGaugeValueFromMessage(message);

        message = secondBatch.get("uaa.requests.global.completed.count");
        long nextValue = IntegrationTestUtils.getGaugeValueFromMessage(message);
        assertThat(nextValue, greaterThan(previousValue));

        message = firstBatch.get("uaa.requests.global.unhealthy.time");
        long value = IntegrationTestUtils.getGaugeValueFromMessage(message);
        assertThat(value, greaterThanOrEqualTo(0l));

        message = firstBatch.get("uaa.requests.global.unhealthy.count");
        value = IntegrationTestUtils.getGaugeValueFromMessage(message);
        assertThat(value, greaterThanOrEqualTo(0l));
    }

    @Test
    public void server_inflight_count() throws IOException {
        performSimpleGet();
        String message = getMessage("uaa.server.inflight.count", WAIT_FOR_MESSAGE);
        long nextValue = IntegrationTestUtils.getGaugeValueFromMessage(message);
        assertThat(nextValue, greaterThanOrEqualTo(0l));
    }


    protected String getMessage(String fragment, int timeout) throws IOException {
        return getMessages(Arrays.asList(fragment), timeout).get(fragment);
    }

    protected Map<String,String> getMessages(List<String> fragments, int timeout) throws IOException {
        long startTime = System.currentTimeMillis();
        Map<String,String> results = new HashMap<>();
        do {
            receiveData = new byte[65535];
            receivePacket.setData(receiveData);
            try {
                serverSocket.receive(receivePacket);
                String message = new String(receivePacket.getData()).trim();
                System.out.println("message = " + message);
                fragments.stream().forEach(fragment -> {
                    if (message.startsWith(fragment)) {
                        results.put(fragment, message);
                    }
                });
            } catch (SocketTimeoutException e) {
                //expected so that we keep looping
            }
        } while (results.size()<fragments.size() && (System.currentTimeMillis() < (startTime + timeout)));
        return results;
    }

    public void performSimpleGet() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        template.exchange(UAA_BASE_URL + "/login",
                          HttpMethod.GET,
                          new HttpEntity<>(null, headers),
                          String.class);
    }
}
