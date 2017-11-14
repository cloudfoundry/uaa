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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
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
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@RunWith(Parameterized.class)
public class UaaMetricsEmitterIT {
    public static final int WAIT_FOR_MESSAGE = 5500;
    private static DatagramSocket serverSocket;
    private static byte[] receiveData;
    private static DatagramPacket receivePacket;
    private static Map<String, String> firstBatch;
    private static List<String> perRequestFragments = Arrays.asList(
        "uaa.requests.ui.latency"
    );

    private static List<String> metricFragments = Arrays.asList(
        "uaa.audit_service.user_authentication_count",
        "uaa.audit_service.principal_not_found_count",
        "uaa.audit_service.client_authentication_failure_count",
        "uaa.audit_service.user_authentication_count",
        "uaa.audit_service.user_authentication_failure_count",
        "uaa.audit_service.user_not_found_count",
        "uaa.audit_service.principal_authentication_failure_count",
        "uaa.audit_service.user_password_failures",
        "uaa.audit_service.client_authentication_count",
        "uaa.audit_service.user_password_changes",
        "uaa.requests.global.completed.count",
        "uaa.requests.global.completed.time",
        "uaa.requests.global.unhealthy.time",
        "uaa.requests.global.unhealthy.count",
        "uaa.server.inflight.count",
        "uaa.requests.global.status_1xx.count",
        "uaa.requests.global.status_2xx.count",
        "uaa.requests.global.status_3xx.count",
        "uaa.requests.global.status_4xx.count",
        "uaa.requests.global.status_5xx.count",
        "uaa.database.global.completed.count",
        "uaa.requests.global.completed.time",
        "uaa.database.global.unhealthy.time",
        "uaa.database.global.unhealthy.count",
        "uaa.requests.ui.completed.count", //this fails standalone since there are no UI requests in pre batch
        "uaa.requests.ui.completed.time",  //this fails standalone since there are no UI requests in pre batch
        "uaa.server.up.time",
        "uaa.requests.ui.latency",         //this fails standalone since there are no UI requests in pre batch
        "uaa.server.idle.time",
        "uaa.vitals.vm.cpu.count",
        "uaa.vitals.vm.cpu.load",
        "uaa.vitals.vm.memory.total",
        "uaa.vitals.vm.memory.committed",
        "uaa.vitals.vm.memory.free",
        "uaa.vitals.jvm.cpu.load",
        "uaa.vitals.jvm.thread.count",
        "uaa.vitals.jvm.heap.init",
        "uaa.vitals.jvm.heap.committed",
        "uaa.vitals.jvm.heap.used",
        "uaa.vitals.jvm.heap.max",
        "uaa.vitals.jvm.non-heap.init",
        "uaa.vitals.jvm.non-heap.committed"
    );
    private static Map<String, String> secondBatch;

    @Parameterized.Parameters(name = "{index}: fragment[{0}]")
    public static Object[] data() {
        return metricFragments.toArray();
    }


    private String statsDKey;

    public UaaMetricsEmitterIT(String statsDKey) {
        this.statsDKey = statsDKey;
    }

    @BeforeClass
    public static void setUpOnce() throws IOException {
        serverSocket = new DatagramSocket(8125);
        serverSocket.setSoTimeout(1000);
        receiveData = new byte[65535];
        receivePacket = new DatagramPacket(receiveData, receiveData.length);
        firstBatch = getMessages(metricFragments, WAIT_FOR_MESSAGE);
        performSimpleGet();
        performLogin(TEST_USERNAME);
        performLogin("user-name-not-found");
        secondBatch = getMessages(metricFragments, WAIT_FOR_MESSAGE);
    }

    @Test
    public void assert_gauge_metrics() throws IOException {
        String data1 = firstBatch.get(statsDKey);
        String data2 = secondBatch.get(statsDKey);

        if(!perRequestFragments.contains(statsDKey)) {
            assertNotNull("Expected to find message for:'" + statsDKey + "' in the first batch.", data1);
            long first = IntegrationTestUtils.getGaugeValueFromMessage(data1);
            assertThat(statsDKey + " first value must have a positive value.", first, greaterThanOrEqualTo(0l));

            assertNotNull("Expected to find message for:'"+statsDKey+"' in the second batch.", data2);
            long second = IntegrationTestUtils.getGaugeValueFromMessage(data2);
            assertThat(statsDKey + " second value must have a positive value.", second, greaterThanOrEqualTo(0l));
        }
    }

    @Test
    public void assert_per_request_metrics() throws IOException {
        String data2 = secondBatch.get(statsDKey);

        if(perRequestFragments.contains(statsDKey)) {
            assertNotNull("Expected to find message for:'"+statsDKey+"' in the second batch.", data2);
            long second = IntegrationTestUtils.getTimeValueFromMessage(data2);
            assertThat(statsDKey + " second value must have a positive value.", second, greaterThanOrEqualTo(0l));
        }
    }


    protected static Map<String,String> getMessages(List<String> fragments, int timeout) throws IOException {
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

    public static void performLogin(String username) {
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
        body.add("username", username);
        body.add("password", TEST_PASSWORD);
        body.add("X-Uaa-Csrf", csrf);
        loginResponse = template.exchange(UAA_BASE_URL + "/login.do",
                                          HttpMethod.POST,
                                          new HttpEntity<>(body, headers),
                                          String.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
    }

    public static void performSimpleGet() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        template.exchange(UAA_BASE_URL + "/login",
                          HttpMethod.GET,
                          new HttpEntity<>(null, headers),
                          String.class);
    }
}
