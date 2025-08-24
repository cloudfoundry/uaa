package org.cloudfoundry.identity.statsd.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_PASSWORD;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.TEST_USERNAME;
import static org.cloudfoundry.identity.statsd.integration.IntegrationTestUtils.UAA_BASE_URL;

class UaaMetricsEmitterIT {
    private static final long WAIT_FOR_MESSAGE = TimeUnit.MILLISECONDS.toNanos(5500);
    private static DatagramSocket serverSocket;
    private static byte[] receiveData;
    private static DatagramPacket receivePacket;
    private static Map<String, String> firstBatch;

    private static final List<String> METRIC_FRAGMENTS = Arrays.asList(
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
            "uaa.requests.ui.completed.count",
            "uaa.requests.ui.completed.time",
            "uaa.server.up.time",
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

    @BeforeAll
    static void setUpOnce() throws IOException {
        serverSocket = new DatagramSocket(8125);
        serverSocket.setSoTimeout(1000);
        receiveData = new byte[65535];
        receivePacket = new DatagramPacket(receiveData, receiveData.length);
        performSimpleGet();
        firstBatch = getMessages(METRIC_FRAGMENTS);
        performSimpleGet();
        performLogin(TEST_USERNAME);
        performLogin("user-name-not-found");
        secondBatch = getMessages(METRIC_FRAGMENTS);
    }

    public static Stream<Arguments> parameters() {
        return METRIC_FRAGMENTS.stream().map(Arguments::of);
    }

    @ParameterizedTest(name = "{index}: fragment[{0}]")
    @MethodSource("parameters")
    void assertGenericMetrics(String statsDKey) {
        String data1 = firstBatch.get(statsDKey);
        String data2 = secondBatch.get(statsDKey);

        assertThat(data1).as("Expected to find message for:'" + statsDKey + "' in the first batch.").isNotNull();
        long first = IntegrationTestUtils.getStatsDValueFromMessage(data1);
        assertThat(first).as(statsDKey + " first value must have a positive value.").isNotNegative();

        assertThat(data2).as("Expected to find message for:'" + statsDKey + "' in the second batch.").isNotNull();
        long second = IntegrationTestUtils.getStatsDValueFromMessage(data2);
        assertThat(second).as(statsDKey + " second value must have a positive value.").isNotNegative();
    }

    private static Map<String, String> getMessages(List<String> fragments) throws IOException {
        long startTime = System.nanoTime();
        Map<String, String> results = new HashMap<>();
        do {
            receiveData = new byte[65535];
            receivePacket.setData(receiveData);
            try {
                serverSocket.receive(receivePacket);
                String message = new String(receivePacket.getData()).trim();
                fragments.forEach(fragment -> {
                    if (message.startsWith(fragment)) {
                        results.put(fragment, message);
                    }
                });
            } catch (SocketTimeoutException e) {
                //expected so that we keep looping
            }
        } while (results.size() < fragments.size() && (System.nanoTime() < (startTime + UaaMetricsEmitterIT.WAIT_FOR_MESSAGE)));
        return results;
    }

    private static void performLogin(String username) {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(UAA_BASE_URL + "/login",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                String.class);

        IntegrationTestUtils.copyCookies(loginResponse, headers);
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());

        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", username);
        body.add("password", TEST_PASSWORD);
        body.add("X-Uaa-Csrf", csrf);
        loginResponse = template.exchange(UAA_BASE_URL + "/login.do",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    private static void performSimpleGet() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        template.exchange(UAA_BASE_URL + "/login",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                String.class);
    }
}
