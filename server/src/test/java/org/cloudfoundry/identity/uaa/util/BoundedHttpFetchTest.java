package org.cloudfoundry.identity.uaa.util;

import com.sun.net.httpserver.HttpServer;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.test.network.NetworkTestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BoundedHttpFetchTest {

    private static final byte[] BODY = "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);

    private HttpServer server;
    private final AtomicInteger hits = new AtomicInteger();

    @BeforeEach
    void startServer() throws Exception {
        server = NetworkTestUtils.startHttpServer(exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(200, BODY.length);
            exchange.getResponseBody().write(BODY);
            exchange.close();
        });
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "localhost"})
    void fetch_withDefaultRequestFactory_reachesLocalServer(String host) {
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createRequestFactory(false, 5_000));

        byte[] body = BoundedHttpFetch.fetch(template, uriFor(host), HttpMethod.GET, null, 1024, true);

        assertThat(body).isEqualTo(BODY);
        assertThat(hits).hasValue(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "localhost"})
    void fetch_withSafeRequestFactory_blocksPrivateAddressBeforeConnecting(String host) {
        RestTemplate template = new RestTemplate(UaaHttpRequestUtils.createSafeRequestFactory(RestTemplateConfig.createDefaults()));

        assertThatThrownBy(() -> BoundedHttpFetch.fetch(template, uriFor(host), HttpMethod.GET, null, 1024, true))
                .isInstanceOf(ResourceAccessException.class)
                .rootCause()
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("resolves to a blocked address");
        assertThat(hits).hasValue(0);
    }

    private URI uriFor(String host) {
        return URI.create("http://" + host + ":" + server.getAddress().getPort() + "/jwks");
    }
}
