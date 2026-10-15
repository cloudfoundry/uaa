package org.cloudfoundry.identity.uaa.cache;

import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;
import com.github.benmanes.caffeine.cache.Ticker;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.StubClientHttpRequestFactory;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class StaleUrlCacheTests {

    private static final Duration CACHE_EXPIRATION = Duration.ofMinutes(10);
    private static final Duration CACHE_EXPIRED = CACHE_EXPIRATION.plusMinutes(1);
    private static final String URL = "http://localhost:8080/uaa/.well-known/openid-configuration";
    // maxEntries=2 in setup gives a 20 KiB weight budget, which is also the default per-response limit.
    private static final int CACHE_BUDGET_BYTES = 2 * 10 * 1024;
    private static final byte[] content1;
    private static final byte[] content2;
    private static final byte[] content3;

    private StaleUrlCache cache;
    @Mock
    private TimeService mockTimeService;
    private RestTemplate restTemplate;
    @Mock
    ResponseEntity<byte[]> responseEntity;

    private StubClientHttpRequestFactory remote;
    private TestTicker ticker;

    static {
        content1 = new byte[8];
        Arrays.fill(content1, (byte) 1);
        content2 = new byte[8];
        Arrays.fill(content2, (byte) 2);
        content3 = new byte[8];
        Arrays.fill(content3, (byte) 3);
    }

    static class DetectRemovalListener implements RemovalListener<Object, Object> {
        volatile int removalCount = 0;

        @Override
        public void onRemoval(@Nullable Object key, @Nullable Object value, RemovalCause cause) {
            removalCount++;
        }
    }

    private DetectRemovalListener listener;

    @BeforeEach
    void setup() {
        ticker = new TestTicker(System.nanoTime());

        listener = new DetectRemovalListener();

        cache = new StaleUrlCache(CACHE_EXPIRATION, mockTimeService, 2, ticker, listener);
        remote = new StubClientHttpRequestFactory();
        restTemplate = new RestTemplate(remote);
    }

    @Test
    void correct_method_invoked_on_rest_template() throws Exception {
        remote.respond(HttpStatus.OK, content1);

        cache.getUrlContent(URL, restTemplate);

        assertThat(remote.requests()).singleElement().satisfies(request -> {
            assertThat(request.getURI()).isEqualTo(new URI(URL));
            assertThat(request.getMethod()).isEqualTo(HttpMethod.GET);
            assertThat(request.getHeaders().getAccept()).contains(MediaType.APPLICATION_OCTET_STREAM);
        });
    }

    @Test
    void incorrect_uri_throws_illegal_argument_exception() {
        assertThatThrownBy(() -> cache.getUrlContent("invalid value", restTemplate))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rest_client_exception_is_propagated() {
        remote.fail(new IOException("mock"));
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate))
                .isInstanceOf(RestClientException.class);
    }

    @Test
    void calling_twice_uses_cache() throws Exception {
        remote.respond(HttpStatus.OK, content1);

        byte[] c1 = cache.getUrlContent(URL, restTemplate);
        byte[] c2 = cache.getUrlContent(URL, restTemplate);

        assertThat(remote.requestCount(new URI(URL))).isOne();
        assertThat(c2).isSameAs(c1);
        assertThat(cache.size()).isOne();
    }

    @Test
    void entry_refreshes_after_time() {
        lenient().when(mockTimeService.getCurrentTimeMillis()).thenAnswer(_ -> System.currentTimeMillis());
        remote.respond(HttpStatus.OK, content1).respond(HttpStatus.OK, content2).respond(HttpStatus.OK, content3);

        // populate the cache
        byte[] c1 = cache.getUrlContent(URL, restTemplate);
        ticker.advance(CACHE_EXPIRED);

        // the next call after timeout should force async refresh and return the new value
        // This call is necessary to trigger the cache refresh operation after the timeout period.
        cache.getUrlContent(URL, restTemplate);
        await().atMost(5, TimeUnit.SECONDS).untilAsserted(
                () -> assertThat(listener.removalCount).isPositive()
        );
        byte[] c2 = cache.getUrlContent(URL, restTemplate);
        assertThat(c2).isEqualTo(content2);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(remote.requests()).hasSize(2));

        // Allow time for the async update to caffeine's cache.
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(cache.getUrlContent(URL, restTemplate))
                        .isNotEqualTo(c1)
                );
    }

    @Test
    void cache_should_start_empty() {
        assertThat(cache.size()).isZero();
    }

    @Test
    void max_weight_is_respected() throws Exception {
        // only one 15 KB entry fits into the 20 KiB budget
        remote.respond(HttpStatus.OK, new byte[15000]);
        String[] uris = {"https://test1.com", "https://test2.com", "https://test3.com"};
        for (String aUri : Arrays.asList(uris[0], uris[0], uris[1], uris[1], uris[2], uris[2])) {
            cache.getUrlContent(aUri, restTemplate);
        }
        for (String aUri : uris) {
            assertThat(remote.requestCount(new URI(aUri))).isOne();
        }
        cache.cleanUp();
        assertThat(cache.size()).isOne();
    }

    @Test
    void tiny_entries_are_still_bounded_by_max_entries() {
        remote.respond(HttpStatus.OK, new byte[1]);
        for (int i = 0; i < 5; i++) {
            cache.getUrlContent("https://test" + i + ".com", restTemplate);
        }
        cache.cleanUp();
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    void stale_entry_returned_on_failure() {
        remote.respond(HttpStatus.OK, content3).fail(new IOException("mock"));

        // populate the cache
        byte[] c1 = cache.getUrlContent(URL, restTemplate);
        ticker.advance(CACHE_EXPIRED);

        // next call after timeout, should force async refresh
        byte[] c2 = cache.getUrlContent(URL, restTemplate);
        assertThat(c2).isSameAs(c1);

        // Allow time for the async getUrlContent to be called
        await().atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(remote.requests()).hasSize(2));

        // Allow time for the async update to caffeine's cache.
        // It should continue returning the stale content due to the exception
        await().during(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> assertThat(cache.getUrlContent(URL, restTemplate))
                        .isSameAs(c1)
                );
    }

    @Test
    void extended_method_invoked_on_rest_template() {
        remote.respond(HttpStatus.OK, new byte[1]);
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Test", "value");

        assertThat(cache.getUrlContent(URL, restTemplate, HttpMethod.GET, new HttpEntity<>(headers))).hasSize(1);

        MockClientHttpRequest request = remote.requests().getFirst();
        assertThat(request.getMethod()).isEqualTo(HttpMethod.GET);
        assertThat(request.getHeaders().getFirst("X-Test")).isEqualTo("value");
    }

    @Test
    void extended_method_sends_request_entity_body() {
        remote.respond(HttpStatus.OK, new byte[1]);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        cache.getUrlContent(URL, restTemplate, HttpMethod.POST, new HttpEntity<>("payload", headers));

        MockClientHttpRequest request = remote.requests().getFirst();
        assertThat(request.getMethod()).isEqualTo(HttpMethod.POST);
        assertThat(request.getBodyAsString()).isEqualTo("payload");
        assertThat(request.getHeaders().getContentType()).isEqualTo(MediaType.TEXT_PLAIN);
    }

    @Test
    void client_error_is_propagated_as_http_client_error() {
        remote.respond(HttpStatus.NOT_FOUND, "missing".getBytes());
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate))
                .isInstanceOf(HttpClientErrorException.NotFound.class);
    }

    @Test
    void oversized_error_body_is_truncated_instead_of_read_fully() {
        remote.respond(HttpStatus.INTERNAL_SERVER_ERROR, new byte[10 * 1024 * 1024]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate))
                .isInstanceOfSatisfying(HttpServerErrorException.class,
                        e -> assertThat(e.getResponseBodyAsByteArray()).hasSize(4 * 1024));
    }

    @Test
    void equal() {
        StaleUrlCache.UriRequest uriRequest = new StaleUrlCache.UriRequest(URL, restTemplate, HttpMethod.GET, responseEntity);
        assertThat(uriRequest)
                .isEqualTo(uriRequest)
                .isNotEqualTo(null)
                .isNotEqualTo(URL);
        assertThat(new StaleUrlCache.UriRequest(URL, restTemplate, HttpMethod.GET, responseEntity)).isEqualTo(uriRequest);
        assertThat(new StaleUrlCache.UriRequest(URL, restTemplate, HttpMethod.GET, responseEntity, 1))
                .isEqualTo(new StaleUrlCache.UriRequest(URL, restTemplate, HttpMethod.GET, null, 1))
                .isNotEqualTo(uriRequest);
        assertThat(new StaleUrlCache.UriRequest(null, restTemplate, HttpMethod.GET, responseEntity)).isNotEqualTo(uriRequest);
    }

    @Test
    void extended_method_invoked_on_rest_template_invalid_http_response() {
        remote.respond(HttpStatus.TEMPORARY_REDIRECT, new byte[1]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate, HttpMethod.GET, new HttpEntity<>(new HttpHeaders())))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getUrlContent_emptyBody_returnsNull() {
        remote.respond(HttpStatus.OK, new byte[0]);
        assertThat(cache.getUrlContent(URL, restTemplate)).isNull();
    }

    @Test
    void getUrlContent_bodyLargerThanCacheBudget_isRejectedAndNotCached() {
        remote.respond(HttpStatus.OK, new byte[CACHE_BUDGET_BYTES + 1]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Response exceeds maximum allowed size");
        cache.cleanUp();
        assertThat(cache.size()).isZero();
    }

    @Test
    void getUrlContent_contentLengthLargerThanLimit_isRejectedWithoutReadingBody() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentLength(1001);
        remote.respond(HttpStatus.OK, headers, new byte[0]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate, 1000))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Response exceeds maximum allowed size");
    }

    @Test
    void getUrlContent_withLimit_rejectsLargerResponse() {
        remote.respond(HttpStatus.OK, new byte[1001]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate, 1000))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Response exceeds maximum allowed size");
    }

    @Test
    void getUrlContent_withLimit_isNotServedAnEntryLoadedWithALargerLimit() throws Exception {
        remote.respond(HttpStatus.OK, new byte[1001]);
        assertThat(cache.getUrlContent(URL, restTemplate)).hasSize(1001);

        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate, 1000))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Response exceeds maximum allowed size");
        assertThat(remote.requestCount(new URI(URL))).isEqualTo(2);
    }

    @Test
    void getUrlContent_failureUnderSmallerLimit_doesNotAffectCallerWithLargerLimit() {
        remote.respond(HttpStatus.OK, new byte[1500]);
        assertThatThrownBy(() -> cache.getUrlContent(URL, restTemplate, 1000))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(cache.getUrlContent(URL, restTemplate, 2000)).hasSize(1500);
    }

    @Test
    void constructor_executed() {
        StaleUrlCache urlCache = new StaleUrlCache(mockTimeService);
        urlCache.clear();
        cache.cleanUp();

        assertThat(urlCache.size()).isZero();
    }

    @Nested
    @DisplayName("When a http server never returns a http response")
    class DeadHttpServer {
        private SlowHttpServer slowHttpServer;

        @BeforeEach
        void startHttpServer() {
            slowHttpServer = new SlowHttpServer();
            slowHttpServer.run();
        }

        @AfterEach
        void stopHttpServer() {
            slowHttpServer.stop();
        }

        @Test
        void throwUnavailableIdpWhenServerMetadataDoesNotReply() {
            RestTemplateConfig restTemplateConfig = RestTemplateConfig.createDefaults();
            restTemplateConfig.timeout = 120;
            RestTemplate restTemplate = restTemplateConfig.trustingRestTemplate();

            String url = slowHttpServer.getUrl();
            await().atMost(60, TimeUnit.SECONDS)
                    .untilAsserted(() -> assertThatThrownBy(() -> cache.getUrlContent(url, restTemplate))
                            .isInstanceOf(ResourceAccessException.class)
                    );
        }
    }

    static class TestTicker implements Ticker {
        long nanos;

        public TestTicker(long initialNanos) {
            nanos = initialNanos;
        }

        @Override
        public long read() {
            return nanos;
        }

        public void advance(Duration duration) {
            nanos += duration.toNanos();
        }
    }
}
